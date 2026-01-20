#!/usr/bin/env python3
"""AAuth signing interceptor for A2A client calls.

This interceptor signs outgoing HTTP requests using AAuth HWK (Header Web Key)
scheme per the AAuth specification. Each request is signed with HTTP Message
Signatures (RFC 9421) providing proof-of-possession without identity verification.
"""

import logging
import os
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from a2a.client.middleware import ClientCallInterceptor, ClientCallContext
from app.tracing_config import inject_context_to_headers, add_event, set_attribute
from app.config import settings

# Import aauth library for signing
from aauth import generate_ed25519_keypair, sign_request, public_key_to_jwk

# Configure logging
logger = logging.getLogger(__name__)

# Generate ephemeral keypair at module load
# This keypair will be used for the lifetime of the backend process
_PRIVATE_KEY, _PUBLIC_KEY = generate_ed25519_keypair()
_PUBLIC_JWK = public_key_to_jwk(_PUBLIC_KEY, kid="backend-ephemeral-1")

logger.info("🔐 AAuth: Generated ephemeral Ed25519 keypair for request signing")
if settings.debug:
    logger.debug(f"🔐 AAuth: Public key JWK: {_PUBLIC_JWK}")


def get_signing_keypair():
    """Get the module-level signing keypair.
    
    Returns:
        Tuple of (private_key, public_key, public_jwk)
    """
    return _PRIVATE_KEY, _PUBLIC_KEY, _PUBLIC_JWK


class AAuthSigningInterceptor(ClientCallInterceptor):
    """Interceptor that signs HTTP requests using AAuth HWK scheme.
    
    This interceptor adds HTTP Message Signature headers to all outgoing
    requests, providing cryptographic proof-of-possession without requiring
    identity verification (pseudonymous authentication).
    
    Per AAuth SPEC.md Section 10, the following headers are added:
    - Signature-Input: Describes which components are covered by the signature
    - Signature: The actual cryptographic signature
    - Signature-Key: Contains the public key (scheme=hwk)
    """
    
    def __init__(self, trace_headers: Optional[Dict[str, str]] = None):
        """Initialize the AAuth signing interceptor.
        
        Args:
            trace_headers: Optional additional headers to inject (e.g., for tracing)
        """
        self.trace_headers = trace_headers or {}
        self.private_key = _PRIVATE_KEY
        self.public_key = _PUBLIC_KEY
    
    async def intercept(
        self,
        method_name: str,
        request_payload: dict[str, Any],
        http_kwargs: dict[str, Any],
        agent_card: Any | None,
        context: ClientCallContext | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Sign the HTTP request with AAuth HWK scheme.
        
        This method:
        1. Extracts URL, method, and body from http_kwargs or agent_card
        2. Signs the request using aauth.sign_request() with scheme=hwk
        3. Adds signature headers to the outgoing request
        4. Injects trace context headers
        """
        if settings.debug:
            logger.debug(f"🔐 AAuthSigningInterceptor.intercept() called for {method_name}")
            logger.debug(f"🔍   request_payload keys: {list(request_payload.keys()) if request_payload else 'None'}")
            logger.debug(f"🔍   http_kwargs keys: {list(http_kwargs.keys())}")
            if agent_card and hasattr(agent_card, 'url'):
                logger.debug(f"🔍   agent_card.url: {agent_card.url}")
        
        headers = http_kwargs.get('headers', {})
        
        # Add custom trace headers if provided
        if self.trace_headers:
            headers.update(self.trace_headers)
        
        # Inject current trace context into headers
        headers = inject_context_to_headers(headers)
        
        # Extract request details for signing
        # Try to get URL from http_kwargs first, then fall back to agent_card
        url = http_kwargs.get('url', '')
        if not url and agent_card and hasattr(agent_card, 'url'):
            url = agent_card.url
            if settings.debug:
                logger.debug(f"🔍   Using URL from agent_card: {url}")
        
        method = http_kwargs.get('method', 'POST').upper()
        
        # Get body if present
        # The A2A SDK may pass body in different ways
        body = None
        if 'content' in http_kwargs:
            body = http_kwargs['content']
            if isinstance(body, str):
                body = body.encode('utf-8')
        elif 'data' in http_kwargs:
            body = http_kwargs['data']
            if isinstance(body, str):
                body = body.encode('utf-8')
        elif 'json' in http_kwargs:
            import json
            # Serialize JSON ourselves to ensure exact bytes match what we sign
            # Then pass as 'content' instead of 'json' so httpx doesn't re-serialize
            body = json.dumps(http_kwargs['json'], separators=(',', ':'), ensure_ascii=True).encode('utf-8')
            # Replace 'json' with 'content' to prevent httpx from re-serializing
            http_kwargs['content'] = body
            del http_kwargs['json']
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
        elif request_payload:
            # A2A SDK passes the JSON-RPC payload in request_payload
            # Serialize JSON ourselves to ensure exact bytes match what we sign
            import json
            body = json.dumps(request_payload, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
            # Ensure httpx uses our serialized bytes, not re-serialize
            # If 'json' is in http_kwargs, replace it with 'content'
            if 'json' in http_kwargs:
                http_kwargs['content'] = body
                del http_kwargs['json']
            else:
                # If no 'json' key, add 'content' so httpx uses our bytes
                http_kwargs['content'] = body
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
            if settings.debug:
                logger.debug(f"🔍   Using request_payload as body, length: {len(body)}")
        
        # Sign the request if we have a URL
        if url:
            try:
                logger.info(f"🔐 AAuth: Signing request to {url} with HWK scheme")
                if settings.debug:
                    logger.debug(f"🔐 AAuth: Method: {method}, Body length: {len(body) if body else 0}")
                
                # Sign the request using AAuth HWK scheme
                if settings.debug:
                    logger.debug(f"🔐 AAuth: Signing with headers: {list(headers.keys())}")
                    for k, v in headers.items():
                        if k.lower() in ['content-type', 'content-digest', 'signature-key']:
                            logger.debug(f"🔐 AAuth:   {k}: {v[:100] if len(v) > 100 else v}")
                
                sig_headers = sign_request(
                    method=method,
                    target_uri=str(url),
                    headers=headers,
                    body=body,
                    private_key=self.private_key,
                    sig_scheme="hwk"
                )
                
                # Add signature headers to the request
                headers.update(sig_headers)
                
                if settings.debug:
                    logger.debug(f"🔐 AAuth: Generated Signature-Input: {sig_headers.get('Signature-Input', '')[:150]}")
                    logger.debug(f"🔐 AAuth: Generated Signature-Key: {sig_headers.get('Signature-Key', '')[:100]}")
                    logger.debug(f"🔐 AAuth: Generated Signature: {sig_headers.get('Signature', '')[:100]}")
                
                logger.info(f"🔐 AAuth: Added signature headers to request")
                if settings.debug:
                    logger.debug(f"🔐 AAuth: Signature-Input: {sig_headers.get('Signature-Input', '')[:100]}...")
                    logger.debug(f"🔐 AAuth: Signature-Key: {sig_headers.get('Signature-Key', '')[:100]}...")
                
                add_event("aauth.request_signed", {
                    "method": method,
                    "url": str(url),
                    "scheme": "hwk",
                    "has_body": body is not None
                })
                set_attribute("aauth.signed", True)
                set_attribute("aauth.scheme", "hwk")
                
            except Exception as e:
                logger.error(f"❌ AAuth: Failed to sign request: {e}")
                if settings.debug:
                    import traceback
                    logger.debug(traceback.format_exc())
                add_event("aauth.signing_failed", {"error": str(e)})
                set_attribute("aauth.signed", False)
        else:
            logger.warning(f"⚠️ AAuth: No URL available, skipping signing")
            add_event("aauth.signing_skipped", {"reason": "no_url"})
        
        # Update http_kwargs with modified headers
        http_kwargs['headers'] = headers
        
        # Add tracing events
        add_event("a2a_client.interceptor.headers_injected", {
            "method_name": method_name,
            "headers_count": len(headers),
            "trace_headers": list(self.trace_headers.keys()) if self.trace_headers else [],
            "has_aauth_signature": 'Signature' in headers
        })
        
        set_attribute("a2a_client.interceptor.method", method_name)
        set_attribute("a2a_client.interceptor.headers_count", len(headers))
        set_attribute("a2a_client.interceptor.has_aauth_signature", 'Signature' in headers)
        
        if settings.debug:
            logger.debug(f"🔗 AAuth: Injected {len(headers)} headers for {method_name}")
        return request_payload, http_kwargs

