#!/usr/bin/env python3
"""AAuth Token Service for requesting auth tokens from Keycloak.

This service implements autonomous AAuth authorization flow (SPEC Section 3.4)
where agents request auth tokens based on their identity and policy evaluation,
without user interaction.

Per SPEC Section 9.3, this service:
- Fetches Keycloak AAuth metadata from `/.well-known/aauth-issuer`
- Makes signed HTTPSig requests to Keycloak's `agent_token_endpoint`
- Handles token caching and refresh
"""

import logging
import os
import time
from typing import Dict, Any, Optional
from urllib.parse import urljoin
import httpx
import json

from app.config import settings
from app.services.aauth_interceptor import get_signing_keypair
from app.tracing_config import span, add_event, set_attribute

# Configure logging
logger = logging.getLogger(__name__)

# Check DEBUG mode from environment
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Token cache: maps (agent_id, scope) -> (auth_token, refresh_token, expires_at)
_token_cache: Dict[str, Dict[str, Any]] = {}


class AAuthTokenService:
    """Service for requesting AAuth auth tokens from Keycloak."""
    
    def __init__(self):
        self.issuer_url = os.getenv("KEYCLOAK_AAUTH_ISSUER_URL")
        if not self.issuer_url:
            # Derive from KEYCLOAK_URL and KEYCLOAK_REALM
            keycloak_url = os.getenv("KEYCLOAK_URL", settings.keycloak_url)
            keycloak_realm = os.getenv("KEYCLOAK_REALM", settings.keycloak_realm)
            self.issuer_url = f"{keycloak_url}/realms/{keycloak_realm}"
        
        self.agent_token_endpoint = os.getenv("KEYCLOAK_AAUTH_AGENT_TOKEN_ENDPOINT")
        # Construct metadata URL by appending path to issuer URL (not using urljoin which treats / as absolute)
        self.metadata_url = f"{self.issuer_url.rstrip('/')}/.well-known/aauth-issuer"
        self.cache_ttl = int(os.getenv("AAUTH_AUTH_TOKEN_CACHE_TTL", "3600"))
        
        # Get signing keypair
        self.private_key, self.public_key, self.public_jwk = get_signing_keypair()
        
        # Signature scheme for signing requests to Keycloak
        self.signature_scheme = os.getenv("AAUTH_SIGNATURE_SCHEME", "hwk").lower()
        if self.signature_scheme not in ["hwk", "jwks"]:
            logger.warning(f"⚠️ Invalid AAUTH_SIGNATURE_SCHEME: {self.signature_scheme}, defaulting to hwk")
            self.signature_scheme = "hwk"
        
        logger.info(f"🔐 AAuth Token Service initialized")
        logger.info(f"🔐   Issuer URL: {self.issuer_url}")
        logger.info(f"🔐   Metadata URL: {self.metadata_url}")
        logger.info(f"🔐   Signature scheme: {self.signature_scheme}")
        if DEBUG:
            logger.debug(f"🔐   Cache TTL: {self.cache_ttl} seconds")
    
    async def _fetch_metadata(self) -> Dict[str, Any]:
        """Fetch Keycloak AAuth metadata from `/.well-known/aauth-issuer`.
        
        Returns:
            Metadata dictionary with `agent_token_endpoint` and other endpoints.
        """
        with span("aauth_token_service.fetch_metadata", {
            "metadata_url": self.metadata_url
        }) as span_obj:
            try:
                logger.info(f"🔐 Fetching AAuth metadata from {self.metadata_url}")
                if DEBUG:
                    logger.debug(f"🔐 Metadata URL: {self.metadata_url}")
                
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(self.metadata_url)
                    response.raise_for_status()
                    metadata = response.json()
                    
                    logger.info(f"✅ AAuth metadata fetched successfully")
                    if DEBUG:
                        logger.debug(f"🔐 Metadata: {json.dumps(metadata, indent=2)}")
                    
                    add_event("aauth_metadata_fetched", {"metadata": metadata})
                    set_attribute("aauth.metadata.issuer", metadata.get("issuer", ""))
                    set_attribute("aauth.metadata.agent_token_endpoint", metadata.get("agent_token_endpoint", ""))
                    
                    return metadata
            except Exception as e:
                logger.error(f"❌ Failed to fetch AAuth metadata: {e}")
                if DEBUG:
                    import traceback
                    logger.debug(traceback.format_exc())
                add_event("aauth_metadata_fetch_failed", {"error": str(e)})
                raise
    
    async def _get_agent_token_endpoint(self) -> str:
        """Get the agent_token_endpoint URL.
        
        Returns:
            Full URL to the agent_token_endpoint.
        """
        if self.agent_token_endpoint:
            return self.agent_token_endpoint
        
        # Fetch metadata to get endpoint
        metadata = await self._fetch_metadata()
        endpoint = metadata.get("agent_token_endpoint")
        if not endpoint:
            # Default to standard path
            endpoint = urljoin(self.issuer_url, "/protocol/aauth/agent/token")
        
        self.agent_token_endpoint = endpoint
        logger.info(f"🔐 Agent token endpoint: {self.agent_token_endpoint}")
        return endpoint
    
    async def _sign_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes] = None
    ) -> Dict[str, str]:
        """Sign an HTTP request using AAuth signature scheme.
        
        Args:
            method: HTTP method (e.g., "POST")
            url: Target URL
            headers: Request headers
            body: Request body bytes
            
        Returns:
            Dictionary of signature headers to add to the request.
        """
        from aauth import sign_request
        
        # Note: The aauth library's sign_request() function automatically adds:
        # - content-digest header (per SPEC Section 10.3, RFC 9530) when body is present
        # - Signature-Input, Signature, and Signature-Key headers
        # We don't need to manually add content-digest - it's handled by the library.
        
        sign_kwargs = {}
        if self.signature_scheme == "jwks":
            agent_id = os.getenv("BACKEND_AGENT_URL", f"http://{settings.host}:{settings.port}")
            kid = self.public_jwk.get("kid", "backend-key-1")
            sign_kwargs = {
                "id": agent_id,
                "kid": kid
            }
            if DEBUG:
                logger.debug(f"🔐 Signing with JWKS scheme: agent_id={agent_id}, kid={kid}")
        else:
            # HWK scheme
            if DEBUG:
                logger.debug(f"🔐 Signing with HWK scheme")
        
        logger.info(f"🔐 Calling aauth.sign_request with:")
        logger.info(f"🔐   method: {method}")
        logger.info(f"🔐   target_uri: {url}")
        logger.info(f"🔐   headers: {headers}")
        logger.info(f"🔐   body_length: {len(body) if body else 0}")
        logger.info(f"🔐   body type: {type(body)}")
        if body:
            logger.info(f"🔐   body hex (first 100): {body.hex()[:100]}...")
            # Compute what digest aauth SHOULD compute
            import hashlib
            import base64
            pre_sign_digest = base64.b64encode(hashlib.sha256(body).digest()).decode('utf-8')
            logger.info(f"🔐   Expected digest from this body: sha-256=:{pre_sign_digest}:")
        logger.info(f"🔐   sig_scheme: {self.signature_scheme}")
        logger.info(f"🔐   sign_kwargs: {sign_kwargs}")

        # Log the public key being used for signing (for debugging key mismatch)
        logger.info(f"🔐 CLIENT SIGNING KEY INFO:")
        logger.info(f"🔐   Public key X (base64): {self.public_jwk.get('x', 'N/A')}")
        logger.info(f"🔐   Public key kid: {self.public_jwk.get('kid', 'N/A')}")
        logger.info(f"🔐   Public key kty: {self.public_jwk.get('kty', 'N/A')}")
        logger.info(f"🔐   Public key crv: {self.public_jwk.get('crv', 'N/A')}")
        logger.info(f"🔐   Full JWK: {self.public_jwk}")

        sig_headers = sign_request(
            method=method,
            target_uri=url,
            headers=headers,
            body=body,
            private_key=self.private_key,
            sig_scheme=self.signature_scheme,
            **sign_kwargs
        )

        logger.info(f"🔐 aauth.sign_request returned: {sig_headers}")

        # LOCAL SIGNATURE VERIFICATION - verify what the aauth library signed
        try:
            from urllib.parse import urlparse
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            # Reconstruct the expected signature base (per RFC 9421)
            parsed_url = urlparse(url)
            sig_input = sig_headers.get('Signature-Input', '')
            sig_key_header = sig_headers.get('Signature-Key', '')

            # Build signature base as Keycloak expects
            signature_base_lines = [
                f'"@method": {method}',
                f'"@authority": {parsed_url.netloc}',
                f'"@path": {parsed_url.path}',
                f'"content-type": {headers.get("Content-Type", "")}',
                f'"content-digest": {headers.get("Content-Digest", "")}',
                f'"signature-key": {sig_key_header}',
            ]

            # Add @signature-params as the final line (RFC 9421 requirement)
            # Extract just the params part from sig1=(...);created=...
            if sig_input.startswith('sig1='):
                params_part = sig_input[5:]  # Remove 'sig1='
                signature_base_lines.append(f'"@signature-params": {params_part}')

            signature_base = '\n'.join(signature_base_lines)
            logger.info(f"🔐 Note: signature_base length should now match aauth library after fix")

            logger.info(f"🔐 LOCAL SIGNATURE VERIFICATION:")
            logger.info(f"🔐 Expected signature base:")
            for line in signature_base_lines:
                logger.info(f"🔐   {line}")
            logger.info(f"🔐 Signature base bytes (hex, first 200): {signature_base.encode('utf-8').hex()[:200]}...")
            logger.info(f"🔐 Signature base length: {len(signature_base.encode('utf-8'))} bytes")

            # Try to verify the signature locally
            signature_b64 = sig_headers.get('Signature', '').replace('sig1=:', '').rstrip(':')
            # Handle URL-safe base64
            signature_bytes = base64.urlsafe_b64decode(signature_b64 + '==')

            logger.info(f"🔐 Signature bytes length: {len(signature_bytes)}")

            # Verify using the public key
            public_key_bytes = base64.urlsafe_b64decode(self.public_jwk['x'] + '==')
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            try:
                public_key.verify(signature_bytes, signature_base.encode('utf-8'))
                logger.info(f"🔐 ✅ LOCAL SIGNATURE VERIFICATION PASSED!")
                logger.info(f"🔐    The aauth library signed the expected signature base correctly.")
            except Exception as verify_error:
                logger.error(f"🔐 ❌ LOCAL SIGNATURE VERIFICATION FAILED!")
                logger.error(f"🔐    Error: {verify_error}")
                logger.error(f"🔐    This means the aauth library signed a DIFFERENT signature base!")
                logger.error(f"🔐    The issue is in the aauth library's signature base construction.")

        except Exception as e:
            logger.warning(f"🔐 Could not perform local signature verification: {e}")

        # Check if aauth computed the correct Content-Digest
        if 'Content-Digest' in sig_headers:
            aauth_digest = sig_headers['Content-Digest']
            logger.info(f"🔐 aauth computed Content-Digest: {aauth_digest}")
            if body:
                import hashlib
                import base64
                expected = f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode('utf-8')}:"
                if aauth_digest != expected:
                    logger.error(f"🔐 ❌ AAUTH LIBRARY COMPUTED WRONG DIGEST!")
                    logger.error(f"🔐    aauth returned: {aauth_digest}")
                    logger.error(f"🔐    Expected:       {expected}")
                    logger.error(f"🔐    This is a bug in the aauth library!")
                else:
                    logger.info(f"🔐 ✓ aauth computed correct Content-Digest")
        else:
            logger.warning(f"🔐 ⚠️ aauth did not return Content-Digest header!")

        # Analyze the signature that was created
        if 'Signature-Input' in sig_headers:
            logger.info(f"🔐 SIGNATURE ANALYSIS:")
            logger.info(f"🔐 Signature-Input: {sig_headers['Signature-Input']}")
            logger.info(f"🔐 Signature: {sig_headers.get('Signature', '')[:100]}...")
            logger.info(f"🔐 Signature-Key: {sig_headers.get('Signature-Key', '')}")

            # Check if this matches RFC 9421 format
            sig_input = sig_headers['Signature-Input']
            if 'created=' in sig_input:
                logger.info(f"🔐 ✓ Uses RFC 9421 'created' parameter")
            else:
                logger.info(f"🔐 ✗ Missing RFC 9421 'created' parameter")

            # Try to determine what signature base format is being used
            if sig_input.startswith('sig1='):
                logger.info(f"🔐 ⚠️  Uses draft format 'sig1=' instead of RFC 9421 'sig='")
            else:
                logger.info(f"🔐 ✓ Uses RFC 9421 signature label format")

        return sig_headers
    
    async def request_auth_token(
        self,
        resource_token: str,
        redirect_uri: str
    ) -> Dict[str, str]:
        """Request an auth token from Keycloak using a resource token.
        
        Per SPEC Section 9.3, this method:
        - Makes a signed HTTPSig request to Keycloak's `agent_token_endpoint`
        - Includes `request_type=auth`, `resource_token`, and `redirect_uri`
        - Signs the request using `AAUTH_SIGNATURE_SCHEME` (hwk or jwks)
        - Returns `auth_token` and `refresh_token` (direct grant per SPEC Section 9.4)
        
        Args:
            resource_token: Signed JWT from the resource (Supply Chain Agent)
            redirect_uri: Redirect URI for the authorization flow
            
        Returns:
            Dictionary with `auth_token`, `refresh_token`, and `expires_in`
        """
        with span("aauth_token_service.request_auth_token", {
            "issuer": self.issuer_url,
            "has_resource_token": bool(resource_token)
        }) as span_obj:
            try:
                logger.info(f"🔐 Requesting auth token from Keycloak")
                if DEBUG:
                    logger.debug(f"🔐 Resource token length: {len(resource_token)}")
                    logger.debug(f"🔐 Redirect URI: {redirect_uri}")
                
                # Get agent token endpoint
                endpoint = await self._get_agent_token_endpoint()
                
                # Prepare request body
                body_data = {
                    "request_type": "auth",
                    "resource_token": resource_token,
                    "redirect_uri": redirect_uri
                }

                # Serialize body as form-urlencoded
                import urllib.parse
                body_bytes = urllib.parse.urlencode(body_data).encode('utf-8')

                logger.info(f"🔐 BODY SERIALIZATION:")
                logger.info(f"🔐 body_data dict: {body_data}")
                logger.info(f"🔐 urllib.parse.urlencode result: {urllib.parse.urlencode(body_data)}")
                logger.info(f"🔐 body_bytes: {body_bytes}")
                logger.info(f"🔐 body_bytes length: {len(body_bytes)}")
                
                # Prepare headers
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": str(len(body_bytes))
                }

                # CRITICAL: Add Content-Digest header BEFORE signing
                # This ensures we control exactly what digest value gets signed
                import hashlib
                import base64
                content_digest = f"sha-256=:{base64.b64encode(hashlib.sha256(body_bytes).digest()).decode('utf-8')}:"
                headers["Content-Digest"] = content_digest
                logger.info(f"🔐 Added Content-Digest header BEFORE signing: {content_digest}")

                # Sign the request
                logger.info(f"🔐 About to sign auth token request with method=POST, url={endpoint}")
                logger.info(f"🔐 Headers before signing: {dict(headers)}")
                logger.info(f"🔐 Body bytes length: {len(body_bytes)}")
                logger.info(f"🔐 EXACT BODY BYTES FOR SIGNING (hex): {body_bytes.hex()[:200]}...")
                logger.info(f"🔐 Body as string: {body_bytes.decode('utf-8')[:200]}...")

                # Manually compute Content-Digest to verify what the aauth library SHOULD compute
                import hashlib
                import base64
                body_digest = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode('utf-8')
                expected_digest = f"sha-256=:{body_digest}:"
                logger.info(f"🔐 MANUALLY COMPUTED CONTENT-DIGEST (from body_bytes we're passing to aauth): {expected_digest}")
                logger.info(f"🔐 If aauth returns a different digest, it's processing the body differently!")

                sig_headers = await self._sign_request("POST", endpoint, headers, body_bytes)
                headers.update(sig_headers)

                logger.info(f"🔐 Signature headers added: {sig_headers}")
                logger.info(f"🔐 Final headers after signing: {dict(headers)}")

                logger.info(f"🔐 Making signed request to {endpoint}")

                # Always log detailed headers for auth server calls (critical for signature debugging)
                logger.info(f"🔐 ===== AUTH SERVER REQUEST HEADERS =====")
                logger.info(f"🔐 Method: POST")
                logger.info(f"🔐 URL: {endpoint}")
                logger.info(f"🔐 Body length: {len(body_bytes)} bytes")
                logger.info(f"🔐 Body content: {body_bytes.decode('utf-8')}")
                logger.info(f"🔐 All headers being sent:")
                for header_name, header_value in headers.items():
                    # Show full header values for debugging (don't truncate)
                    logger.info(f"🔐   {header_name}: {header_value}")
                    # Special detailed logging for Signature-Key header
                    if header_name.lower() == "signature-key":
                        logger.info(f"🔐     ^^^ Signature-Key raw value: {repr(header_value)}")
                        logger.info(f"🔐     ^^^ Signature-Key bytes: {[b for b in header_value.encode('utf-8')]}")
                    # Highlight content-digest if present
                    if header_name.lower() == "content-digest":
                        logger.info(f"🔐     ^^^ Content-Digest (added by aauth library when body is present)")
                logger.info(f"🔐 ========================================")

                if DEBUG:
                    logger.debug(f"🔐 ===== Keycloak Request Details =====")
                    logger.debug(f"🔐 Method: POST")
                    logger.debug(f"🔐 URL: {endpoint}")
                    logger.debug(f"🔐 Body length: {len(body_bytes)} bytes")
                    logger.debug(f"🔐 Body content: {body_bytes.decode('utf-8')}")
                    logger.debug(f"🔐 All headers:")
                    for header_name, header_value in headers.items():
                        # Truncate very long values (like signatures) for readability
                        if len(header_value) > 200:
                            display_value = f"{header_value[:200]}... (truncated, total length: {len(header_value)})"
                        else:
                            display_value = header_value
                        logger.debug(f"🔐   {header_name}: {display_value}")
                        # Highlight content-digest if present
                        if header_name.lower() == "content-digest":
                            logger.debug(f"🔐     ^^^ Content-Digest (added by aauth library when body is present)")
                    logger.debug(f"🔐 =====================================")

                # Make request to Keycloak
                logger.info(f"🔐 ABOUT TO MAKE HTTP REQUEST TO KEYCLOAK...")
                logger.info(f"🔐 Final body_bytes: {body_bytes}")
                logger.info(f"🔐 Final body_bytes length: {len(body_bytes)}")
                logger.info(f"🔐 Content-Length header: {headers.get('Content-Length')}")
                logger.info(f"🔐 Final headers: {dict(headers)}")

                # Verify Content-Length matches actual body length
                if headers.get('Content-Length') != str(len(body_bytes)):
                    logger.error(f"🔐 ❌ CONTENT-LENGTH MISMATCH!")
                    logger.error(f"🔐    Header says: {headers.get('Content-Length')}")
                    logger.error(f"🔐    Actual body: {len(body_bytes)}")
                    # Fix the Content-Length header
                    headers['Content-Length'] = str(len(body_bytes))
                    logger.info(f"🔐 Fixed Content-Length to: {headers['Content-Length']}")

                # Manually verify Content-Digest matches the body we're about to send
                import hashlib
                import base64
                actual_digest = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode('utf-8')
                expected_content_digest = f"sha-256=:{actual_digest}:"
                sent_content_digest = headers.get('Content-Digest', '')
                logger.info(f"🔐 CONTENT-DIGEST VERIFICATION:")
                logger.info(f"🔐   Computed from body_bytes: {expected_content_digest}")
                logger.info(f"🔐   Header being sent:        {sent_content_digest}")
                if expected_content_digest != sent_content_digest:
                    logger.error(f"🔐 ❌ CONTENT-DIGEST MISMATCH BEFORE SENDING!")
                    logger.error(f"🔐    This means aauth library computed digest from different bytes!")
                else:
                    logger.info(f"🔐 ✓ Content-Digest matches body_bytes")

                async with httpx.AsyncClient(timeout=30.0) as client:
                    # Build request explicitly to inspect it
                    request = client.build_request(
                        "POST",
                        endpoint,
                        headers=headers,
                        content=body_bytes
                    )
                    logger.info(f"🔐 Built request - content length: {len(request.content) if request.content else 0}")
                    logger.info(f"🔐 Built request - headers: {dict(request.headers)}")

                    response = await client.send(request)

                    logger.info(f"🔐 HTTP RESPONSE STATUS: {response.status_code}")
                    if response.status_code != 200:
                        logger.info(f"🔐 HTTP RESPONSE TEXT: {response.text[:500]}")

                    if response.status_code == 200:
                        result = response.json()
                        auth_token = result.get("auth_token")
                        refresh_token = result.get("refresh_token")
                        expires_in = result.get("expires_in", 3600)
                        
                        logger.info(f"✅ Auth token received successfully")
                        if DEBUG:
                            logger.debug(f"🔐 Auth token length: {len(auth_token) if auth_token else 0}")
                            logger.debug(f"🔐 Expires in: {expires_in} seconds")
                        
                        add_event("aauth_token_received", {
                            "has_auth_token": bool(auth_token),
                            "has_refresh_token": bool(refresh_token),
                            "expires_in": expires_in
                        })
                        set_attribute("aauth.token.received", True)
                        set_attribute("aauth.token.expires_in", expires_in)
                        
                        return {
                            "auth_token": auth_token,
                            "refresh_token": refresh_token,
                            "expires_in": expires_in
                        }
                    else:
                        error_msg = f"Keycloak returned status {response.status_code}"
                        try:
                            error_body = response.json()
                            error_msg = error_body.get("error", error_msg)
                            if DEBUG:
                                logger.debug(f"🔐 Error response: {error_body}")
                        except:
                            error_msg = f"{error_msg}: {response.text[:200]}"
                        
                        logger.error(f"❌ Failed to get auth token: {error_msg}")
                        add_event("aauth_token_request_failed", {
                            "status_code": response.status_code,
                            "error": error_msg
                        })
                        set_attribute("aauth.token.received", False)
                        raise Exception(f"Failed to get auth token: {error_msg}")
                        
            except Exception as e:
                logger.error(f"❌ Exception requesting auth token: {e}")
                if DEBUG:
                    import traceback
                    logger.debug(traceback.format_exc())
                add_event("aauth_token_request_exception", {"error": str(e)})
                raise
    
    async def refresh_auth_token(self, refresh_token: str) -> Dict[str, str]:
        """Refresh an auth token using a refresh token.
        
        Per SPEC Section 9.7, this method:
        - Makes a signed HTTPSig request to Keycloak's `agent_token_endpoint`
        - Includes `request_type=refresh` and `refresh_token`
        - Returns new `auth_token` and `refresh_token`
        
        Args:
            refresh_token: Refresh token from previous auth token request
            
        Returns:
            Dictionary with `auth_token`, `refresh_token`, and `expires_in`
        """
        with span("aauth_token_service.refresh_auth_token", {
            "issuer": self.issuer_url
        }) as span_obj:
            try:
                logger.info(f"🔐 Refreshing auth token")
                if DEBUG:
                    logger.debug(f"🔐 Refresh token length: {len(refresh_token)}")
                
                # Get agent token endpoint
                endpoint = await self._get_agent_token_endpoint()
                
                # Prepare request body
                body_data = {
                    "request_type": "refresh",
                    "refresh_token": refresh_token
                }

                # Serialize body as form-urlencoded
                import urllib.parse
                body_bytes = urllib.parse.urlencode(body_data).encode('utf-8')

                logger.info(f"🔐 BODY SERIALIZATION (REFRESH):")
                logger.info(f"🔐 body_data dict: {body_data}")
                logger.info(f"🔐 urllib.parse.urlencode result: {urllib.parse.urlencode(body_data)}")
                logger.info(f"🔐 body_bytes: {body_bytes}")
                logger.info(f"🔐 body_bytes length: {len(body_bytes)}")

                # Prepare headers
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": str(len(body_bytes))
                }

                # CRITICAL: Add Content-Digest header BEFORE signing
                # This ensures we control exactly what digest value gets signed
                import hashlib
                import base64
                content_digest = f"sha-256=:{base64.b64encode(hashlib.sha256(body_bytes).digest()).decode('utf-8')}:"
                headers["Content-Digest"] = content_digest
                logger.info(f"🔐 Added Content-Digest header BEFORE signing: {content_digest}")

                # Sign the request
                logger.info(f"🔐 About to sign refresh token request with method=POST, url={endpoint}")
                logger.info(f"🔐 Headers before signing: {dict(headers)}")
                logger.info(f"🔐 Body bytes length: {len(body_bytes)}")

                sig_headers = await self._sign_request("POST", endpoint, headers, body_bytes)
                headers.update(sig_headers)

                logger.info(f"🔐 Signature headers added: {sig_headers}")
                logger.info(f"🔐 Final headers after signing: {dict(headers)}")

                logger.info(f"🔐 Making signed refresh request to {endpoint}")
                if DEBUG:
                    logger.debug(f"🔐 ===== Keycloak Refresh Request Details =====")
                    logger.debug(f"🔐 Method: POST")
                    logger.debug(f"🔐 URL: {endpoint}")
                    logger.debug(f"🔐 Body length: {len(body_bytes)} bytes")
                    logger.debug(f"🔐 Body content: {body_bytes.decode('utf-8')}")
                    logger.debug(f"🔐 All headers:")
                    for header_name, header_value in headers.items():
                        # Truncate very long values (like signatures) for readability
                        if len(header_value) > 200:
                            display_value = f"{header_value[:200]}... (truncated, total length: {len(header_value)})"
                        else:
                            display_value = header_value
                        logger.debug(f"🔐   {header_name}: {display_value}")
                        # Highlight content-digest if present
                        if header_name.lower() == "content-digest":
                            logger.debug(f"🔐     ^^^ Content-Digest (added by aauth library when body is present)")
                    logger.debug(f"🔐 ============================================")

                # Make request to Keycloak
                logger.info(f"🔐 ABOUT TO MAKE HTTP REQUEST TO KEYCLOAK (REFRESH)...")
                logger.info(f"🔐 Final body_bytes length: {len(body_bytes)}")
                logger.info(f"🔐 Content-Length header: {headers.get('Content-Length')}")
                logger.info(f"🔐 Final headers: {dict(headers)}")

                # Verify Content-Length matches actual body length
                if headers.get('Content-Length') != str(len(body_bytes)):
                    logger.error(f"🔐 ❌ CONTENT-LENGTH MISMATCH!")
                    headers['Content-Length'] = str(len(body_bytes))

                async with httpx.AsyncClient(timeout=30.0) as client:
                    # Build request explicitly to inspect it
                    request = client.build_request(
                        "POST",
                        endpoint,
                        headers=headers,
                        content=body_bytes
                    )
                    logger.info(f"🔐 Built request - content length: {len(request.content) if request.content else 0}")

                    response = await client.send(request)

                    logger.info(f"🔐 HTTP RESPONSE STATUS: {response.status_code}")
                    if response.status_code != 200:
                        logger.info(f"🔐 HTTP RESPONSE TEXT: {response.text[:500]}")

                    if response.status_code == 200:
                        result = response.json()
                        auth_token = result.get("auth_token")
                        refresh_token = result.get("refresh_token")
                        expires_in = result.get("expires_in", 3600)
                        
                        logger.info(f"✅ Auth token refreshed successfully")
                        if DEBUG:
                            logger.debug(f"🔐 New auth token length: {len(auth_token) if auth_token else 0}")
                            logger.debug(f"🔐 Expires in: {expires_in} seconds")
                        
                        add_event("aauth_token_refreshed", {
                            "has_auth_token": bool(auth_token),
                            "has_refresh_token": bool(refresh_token),
                            "expires_in": expires_in
                        })
                        
                        return {
                            "auth_token": auth_token,
                            "refresh_token": refresh_token,
                            "expires_in": expires_in
                        }
                    else:
                        error_msg = f"Keycloak returned status {response.status_code}"
                        try:
                            error_body = response.json()
                            error_msg = error_body.get("error", error_msg)
                        except:
                            error_msg = f"{error_msg}: {response.text[:200]}"
                        
                        logger.error(f"❌ Failed to refresh auth token: {error_msg}")
                        add_event("aauth_token_refresh_failed", {
                            "status_code": response.status_code,
                            "error": error_msg
                        })
                        raise Exception(f"Failed to refresh auth token: {error_msg}")
                        
            except Exception as e:
                logger.error(f"❌ Exception refreshing auth token: {e}")
                if DEBUG:
                    import traceback
                    logger.debug(traceback.format_exc())
                add_event("aauth_token_refresh_exception", {"error": str(e)})
                raise
    
    def _get_cache_key(self, agent_id: str, scope: str) -> str:
        """Generate cache key for token storage."""
        return f"{agent_id}:{scope}"
    
    def _is_token_expired(self, expires_at: float) -> bool:
        """Check if token is expired."""
        return time.time() >= expires_at
    
    async def get_cached_token(self, agent_id: str, scope: str) -> Optional[str]:
        """Get cached auth token if available and not expired.
        
        Args:
            agent_id: Agent identifier
            scope: Requested scope
            
        Returns:
            Cached auth token if available and valid, None otherwise
        """
        cache_key = self._get_cache_key(agent_id, scope)
        cached = _token_cache.get(cache_key)
        
        if cached:
            expires_at = cached.get("expires_at", 0)
            if not self._is_token_expired(expires_at):
                auth_token = cached.get("auth_token")
                logger.info(f"✅ Using cached auth token (expires in {int(expires_at - time.time())} seconds)")
                if DEBUG:
                    logger.debug(f"🔐 Cache key: {cache_key}")
                return auth_token
            else:
                logger.info(f"🔐 Cached token expired, removing from cache")
                del _token_cache[cache_key]
        
        return None
    
    def _cache_token(
        self,
        agent_id: str,
        scope: str,
        auth_token: str,
        refresh_token: str,
        expires_in: int
    ):
        """Cache auth token with expiration.
        
        Args:
            agent_id: Agent identifier
            scope: Requested scope
            auth_token: Auth token to cache
            refresh_token: Refresh token to cache
            expires_in: Token expiration time in seconds
        """
        cache_key = self._get_cache_key(agent_id, scope)
        expires_at = time.time() + expires_in - 60  # Subtract 60 seconds for safety margin
        
        _token_cache[cache_key] = {
            "auth_token": auth_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
            "expires_in": expires_in
        }
        
        logger.info(f"🔐 Cached auth token (expires in {expires_in} seconds)")
        if DEBUG:
            logger.debug(f"🔐 Cache key: {cache_key}")
            logger.debug(f"🔐 Expires at: {expires_at} ({time.ctime(expires_at)})")


# Global instance
aauth_token_service = AAuthTokenService()

