#!/usr/bin/env python3
"""AAuth Token Exchange Service for Supply Chain Agent.

This service implements token exchange (SPEC 9.10) for multi-hop delegation.
When SCA receives an auth_token from upstream (backend) and needs to call
downstream (MAA), it exchanges the upstream token for a new token bound to MAA.

Per SPEC Section 9.10:
- POST to agent_token_endpoint with request_type=exchange
- Present upstream auth_token in Signature-Key header with scheme=jwt
- Sign the request with SCA's signing key
- Return exchanged auth_token with act claim
"""

import logging
import os
import time
from typing import Dict, Any, Optional
from urllib.parse import urljoin
import httpx
import json
import urllib.parse
import hashlib
import base64

from aauth_interceptor import get_signing_keypair
from aauth import sign_request, public_key_to_jwk
from tracing_config import span, add_event, set_attribute

# Configure logging
logger = logging.getLogger(__name__)

# Check DEBUG mode from environment
DEBUG = os.getenv("DEBUG", "false").lower() == "true"


class AAuthTokenService:
    """Service for exchanging AAuth tokens for multi-hop delegation."""
    
    def __init__(self):
        self.issuer_url = os.getenv("KEYCLOAK_AAUTH_ISSUER_URL")
        if not self.issuer_url:
            # Derive from KEYCLOAK_URL and KEYCLOAK_REALM if available
            keycloak_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
            keycloak_realm = os.getenv("KEYCLOAK_REALM", "aauth-test")
            self.issuer_url = f"{keycloak_url}/realms/{keycloak_realm}"
        
        self.agent_token_endpoint = os.getenv("KEYCLOAK_AAUTH_AGENT_TOKEN_ENDPOINT")
        # Construct metadata URL by appending path to issuer URL
        self.metadata_url = f"{self.issuer_url.rstrip('/')}/.well-known/aauth-issuer"
        
        # Get signing keypair
        self.private_key, self.public_key, self.public_jwk = get_signing_keypair()
        
        # Signature scheme for signing requests to Keycloak
        self.signature_scheme = os.getenv("AAUTH_SIGNATURE_SCHEME", "jwks").lower()
        if self.signature_scheme not in ["hwk", "jwks"]:
            logger.warning(f"⚠️ Invalid AAUTH_SIGNATURE_SCHEME: {self.signature_scheme}, defaulting to jwks")
            self.signature_scheme = "jwks"
        
        logger.info(f"🔐 AAuth Token Exchange Service initialized")
        logger.info(f"🔐   Issuer URL: {self.issuer_url}")
        logger.info(f"🔐   Metadata URL: {self.metadata_url}")
        logger.info(f"🔐   Signature scheme: {self.signature_scheme}")
    
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
        body: Optional[bytes],
        upstream_auth_token: Optional[str] = None
    ) -> Dict[str, str]:
        """Sign the request with AAuth HTTPSig.
        
        For token exchange, the upstream auth_token is presented in Signature-Key
        header with scheme=jwt, while the request itself is signed with SCA's key.
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers
            body: Request body bytes
            upstream_auth_token: Optional upstream auth token for exchange requests
            
        Returns:
            Dictionary of signature headers to add to the request
        """
        # Prepare signing parameters
        sign_kwargs = {}
        agent_id = None
        kid = None
        
        # For token exchange (when upstream_auth_token is provided), use scheme=jwt per SPEC 9.10:
        # "The upstream auth token MUST be presented via the Signature-Key header using
        #  sig=(scheme=jwt jwt="<upstream-auth-token>")"
        if upstream_auth_token:
            # Use scheme=jwt with the upstream auth token
            effective_scheme = "jwt"
            sign_kwargs = {
                "jwt": upstream_auth_token
            }
            logger.info(f"🔐 Signing with JWT scheme for token exchange (upstream auth_token length: {len(upstream_auth_token)})")
            if DEBUG:
                logger.debug(f"🔐 Upstream auth_token (first 50 chars): {upstream_auth_token[:50]}...")
        elif self.signature_scheme == "jwks":
            # For non-exchange requests, use JWKS scheme
            effective_scheme = "jwks"
            agent_id = os.getenv("SUPPLY_CHAIN_AGENT_ID_URL")
            if not agent_id:
                agent_id = os.getenv("SUPPLY_CHAIN_AGENT_URL", "http://localhost:9999").rstrip('/')
            
            # Extract kid from the public JWK
            kid = self.public_jwk.get("kid", "supply-chain-agent-key-1")
            sign_kwargs = {
                "id": agent_id,
                "kid": kid
            }
            logger.info(f"🔐 Signing with JWKS scheme (agent: {agent_id}, kid: {kid})")
        else:
            # Default to HWK scheme
            effective_scheme = "hwk"
            logger.info(f"🔐 Signing with {effective_scheme} scheme")
        
        # Sign the request
        sig_headers = sign_request(
            method=method,
            target_uri=str(url),
            headers=headers,
            body=body,
            private_key=self.private_key,
            sig_scheme=effective_scheme,
            **sign_kwargs
        )
        
        return sig_headers
    
    async def exchange_token(
        self,
        upstream_auth_token: str,
        resource_token: str,
        auth_server_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Exchange upstream auth_token for a new token bound to downstream resource.
        
        Per SPEC Section 9.10, this method:
        1. POSTs to agent_token_endpoint with request_type=exchange
        2. Includes resource_token in the request body
        3. Presents upstream_auth_token in Signature-Key header with scheme=jwt
        4. Signs the request with SCA's signing key
        
        Args:
            upstream_auth_token: The auth_token from upstream (backend)
            resource_token: The resource_token from downstream resource's Agent-Auth challenge
            auth_server_url: Optional auth server URL (defaults to issuer_url)
            
        Returns:
            Dictionary with `auth_token` and `expires_in`
        """
        with span("aauth_token_service.exchange_token", {
            "issuer": self.issuer_url,
            "has_upstream_token": bool(upstream_auth_token),
            "has_resource_token": bool(resource_token)
        }) as span_obj:
            try:
                logger.info(f"🔐 Exchanging upstream auth_token for downstream token")
                if DEBUG:
                    logger.debug(f"🔐 Upstream auth_token length: {len(upstream_auth_token)}")
                    logger.debug(f"🔐 Resource token length: {len(resource_token)}")
                
                # Get agent token endpoint
                endpoint = await self._get_agent_token_endpoint()
                
                # Prepare request body per SPEC 9.10
                body_data = {
                    "request_type": "exchange",
                    "resource_token": resource_token
                }
                
                # Serialize body as form-urlencoded
                body_bytes = urllib.parse.urlencode(body_data).encode('utf-8')
                
                if DEBUG:
                    logger.debug(f"🔐 Exchange request body: {body_bytes.decode('utf-8')}")
                
                # Prepare headers
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": str(len(body_bytes))
                }
                
                # Add Content-Digest header
                content_digest = f"sha-256=:{base64.b64encode(hashlib.sha256(body_bytes).digest()).decode('utf-8')}:"
                headers["Content-Digest"] = content_digest
                
                # Sign the request with upstream auth_token in Signature-Key
                sig_headers = await self._sign_request(
                    "POST",
                    endpoint,
                    headers,
                    body_bytes,
                    upstream_auth_token=upstream_auth_token
                )
                headers.update(sig_headers)
                
                logger.info(f"🔐 Making token exchange request to {endpoint}")
                if DEBUG:
                    logger.debug(f"🔐 Request headers: {dict(headers)}")
                
                # Make request to Keycloak
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(endpoint, headers=headers, content=body_bytes)
                
                if response.status_code != 200:
                    error_msg = f"Keycloak returned status {response.status_code}"
                    try:
                        error_body = response.json()
                        error_msg = error_body.get("error", error_msg)
                        error_desc = error_body.get("error_description", "")
                        if error_desc:
                            error_msg = f"{error_msg}: {error_desc}"
                        logger.error(f"❌ Token exchange failed: {error_msg}")
                        logger.info(f"🔐 Keycloak full error response: {error_body}")
                        if DEBUG:
                            logger.debug(f"🔐 Error response: {error_body}")
                    except Exception:
                        error_msg = f"{error_msg}: {response.text[:200]}"
                        logger.error(f"❌ Token exchange failed: {error_msg}")
                    add_event("aauth_token_exchange_failed", {
                        "status_code": response.status_code,
                        "error": error_msg
                    })
                    set_attribute("aauth.token.exchange.failed", True)
                    raise Exception(f"Token exchange failed: {error_msg}")
                
                result = response.json()
                auth_token = result.get("auth_token")
                expires_in = result.get("expires_in", 3600)
                
                if not auth_token:
                    raise Exception("Token exchange did not return auth_token")
                
                logger.info(f"✅ Token exchange successful")
                if DEBUG:
                    logger.debug(f"🔐 Exchanged auth_token length: {len(auth_token)}")
                    logger.debug(f"🔐 Expires in: {expires_in} seconds")
                
                add_event("aauth_token_exchange_success", {
                    "expires_in": expires_in
                })
                set_attribute("aauth.token.exchange.success", True)
                set_attribute("aauth.token.expires_in", expires_in)
                
                return {
                    "auth_token": auth_token,
                    "expires_in": expires_in
                }
                
            except Exception as e:
                logger.error(f"❌ Exception during token exchange: {e}")
                if DEBUG:
                    import traceback
                    logger.debug(traceback.format_exc())
                add_event("aauth_token_exchange_exception", {"error": str(e)})
                raise
