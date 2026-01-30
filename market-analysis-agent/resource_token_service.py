#!/usr/bin/env python3
"""Resource Token Service for generating and signing resource tokens.

Per SPEC Section 6, resource tokens are signed JWTs that bind an agent's
access request to the resource's identity. This service generates resource
tokens with the required claims and signs them with the resource's private key.
"""

import logging
import os
import time
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import json
import base64
import hashlib

# Try to import PyJWT for JWT creation
try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False
    logging.getLogger(__name__).warning("⚠️ PyJWT not available - resource token generation will fail")

# Configure logging
logger = logging.getLogger(__name__)

# Check DEBUG mode from environment
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# Persistent keypair for resource token signing and JWKS publication.
# Keycloak fetches /.well-known/aauth-resource -> jwks_uri and validates resource tokens with this key.
try:
    from aauth import generate_ed25519_keypair, public_key_to_jwk
    _PRIVATE_KEY, _PUBLIC_KEY = generate_ed25519_keypair()
    _PUBLIC_JWK = public_key_to_jwk(_PUBLIC_KEY, kid="market-analysis-agent-ephemeral-1")
    logger.info("🔐 AAuth: Generated ephemeral Ed25519 keypair for resource token signing and JWKS")
except Exception as e:
    _PRIVATE_KEY = _PUBLIC_KEY = _PUBLIC_JWK = None
    logger.error(f"❌ Failed to generate signing keypair at module load: {e}")


def get_signing_keypair():
    """Return the module-level signing keypair for JWKS and resource token signing.

    Returns:
        Tuple of (private_key, public_key, public_jwk). Use for /jwks.json and generate_resource_token.
    """
    if _PRIVATE_KEY is None:
        raise RuntimeError("Signing keypair not initialized")
    return _PRIVATE_KEY, _PUBLIC_KEY, _PUBLIC_JWK


def calculate_jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """Calculate JWK Thumbprint per RFC 7638.
    
    Per RFC 7638, the thumbprint is computed using only the REQUIRED members
    of the JWK for the specific key type, in lexicographical order.
    
    For OKP (Ed25519/Ed448) keys: crv, kty, x
    For EC keys: crv, kty, x, y
    For RSA keys: e, kty, n
    For symmetric keys: k, kty
    
    Args:
        jwk: JSON Web Key dictionary
        
    Returns:
        BASE64URL(SHA-256(canonical JWK)) as string
    """
    kty = jwk.get("kty")
    
    # Build canonical JWK with only required members per RFC 7638
    if kty == "OKP":
        # Ed25519/Ed448: required members are crv, kty, x (in lex order)
        canonical_members = {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"]
        }
    elif kty == "EC":
        # EC: required members are crv, kty, x, y (in lex order)
        canonical_members = {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"]
        }
    elif kty == "RSA":
        # RSA: required members are e, kty, n (in lex order)
        canonical_members = {
            "e": jwk["e"],
            "kty": jwk["kty"],
            "n": jwk["n"]
        }
    elif kty == "oct":
        # Symmetric: required members are k, kty (in lex order)
        canonical_members = {
            "k": jwk["k"],
            "kty": jwk["kty"]
        }
    else:
        # Unknown key type - use all members (fallback)
        logger.warning(f"Unknown key type '{kty}' - using all JWK members for thumbprint")
        canonical_members = jwk
    
    # Create canonical JWK: sort keys lexicographically, remove whitespace
    canonical_jwk = json.dumps(canonical_members, separators=(',', ':'), sort_keys=True)
    
    if DEBUG:
        logger.debug(f"🔐 Canonical JWK for thumbprint: {canonical_jwk}")
    
    # Calculate SHA-256 hash
    hash_bytes = hashlib.sha256(canonical_jwk.encode('utf-8')).digest()
    
    # Base64URL encode (no padding)
    thumbprint = base64.urlsafe_b64encode(hash_bytes).decode('utf-8').rstrip('=')
    
    if DEBUG:
        logger.debug(f"🔐 Calculated thumbprint: {thumbprint}")
    
    return thumbprint


def generate_resource_token(
    agent_id: str,
    agent_jwk: Dict[str, Any],
    auth_server_url: str,
    scope: str = "market-analysis:analyze",
    expires_in: int = 300  # 5 minutes default
) -> str:
    """Generate and sign a resource token per SPEC Section 6.
    
    Args:
        agent_id: The requesting agent's HTTPS URL identifier
        agent_jwk: The agent's public signing key as JWK (for agent_jkt calculation)
        auth_server_url: The auth server's HTTPS URL identifier (aud claim)
        scope: Space-separated scope values for the access request
        expires_in: Token expiration time in seconds (default: 5 minutes)
        
    Returns:
        Signed JWT resource token as string
    """
    if not HAS_JWT:
        raise ImportError("PyJWT is required for resource token generation")
    
    # Use the module-level persistent keypair (same key published at /jwks.json and /.well-known/aauth-resource)
    private_key, public_key, public_jwk = get_signing_keypair()
    
    # Get resource identifier (iss claim)
    resource_id = os.getenv("MARKET_ANALYSIS_AGENT_ID_URL")
    if not resource_id:
        resource_id = os.getenv("MARKET_ANALYSIS_AGENT_URL", "http://localhost:9998").rstrip('/')
    
    # Calculate agent_jkt (JWK Thumbprint)
    agent_jkt = calculate_jwk_thumbprint(agent_jwk)
    
    if DEBUG:
        logger.debug(f"🔐 Generating resource token:")
        logger.debug(f"🔐   iss: {resource_id}")
        logger.debug(f"🔐   aud: {auth_server_url}")
        logger.debug(f"🔐   agent: {agent_id}")
        logger.debug(f"🔐   agent_jkt: {agent_jkt}")
        logger.debug(f"🔐   scope: {scope}")
        logger.debug(f"🔐   exp: {int(time.time()) + expires_in}")
    
    # Prepare JWT header
    kid = public_jwk.get("kid", "market-analysis-agent-key-1")
    header = {
        "typ": "resource+jwt",
        "alg": "EdDSA",  # Ed25519 uses EdDSA algorithm
        "kid": kid
    }
    
    # Prepare JWT payload
    payload = {
        "iss": resource_id,
        "aud": auth_server_url,
        "agent": agent_id,
        "agent_jkt": agent_jkt,
        "exp": int(time.time()) + expires_in,
        "scope": scope
    }
    
    # Sign the JWT using Ed25519 private key
    try:
        token = jwt.encode(
            payload,
            private_key,
            algorithm="EdDSA",
            headers=header
        )
        
        logger.info(f"✅ Resource token generated successfully")
        if DEBUG:
            logger.debug(f"🔐 Resource token length: {len(token)}")
            logger.debug(f"🔐 Resource token (first 100 chars): {token[:100]}...")
        
        return token
    except Exception as e:
        logger.error(f"❌ Failed to generate resource token: {e}")
        if DEBUG:
            import traceback
            logger.debug(traceback.format_exc())
        raise
