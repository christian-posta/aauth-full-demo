#!/usr/bin/env python3
"""Fetch AAuth issuer metadata (JWKS URL) for Keycloak / spec-compliant auth servers."""

import logging
import time
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

_JWKS_URL_CACHE: Dict[str, tuple[float, str]] = {}
_CACHE_TTL_SECONDS = 300.0


def _normalize_aauth_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    token = metadata.get("token_endpoint") or metadata.get("agent_token_endpoint")
    interaction = metadata.get("interaction_endpoint") or metadata.get("agent_auth_endpoint")
    jwks = metadata.get("jwks_uri")
    return {
        "token_endpoint": token,
        "interaction_endpoint": interaction,
        "jwks_uri": jwks,
    }


def _fetch_metadata_sync(issuer_url: str) -> Dict[str, Any]:
    base = issuer_url.rstrip("/")
    paths = ("/.well-known/aauth-issuer.json", "/.well-known/aauth-issuer")
    last_exc: Optional[Exception] = None
    for path in paths:
        url = f"{base}{path}"
        try:
            response = httpx.get(url, timeout=10.0)
            response.raise_for_status()
            raw = response.json()
            return _normalize_aauth_metadata(raw)
        except Exception as e:
            last_exc = e
            logger.debug("AAuth metadata fetch failed for %s: %s", url, e)
    raise ValueError(
        f"AAuth issuer metadata not found for {issuer_url} (tried {paths})"
    ) from last_exc


def get_aauth_jwks_url(keycloak_issuer_url: str) -> str:
    """
    Return JWKS URL for verifying auth+jwt from the auth server.
    Uses AAuth issuer metadata when available; falls back to OIDC realm certs.
    Results are cached briefly per issuer.
    """
    base = keycloak_issuer_url.rstrip("/")
    now = time.time()
    cached = _JWKS_URL_CACHE.get(base)
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    fallback_oidc = f"{base}/protocol/openid-connect/certs"
    try:
        meta = _fetch_metadata_sync(base)
        jwks = meta.get("jwks_uri")
        if jwks:
            _JWKS_URL_CACHE[base] = (now, jwks)
            return jwks
    except Exception as e:
        logger.warning("AAuth metadata JWKS discovery failed for %s, using OIDC fallback: %s", base, e)

    _JWKS_URL_CACHE[base] = (now, fallback_oidc)
    return fallback_oidc
