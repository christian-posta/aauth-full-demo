#!/usr/bin/env python3

import base64
import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional

import httpx

import asyncio
from aauth import sign_request, parse_aauth_header
from aauth_interceptor import get_signing_keypair

logger = logging.getLogger(__name__)
token_logger = logging.getLogger("aauth.tokens")


def _normalize_aauth_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Map spec + Keycloak extension field names to canonical keys."""
    token = metadata.get("token_endpoint") or metadata.get("agent_token_endpoint")
    interaction = metadata.get("interaction_endpoint") or metadata.get("agent_auth_endpoint")
    jwks = metadata.get("jwks_uri")
    return {
        "token_endpoint": token,
        "interaction_endpoint": interaction,
        "jwks_uri": jwks,
    }


class AAuthTokenService:
    def __init__(self):
        self.issuer_url = os.getenv("KEYCLOAK_AAUTH_ISSUER_URL")
        if not self.issuer_url:
            keycloak_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
            keycloak_realm = os.getenv("KEYCLOAK_REALM", "aauth-test")
            self.issuer_url = f"{keycloak_url}/realms/{keycloak_realm}"

        self.token_endpoint = os.getenv("KEYCLOAK_AAUTH_TOKEN_ENDPOINT")
        self.jwks_uri: Optional[str] = None
        self.private_key, self.public_key, self.public_jwk = get_signing_keypair()
        self.signature_scheme = os.getenv("AAUTH_SIGNATURE_SCHEME", "jwks_uri").lower()
        if self.signature_scheme not in ["hwk", "jwks_uri"]:
            self.signature_scheme = "jwks_uri"
        self.default_wait_seconds = int(os.getenv("AAUTH_PREFER_WAIT_SECONDS", "45"))

    async def _fetch_metadata_for_issuer(self, issuer_url: str) -> Dict[str, Any]:
        """Fetch AAuth issuer metadata; try current spec path then Keycloak extension path."""
        base = issuer_url.rstrip("/")
        paths = ("/.well-known/aauth-issuer.json", "/.well-known/aauth-issuer")
        last_exc: Optional[Exception] = None
        async with httpx.AsyncClient(timeout=10.0) as client:
            for path in paths:
                url = f"{base}{path}"
                try:
                    response = await client.get(url)
                    response.raise_for_status()
                    raw = response.json()
                    return _normalize_aauth_metadata(raw)
                except Exception as e:
                    last_exc = e
                    logger.debug("AAuth metadata fetch failed for %s: %s", url, e)
        raise ValueError(
            f"AAuth issuer metadata not found for {issuer_url} (tried {paths})"
        ) from last_exc

    async def _get_token_endpoint(self, issuer_url: Optional[str] = None) -> str:
        base = (issuer_url or self.issuer_url).rstrip("/")
        default_base = self.issuer_url.rstrip("/")
        use_env = issuer_url is None or base == default_base

        if use_env and self.token_endpoint:
            return self.token_endpoint

        metadata = await self._fetch_metadata_for_issuer(base)
        self.jwks_uri = metadata.get("jwks_uri") or self.jwks_uri
        token_ep = (self.token_endpoint if use_env else None) or metadata.get("token_endpoint")
        if not token_ep:
            raise ValueError("AAuth metadata missing token_endpoint (or agent_token_endpoint)")
        if use_env:
            self.token_endpoint = self.token_endpoint or token_ep
        return token_ep

    def _headers(self, body_bytes: bytes, wait_seconds: int) -> Dict[str, str]:
        digest = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode("utf-8")
        return {
            "Content-Type": "application/json",
            "Content-Length": str(len(body_bytes)),
            "Content-Digest": f"sha-256=:{digest}:",
            "Prefer": f"wait={wait_seconds}",
        }

    async def _sign_request(self, method: str, url: str, headers: Dict[str, str], body_bytes: bytes) -> Dict[str, str]:
        sign_kwargs: Dict[str, str] = {}
        if self.signature_scheme == "jwks_uri":
            agent_id = os.getenv("SUPPLY_CHAIN_AGENT_ID_URL") or os.getenv("SUPPLY_CHAIN_AGENT_URL", "http://localhost:9999").rstrip("/")
            kid = self.public_jwk.get("kid", "supply-chain-agent-key-1")
            sign_kwargs = {"id": agent_id, "kid": kid}

        return sign_request(
            method=method,
            target_uri=str(url),
            headers=headers,
            body=None,
            private_key=self.private_key,
            sig_scheme=self.signature_scheme,
            **sign_kwargs,
        )

    async def exchange_token(
        self,
        upstream_auth_token: str,
        resource_token: str,
        auth_server_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        issuer_override = auth_server_url.rstrip("/") if auth_server_url else None
        endpoint = await self._get_token_endpoint(issuer_override)
        payload = {
            "resource_token": resource_token,
            "upstream_token": upstream_auth_token,
        }
        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = self._headers(body_bytes, self.default_wait_seconds)
        headers.update(await self._sign_request("POST", endpoint, headers, body_bytes))

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(endpoint, headers=headers, content=body_bytes)

        if response.status_code == 202:
            location = response.headers.get("Location")
            retry_after = int(response.headers.get("Retry-After", "0"))
            aauth_header = response.headers.get("AAuth", "")
            parsed = parse_aauth_header(aauth_header) if aauth_header else {}
            body = response.json() if response.content else {}
            require = body.get("require") or parsed.get("require")
            code = body.get("code") or parsed.get("code")
            pending_url = body.get("location") or location
            result: Dict[str, Any] = {
                "status": "approval_pending" if require == "approval" else "interaction_required",
                "pending_url": pending_url,
                "retry_after": retry_after,
                "require": require,
            }
            if code:
                result["interaction_code"] = code
            return result

        if response.status_code != 200:
            try:
                body = response.json()
            except Exception:
                body = {"error": response.text[:200]}
            raise ValueError(f"Token exchange failed: {response.status_code} {body}")

        result = response.json()
        auth_token = result.get("auth_token")
        if not auth_token:
            raise ValueError("Token exchange did not return auth_token")
        token_logger.info("🔐 Token exchange produced downstream auth_token")
        return {
            "status": "success",
            "auth_token": auth_token,
            "expires_in": result.get("expires_in", 3600),
        }

    async def poll_exchanged_token(
        self,
        pending_url: str,
        max_attempts: int = 20,
    ) -> Dict[str, Any]:
        attempts = 0
        next_url = pending_url
        while attempts < max_attempts:
            attempts += 1
            headers = {"Prefer": f"wait={self.default_wait_seconds}"}
            headers.update(await self._sign_request("GET", next_url, headers, b""))
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(next_url, headers=headers)

            if response.status_code == 200:
                result = response.json()
                auth_token = result.get("auth_token")
                if not auth_token:
                    raise ValueError("Pending exchange success missing auth_token")
                return {
                    "status": "success",
                    "auth_token": auth_token,
                    "expires_in": result.get("expires_in", 3600),
                }

            if response.status_code == 202:
                location = response.headers.get("Location")
                retry_after = int(response.headers.get("Retry-After", "0"))
                aauth_header = response.headers.get("AAuth", "")
                parsed = parse_aauth_header(aauth_header) if aauth_header else {}
                body = response.json() if response.content else {}
                require = body.get("require") or parsed.get("require")
                code = body.get("code") or parsed.get("code")
                next_url = body.get("location") or location or next_url
                await asyncio.sleep(max(retry_after, 0))
                pending_result: Dict[str, Any] = {
                    "status": "approval_pending" if require == "approval" else "interaction_required",
                    "pending_url": next_url,
                    "retry_after": retry_after,
                    "require": require,
                }
                if code:
                    pending_result["interaction_code"] = code
                return pending_result

            if response.status_code == 503:
                await asyncio.sleep(int(response.headers.get("Retry-After", "1")))
                continue

            try:
                body = response.json()
            except Exception:
                body = {"error": response.text[:200]}
            raise ValueError(f"Pending token exchange failed: {response.status_code} {body}")

        raise TimeoutError("Timed out waiting for downstream token exchange")
