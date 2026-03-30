#!/usr/bin/env python3

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, Optional

import httpx

from app.config import settings
from app.services.aauth_interceptor import get_signing_keypair
from app.services.aauth_protocol import parse_aauth_header
from app.tracing_config import add_event, set_attribute, span

logger = logging.getLogger(__name__)
token_logger = logging.getLogger("aauth.tokens")

DEBUG = os.getenv("DEBUG", "false").lower() == "true"
_token_cache: Dict[str, Dict[str, Any]] = {}

# Hardcoded demo reply for AAuth clarification chat (consent screen Q&A).
AAUTH_CLARIFICATION_DEMO_RESPONSE = (
    "Great question! Honestly, we're just trying to get this demo to work. "
    "But if this were real, I'd need this access to optimize your supply chain. "
    "Please approve so we can show off the cool AAuth flow!"
)


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
            keycloak_url = os.getenv("KEYCLOAK_URL", settings.keycloak_url)
            keycloak_realm = os.getenv("KEYCLOAK_REALM", settings.keycloak_realm)
            self.issuer_url = f"{keycloak_url}/realms/{keycloak_realm}"

        self.token_endpoint = os.getenv("KEYCLOAK_AAUTH_TOKEN_ENDPOINT")
        self.interaction_endpoint = os.getenv("KEYCLOAK_AAUTH_INTERACTION_ENDPOINT")
        self.jwks_uri: Optional[str] = None
        self.cache_ttl = int(os.getenv("AAUTH_AUTH_TOKEN_CACHE_TTL", "3600"))
        self.default_wait_seconds = int(os.getenv("AAUTH_PREFER_WAIT_SECONDS", "45"))

        self.private_key, self.public_key, self.public_jwk = get_signing_keypair()
        self.signature_scheme = os.getenv("AAUTH_SIGNATURE_SCHEME", "hwk").lower()
        if self.signature_scheme not in ["hwk", "jwks_uri"]:
            self.signature_scheme = "hwk"

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
                    if DEBUG:
                        logger.debug("AAuth metadata fetch failed for %s: %s", url, e)
        raise ValueError(
            f"AAuth issuer metadata not found for {issuer_url} (tried {paths})"
        ) from last_exc

    async def _get_endpoints(self, issuer_url: Optional[str] = None) -> tuple[str, str]:
        """Resolve token and interaction endpoints. Optional issuer_url overrides default (e.g. from 401 challenge)."""
        base = (issuer_url or self.issuer_url).rstrip("/")
        default_base = self.issuer_url.rstrip("/")
        use_env = issuer_url is None or base == default_base

        if use_env and self.token_endpoint and self.interaction_endpoint:
            return self.token_endpoint, self.interaction_endpoint

        metadata = await self._fetch_metadata_for_issuer(base)
        self.jwks_uri = metadata.get("jwks_uri") or self.jwks_uri

        if use_env:
            token_ep = self.token_endpoint or metadata.get("token_endpoint")
            interaction_ep = self.interaction_endpoint or metadata.get("interaction_endpoint")
            if token_ep:
                self.token_endpoint = self.token_endpoint or token_ep
            if interaction_ep:
                self.interaction_endpoint = self.interaction_endpoint or interaction_ep
        else:
            token_ep = metadata.get("token_endpoint")
            interaction_ep = metadata.get("interaction_endpoint")

        if not token_ep:
            raise ValueError("AAuth metadata missing token_endpoint (or agent_token_endpoint)")
        if not interaction_ep:
            raise ValueError("AAuth metadata missing interaction_endpoint (or agent_auth_endpoint)")
        return token_ep, interaction_ep

    async def _sign_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes] = None,
    ) -> Dict[str, str]:
        from aauth import sign_request

        sign_kwargs: Dict[str, str] = {}
        if self.signature_scheme == "jwks_uri":
            agent_id = os.getenv("BACKEND_AGENT_URL", f"http://{settings.host}:{settings.port}")
            kid = self.public_jwk.get("kid", "backend-key-1")
            sign_kwargs = {"id": agent_id, "kid": kid}

        return sign_request(
            method=method,
            target_uri=url,
            headers=headers,
            body=None,
            private_key=self.private_key,
            sig_scheme=self.signature_scheme,
            **sign_kwargs,
        )

    def _json_headers(self, body_bytes: bytes, wait_seconds: Optional[int] = None) -> Dict[str, str]:
        digest = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body_bytes)),
            "Content-Digest": f"sha-256=:{digest}:",
        }
        if wait_seconds is not None:
            headers["Prefer"] = f"wait={wait_seconds}"
        return headers

    async def _send_signed_json(
        self,
        method: str,
        url: str,
        payload: Optional[Dict[str, Any]] = None,
        wait_seconds: Optional[int] = None,
    ) -> httpx.Response:
        body_bytes = json.dumps(payload or {}, separators=(",", ":")).encode("utf-8") if payload is not None else b""
        if payload is not None:
            headers = self._json_headers(body_bytes, wait_seconds)
        else:
            headers = {"Prefer": f"wait={wait_seconds}"} if wait_seconds is not None else {}
        sig_headers = await self._sign_request(method, url, headers, body_bytes)
        headers.update(sig_headers)

        timeout = max(60.0, (wait_seconds or 0) + 15.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            request = client.build_request(method, url, headers=headers, content=body_bytes if payload is not None else None)
            return await client.send(request)

    def _parse_pending_response(self, response: httpx.Response, interaction_endpoint: str) -> Dict[str, Any]:
        body = response.json() if response.content else {}
        location = response.headers.get("Location") or body.get("location")
        if not location:
            raise ValueError("Pending response missing Location header")

        retry_after = int(response.headers.get("Retry-After", "0"))
        aauth_header = response.headers.get("AAuth", "")
        parsed_header = parse_aauth_header(aauth_header) if aauth_header else None
        require = body.get("require") or (parsed_header.require if parsed_header else None)
        code = body.get("code") or (parsed_header.code if parsed_header else None)

        result = {
            "status": "approval_pending" if require == "approval" else "interaction_required",
            "pending_url": location,
            "retry_after": retry_after,
            "interaction_endpoint": interaction_endpoint,
            "require": require,
        }
        if code:
            result["interaction_code"] = code
        clarification = body.get("clarification")
        if clarification:
            result["clarification"] = clarification
        return result

    async def request_auth_token(
        self,
        resource_token: str,
        purpose: Optional[str] = None,
        wait_seconds: Optional[int] = None,
        auth_server_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        with span("aauth_token_service.request_auth_token", {"has_resource_token": bool(resource_token)}):
            issuer_override = auth_server_url.rstrip("/") if auth_server_url else None
            token_endpoint, interaction_endpoint = await self._get_endpoints(issuer_override)
            payload: Dict[str, Any] = {"resource_token": resource_token}
            if purpose:
                payload["purpose"] = purpose

            response = await self._send_signed_json(
                "POST",
                token_endpoint,
                payload=payload,
                wait_seconds=wait_seconds or self.default_wait_seconds,
            )

            if response.status_code == 200:
                result = response.json()
                auth_token = result.get("auth_token")
                if not auth_token:
                    raise ValueError("Auth server 200 response missing auth_token")
                token_logger.info("🔐 Received auth_token from auth server")
                return {
                    "status": "success",
                    "auth_token": auth_token,
                    "expires_in": result.get("expires_in", 3600),
                }

            if response.status_code == 202:
                return self._parse_pending_response(response, interaction_endpoint)

            try:
                error_body = response.json()
            except Exception:
                error_body = {"error": response.text[:200]}
            raise ValueError(f"AAuth token request failed: {response.status_code} {error_body}")

    async def poll_for_auth_token(
        self,
        pending_url: str,
        wait_seconds: Optional[int] = None,
        max_attempts: int = 120,
        min_poll_interval: float = 3.0,
    ) -> Dict[str, Any]:
        """Poll a pending URL until an auth_token is delivered or a terminal status is reached.

        Args:
            min_poll_interval: Floor in seconds between poll GETs when Retry-After is 0
                               or the server does not honour Prefer: wait (default 3s).
        """
        with span("aauth_token_service.poll_for_auth_token", {"pending_url": pending_url}):
            _, interaction_endpoint = await self._get_endpoints()
            ws = wait_seconds or self.default_wait_seconds
            token_logger.info(
                "AAuth poll started: pending_url=%s max_attempts=%s Prefer_wait=%s min_interval=%s",
                pending_url,
                max_attempts,
                ws,
                min_poll_interval,
            )
            attempts = 0
            next_url = pending_url
            while attempts < max_attempts:
                attempts += 1
                token_logger.info(
                    "AAuth poll GET attempt %s/%s url=%s",
                    attempts,
                    max_attempts,
                    next_url,
                )
                response = await self._send_signed_json(
                    "GET",
                    next_url,
                    payload=None,
                    wait_seconds=ws,
                )
                token_logger.info(
                    "AAuth poll response: status=%s attempt=%s/%s",
                    response.status_code,
                    attempts,
                    max_attempts,
                )

                if response.status_code == 200:
                    result = response.json()
                    auth_token = result.get("auth_token")
                    if not auth_token:
                        raise ValueError("Pending auth success response missing auth_token")
                    exp = result.get("expires_in", 3600)
                    token_logger.info(
                        "AAuth poll complete: auth_token received expires_in=%s",
                        exp,
                    )
                    return {
                        "status": "success",
                        "auth_token": auth_token,
                        "expires_in": exp,
                    }

                if response.status_code == 202:
                    body = response.json() if response.content else {}
                    pending_status = body.get("status")
                    require = body.get("require")
                    retry_after = int(response.headers.get("Retry-After", "0"))
                    clarification_question = body.get("clarification")
                    is_awaiting = pending_status == "awaiting_clarification"
                    token_logger.info(
                        "AAuth poll 202: body_status=%s require=%s retry_after=%s "
                        "clarification=%s is_awaiting=%s",
                        pending_status,
                        require,
                        retry_after,
                        bool(clarification_question),
                        is_awaiting,
                    )
                    if is_awaiting or clarification_question:
                        token_logger.info(
                            "AAuth poll 202 full body: %s", json.dumps(body)[:500]
                        )
                        token_logger.info(
                            "AAuth poll 202 response headers: %s",
                            dict(response.headers),
                        )

                    if is_awaiting and clarification_question:
                        post_url = body.get("location") or next_url
                        token_logger.info(
                            "Clarification question from user: %s", clarification_question
                        )
                        token_logger.info(
                            "AAuth poll POST clarification_response url=%s (next_url was %s)",
                            post_url,
                            next_url,
                        )
                        post_resp = await self._send_signed_json(
                            "POST",
                            post_url,
                            payload={"clarification_response": AAUTH_CLARIFICATION_DEMO_RESPONSE},
                        )
                        token_logger.info(
                            "Clarification POST result: status=%s body=%s",
                            post_resp.status_code,
                            post_resp.text[:500],
                        )
                        if post_resp.status_code in (200, 204):
                            token_logger.info("Clarification response accepted, resuming poll")
                        else:
                            token_logger.warning(
                                "Clarification POST unexpected status: %s — will retry once after 2s",
                                post_resp.status_code,
                            )
                            await asyncio.sleep(2)
                            post_resp2 = await self._send_signed_json(
                                "POST",
                                post_url,
                                payload={"clarification_response": AAUTH_CLARIFICATION_DEMO_RESPONSE},
                            )
                            token_logger.info(
                                "Clarification POST retry result: status=%s body=%s",
                                post_resp2.status_code,
                                post_resp2.text[:500],
                            )
                        next_url = post_url
                        continue
                    elif clarification_question and not is_awaiting:
                        token_logger.warning(
                            "Clarification field present but status=%s (not awaiting_clarification) — skipping POST",
                            pending_status,
                        )

                    pending_result = self._parse_pending_response(response, interaction_endpoint)
                    next_url = pending_result["pending_url"]
                    sleep_s = max(pending_result.get("retry_after", 0), min_poll_interval)
                    token_logger.info("AAuth poll sleeping %ss before next GET", sleep_s)
                    await asyncio.sleep(sleep_s)
                    continue

                if response.status_code == 503:
                    ra = int(response.headers.get("Retry-After", "1"))
                    token_logger.warning(
                        "AAuth poll 503 unavailable, sleeping %ss (attempt %s/%s)",
                        ra,
                        attempts,
                        max_attempts,
                    )
                    await asyncio.sleep(ra)
                    continue

                try:
                    error_body = response.json()
                except Exception:
                    error_body = {"error": response.text[:200]}
                raise ValueError(f"Pending auth polling failed: {response.status_code} {error_body}")

            token_logger.error(
                "AAuth poll timed out after %s attempts (pending_url=%s)",
                max_attempts,
                pending_url,
            )
            raise TimeoutError("Timed out waiting for auth token")

    async def refresh_auth_token(self, auth_token: str) -> Dict[str, Any]:
        token_endpoint, _ = await self._get_endpoints()
        response = await self._send_signed_json(
            "POST",
            token_endpoint,
            payload={"auth_token": auth_token},
            wait_seconds=self.default_wait_seconds,
        )
        if response.status_code != 200:
            raise ValueError(f"Failed to refresh auth token: {response.status_code} {response.text[:200]}")
        result = response.json()
        if not result.get("auth_token"):
            raise ValueError("Refresh response missing auth_token")
        return {
            "status": "success",
            "auth_token": result["auth_token"],
            "expires_in": result.get("expires_in", 3600),
        }

    def _get_cache_key(self, agent_id: str, scope: str) -> str:
        return f"{agent_id}:{scope}"

    def _is_token_expired(self, expires_at: float) -> bool:
        return time.time() >= expires_at

    async def get_cached_token(self, agent_id: str, scope: str) -> Optional[str]:
        cache_key = self._get_cache_key(agent_id, scope)
        cached = _token_cache.get(cache_key)
        if not cached:
            return None

        expires_at = cached.get("expires_at", 0)
        auth_token = cached.get("auth_token")
        if not auth_token:
            return None
        if not self._is_token_expired(expires_at):
            return auth_token
        return None

    def cache_token(self, agent_id: str, scope: str, auth_token: str, expires_in: int) -> None:
        _token_cache[self._get_cache_key(agent_id, scope)] = {
            "auth_token": auth_token,
            "expires_at": time.time() + expires_in - 60,
            "expires_in": expires_in,
        }


aauth_token_service = AAuthTokenService()
