"""Obtain and refresh aa-agent+jwt from an Agent Server (stable + ephemeral keys)."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from typing import Any
from urllib.parse import urljoin

import httpx
import jwt as pyjwt

import aauth
from app.config import settings
from app.services.stable_identity import load_or_create_stable_identity

logger = logging.getLogger(__name__)

REFRESH_LEEWAY_SECONDS = 120
DELEGATION_JWT_TTL_SECONDS = 300
HTTP_TIMEOUT = httpx.Timeout(60.0)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_jkt_jwt(
    stable_priv: Any,
    stable_pub_jwk: dict[str, Any],
    new_eph_pub_jwk: dict[str, Any],
    ttl: int = DELEGATION_JWT_TTL_SECONDS,
) -> str:
    """Short-lived delegation JWT: stable key signs, cnf.jwk is new ephemeral public key."""
    stable_jkt = f"urn:jkt:sha-256:{aauth.calculate_jwk_thumbprint(stable_pub_jwk)}"
    now = int(time.time())
    header = {
        "alg": "EdDSA",
        "typ": "jkt-s256+jwt",
        "jwk": stable_pub_jwk,
    }
    payload = {
        "iss": stable_jkt,
        "iat": now,
        "exp": now + ttl,
        "cnf": {"jwk": new_eph_pub_jwk},
    }
    header_enc = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_enc = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_enc}.{payload_enc}".encode()
    sig = stable_priv.sign(signing_input)
    return f"{header_enc}.{payload_enc}.{_b64url(sig)}"


def _merge_sign_headers(
    method: str,
    target_uri: str,
    body: bytes | None,
    ephemeral_priv: Any,
    sig_scheme: str = "hwk",
    **kwargs: Any,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    sig = aauth.sign_request(
        method=method,
        target_uri=target_uri,
        headers=headers,
        body=body,
        private_key=ephemeral_priv,
        sig_scheme=sig_scheme,
        **kwargs,
    )
    return {**headers, **sig}


def _parse_retry_after(headers: httpx.Headers) -> float:
    raw = headers.get("retry-after")
    if not raw:
        return 1.0
    try:
        return float(raw)
    except ValueError:
        return 1.0


class AgentTokenService:
    """Registers with Agent Server, polls if needed, refreshes token, exposes signing material."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._stable_priv: Any = None
        self._stable_pub_jwk: dict[str, Any] | None = None
        self._eph_priv: Any = None
        self._eph_pub_jwk: dict[str, Any] | None = None
        self._agent_token: str | None = None
        self._token_exp: float = 0.0
        self._issuer: str | None = None
        self._registration_url: str | None = None
        self._refresh_url: str | None = None
        self._meta: dict[str, Any] = {}

    async def startup(self) -> None:
        self._stable_priv, _stable_pub, self._stable_pub_jwk = load_or_create_stable_identity(
            settings.stable_identity_dir
        )

        self._eph_priv, _eph_pub = aauth.generate_ed25519_keypair()
        self._eph_pub_jwk = aauth.public_key_to_jwk(_eph_pub)
        logger.info(
            "Ephemeral signing key (startup): %s",
            json.dumps(self._eph_pub_jwk, separators=(",", ":")),
        )

        base = settings.agent_server_base.rstrip("/")
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            await self._discover(client, base)
            await self._register_or_poll(client, base)

        logger.info("Agent Server registration complete; agent token acquired")

    async def _discover(self, client: httpx.AsyncClient, base: str) -> None:
        wh_url = f"{base}/.well-known/aauth-agent.json"
        r = await client.get(wh_url)
        r.raise_for_status()
        self._meta = r.json()
        self._issuer = self._meta.get("issuer")
        if not self._issuer:
            raise RuntimeError("Agent Server metadata missing issuer")
        self._registration_url = self._meta.get("registration_endpoint", f"{base}/register")
        self._refresh_url = self._meta.get("refresh_endpoint", f"{base}/refresh")
        logger.info(
            "Agent Server discovery OK: issuer=%s register=%s refresh=%s",
            self._issuer,
            self._registration_url,
            self._refresh_url,
        )

    async def _register_or_poll(self, client: httpx.AsyncClient, base: str) -> None:
        assert self._stable_pub_jwk is not None and self._eph_priv is not None
        body_obj = {
            "stable_pub": self._stable_pub_jwk,
            "agent_name": settings.agent_name,
        }
        body_bytes = json.dumps(body_obj).encode()
        hdrs = _merge_sign_headers(
            "POST",
            self._registration_url,
            body_bytes,
            self._eph_priv,
            sig_scheme="hwk",
        )
        r = await client.post(self._registration_url, headers=hdrs, content=body_bytes)

        if r.status_code == 200:
            data = r.json()
            self._set_agent_token(data["agent_token"])
            return

        if r.status_code != 202:
            raise RuntimeError(
                f"POST /register failed HTTP {r.status_code}: {r.text[:800]}"
            )

        loc = r.headers.get("location")
        if not loc:
            raise RuntimeError("202 from register but no Location header")
        poll_url = loc if loc.startswith("http") else urljoin(f"{base}/", loc.lstrip("/"))

        while True:
            wait = _parse_retry_after(r.headers)
            await asyncio.sleep(wait)
            poll_hdrs = _merge_sign_headers("GET", poll_url, None, self._eph_priv, sig_scheme="hwk")
            r = await client.get(poll_url, headers=poll_hdrs)
            if r.status_code == 200:
                data = r.json()
                self._set_agent_token(data["agent_token"])
                return
            if r.status_code == 202:
                continue
            if r.status_code in (401, 403, 404, 410):
                raise RuntimeError(
                    f"Registration poll failed HTTP {r.status_code}: {r.text[:800]}"
                )
            raise RuntimeError(
                f"Unexpected poll status {r.status_code}: {r.text[:800]}"
            )

    def _set_agent_token(self, token: str) -> None:
        self._agent_token = token
        claims = pyjwt.decode(token, options={"verify_signature": False})
        if claims.get("iss") != self._issuer:
            logger.warning(
                "agent_token iss %r differs from discovery issuer %r",
                claims.get("iss"),
                self._issuer,
            )
        exp = claims.get("exp")
        if exp is None:
            raise RuntimeError("agent_token missing exp")
        self._token_exp = float(exp)
        cnf = claims.get("cnf") or {}
        jwk = cnf.get("jwk") or {}
        if self._eph_pub_jwk and jwk.get("x") != self._eph_pub_jwk.get("x"):
            raise RuntimeError("agent_token cnf.jwk does not match current ephemeral key")
        logger.info(
            "Agent token updated, exp in %.0fs",
            self._token_exp - time.time(),
        )

    async def ensure_valid_token(self) -> None:
        async with self._lock:
            if self._agent_token is None:
                raise RuntimeError("Agent token not initialized; call startup() first")
            if time.time() < self._token_exp - REFRESH_LEEWAY_SECONDS:
                return
            await self._refresh_locked()

    async def _refresh_locked(self) -> None:
        assert self._stable_priv is not None and self._stable_pub_jwk is not None
        new_eph_priv, new_eph_pub = aauth.generate_ed25519_keypair()
        new_eph_pub_jwk = aauth.public_key_to_jwk(new_eph_pub)
        jkt_jwt = build_jkt_jwt(self._stable_priv, self._stable_pub_jwk, new_eph_pub_jwk)
        hdrs = _merge_sign_headers(
            "POST",
            self._refresh_url,
            None,
            new_eph_priv,
            sig_scheme="jkt-jwt",
            jwt=jkt_jwt,
        )
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.post(self._refresh_url, headers=hdrs)
        if r.status_code != 200:
            raise RuntimeError(
                f"POST /refresh failed HTTP {r.status_code}: {r.text[:800]}"
            )
        data = r.json()
        self._eph_priv = new_eph_priv
        self._eph_pub_jwk = new_eph_pub_jwk
        logger.info(
            "Ephemeral signing key (after refresh): %s",
            json.dumps(self._eph_pub_jwk, separators=(",", ":")),
        )
        self._set_agent_token(data["agent_token"])

    def get_http_signing_private_key_and_token(self) -> tuple[Any, str]:
        if self._eph_priv is None or self._agent_token is None:
            raise RuntimeError("Agent token service not ready")
        return self._eph_priv, self._agent_token


agent_token_service = AgentTokenService()
