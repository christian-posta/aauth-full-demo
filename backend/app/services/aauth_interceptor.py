#!/usr/bin/env python3
"""AAuth signing interceptor for A2A client calls using Agent Server tokens."""

import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse, urlunparse

from a2a.client.middleware import ClientCallInterceptor, ClientCallContext
from aauth import sign_request

from app.config import settings
from app.services.agent_token_service import AgentTokenService
from app.tracing_config import inject_context_to_headers, add_event, set_attribute

logger = logging.getLogger(__name__)


class AAuthSigningInterceptor(ClientCallInterceptor):
    """Signs outbound A2A requests with ``sig=jwt`` (``aa-agent+jwt``) + ephemeral PoP."""

    def __init__(
        self,
        agent_token_service: AgentTokenService,
        trace_headers: Optional[Dict[str, str]] = None,
    ):
        self.trace_headers = trace_headers or {}
        self.agent_token_service = agent_token_service
        if settings.debug:
            logger.debug("🔐 AAuthSigningInterceptor initialized (agent JWT)")

    async def intercept(
        self,
        method_name: str,
        request_payload: dict[str, Any],
        http_kwargs: dict[str, Any],
        agent_card: Any | None,
        context: ClientCallContext | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if settings.debug:
            logger.debug("🔐 AAuthSigningInterceptor.intercept() called for %s", method_name)
            logger.debug(
                "🔍   request_payload keys: %s",
                list(request_payload.keys()) if request_payload else "None",
            )
            logger.debug("🔍   http_kwargs keys: %s", list(http_kwargs.keys()))
            if agent_card and hasattr(agent_card, "url"):
                logger.debug("🔍   agent_card.url: %s", agent_card.url)

        headers = http_kwargs.get("headers", {})

        if self.trace_headers:
            headers.update(self.trace_headers)

        headers = inject_context_to_headers(headers)

        url = http_kwargs.get("url", "")
        if settings.debug:
            logger.debug("🔍   http_kwargs.get('url'): %s", url)
        if not url and agent_card and hasattr(agent_card, "url"):
            url = agent_card.url
            if settings.debug:
                logger.debug("🔍   Using URL from agent_card: %s", url)

        original_url = url
        if url:
            parsed = urlparse(url)
            normalized_path = parsed.path if parsed.path else "/"
            url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    normalized_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )
            if original_url != url:
                logger.info("🔐 URL normalized for signing: %s -> %s", original_url, url)
            if settings.debug:
                logger.debug("🔍   Normalized URL path: %s", url)

        if settings.debug:
            logger.debug("🔍   Final URL used for signing: %s", url)
        else:
            logger.info("🔐 Signing request to: %s", url)

        method = http_kwargs.get("method", "POST").upper()

        body = None
        if "content" in http_kwargs:
            body = http_kwargs["content"]
            if isinstance(body, str):
                body = body.encode("utf-8")
        elif "data" in http_kwargs:
            body = http_kwargs["data"]
            if isinstance(body, str):
                body = body.encode("utf-8")
        elif "json" in http_kwargs:
            import json

            body = json.dumps(
                http_kwargs["json"], separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
            http_kwargs["content"] = body
            del http_kwargs["json"]
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
        elif request_payload:
            import json

            body = json.dumps(
                request_payload, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
            if "json" in http_kwargs:
                http_kwargs["content"] = body
                del http_kwargs["json"]
            else:
                http_kwargs["content"] = body
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
            if settings.debug:
                logger.debug("🔍   Using request_payload as body, length: %s", len(body))

        if url:
            try:
                await self.agent_token_service.ensure_valid_token()
                signing_priv, agent_jwt = (
                    self.agent_token_service.get_http_signing_private_key_and_token()
                )
                sig_scheme = "jwt"
                sign_kwargs = {"jwt": agent_jwt}
                logger.info("🔐 AAuth: Signing with agent token (aa-agent+jwt in Signature-Key)")

                if "Content-Digest" in headers or "content-digest" in headers:
                    headers.pop("Content-Digest", None)
                    headers.pop("content-digest", None)

                if settings.debug:
                    logger.debug(
                        "🔐 AAuth: Method: %s, Body length: %s",
                        method,
                        len(body) if body else 0,
                    )
                    parsed_url = urlparse(str(url))
                    logger.debug("🔐 SIGNING - Full URL: %s", url)
                    if body:
                        import base64
                        import hashlib

                        digest = hashlib.sha256(body).digest()
                        digest_b64 = base64.b64encode(digest).decode("ascii")
                        logger.debug(
                            "🔐   Expected Content-Digest: sha-256=:%s:", digest_b64
                        )

                target_uri = str(url)
                logger.info(
                    "🔐 SIGNING with: method=%s, target_uri=%r", method, target_uri
                )

                sig_headers = sign_request(
                    method=method,
                    target_uri=target_uri,
                    headers=headers,
                    body=None,
                    private_key=signing_priv,
                    sig_scheme=sig_scheme,
                    **sign_kwargs,
                )

                headers.update(sig_headers)

                add_event(
                    "aauth.request_signed",
                    {
                        "method": method,
                        "url": str(url),
                        "scheme": sig_scheme,
                        "has_body": body is not None,
                    },
                )
                set_attribute("aauth.signed", True)
                set_attribute("aauth.scheme", sig_scheme)

            except Exception as e:
                logger.error("❌ AAuth: Failed to sign request: %s", e)
                if settings.debug:
                    import traceback

                    logger.debug(traceback.format_exc())
                add_event("aauth.signing_failed", {"error": str(e)})
                set_attribute("aauth.signed", False)
        else:
            logger.warning("⚠️ AAuth: No URL available, skipping signing")
            add_event("aauth.signing_skipped", {"reason": "no_url"})

        http_kwargs["headers"] = headers

        add_event(
            "a2a_client.interceptor.headers_injected",
            {
                "method_name": method_name,
                "headers_count": len(headers),
                "trace_headers": list(self.trace_headers.keys()) if self.trace_headers else [],
                "has_aauth_signature": "Signature" in headers,
            },
        )

        set_attribute("a2a_client.interceptor.method", method_name)
        set_attribute("a2a_client.interceptor.headers_count", len(headers))
        set_attribute(
            "a2a_client.interceptor.has_aauth_signature", "Signature" in headers
        )

        if settings.debug:
            logger.debug("🔗 AAuth: Injected %s headers for %s", len(headers), method_name)
        return request_payload, http_kwargs
