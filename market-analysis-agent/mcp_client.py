"""
MCP Client for Market Analysis Agent

Uses the official Model Context Protocol Python SDK. Outbound HTTP to the MCP
server is signed with AAuth ``sig_scheme=jwt`` (aa-agent+jwt) via an httpx
request hook; see :mod:`agent_token_service`.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

import httpx
from aauth import sign_request
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared._httpx_utils import McpHttpClientFactory

# Load environment variables
load_dotenv()

if TYPE_CHECKING:
    from agent_token_service import AgentTokenService

logger = logging.getLogger(__name__)


def _normalize_request_target_uri(request: httpx.Request) -> str:
    u = urlparse(str(request.url))
    path = u.path if u.path else "/"
    return urlunparse((u.scheme, u.netloc, path, u.params, u.query, u.fragment))


def _headers_for_signing_from_request(request: httpx.Request) -> dict[str, str]:
    h: dict[str, str] = {}
    for k, v in request.headers.items():
        kl = k.lower()
        if kl in (
            "content-digest",
            "signature",
            "signature-input",
            "signature-key",
        ):
            continue
        h[k] = v
    return h


def create_httpx_client_factory_with_aauth(
    token_svc: "AgentTokenService",
) -> McpHttpClientFactory:
    """MCP httpx client factory: signs every request with agent JWT (same as backend/supply-chain A2A)."""

    async def aauth_mcp_request_hook(request: httpx.Request) -> None:
        await token_svc.ensure_valid_token()
        priv, agent_jwt = token_svc.get_http_signing_private_key_and_token()
        method = (request.method or "GET").upper()
        target_uri = _normalize_request_target_uri(request)
        hop = _headers_for_signing_from_request(request)
        sig = sign_request(
            method=method,
            target_uri=target_uri,
            headers=hop,
            body=None,
            private_key=priv,
            sig_scheme="jwt",
            jwt=agent_jwt,
        )
        for k, v in sig.items():
            request.headers[k] = v
        logger.debug("AAuth: signed MCP %s %s (jwt in Signature-Key)", method, target_uri)

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {
            "follow_redirects": True,
            "event_hooks": {"request": [aauth_mcp_request_hook]},
        }
        if timeout is None:
            kwargs["timeout"] = httpx.Timeout(30.0)
        else:
            kwargs["timeout"] = timeout
        if headers is not None:
            kwargs["headers"] = headers
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)

    return factory


def validate_mcp_url(base_url: str, path: str) -> bool:
    """Validate that the MCP server URL is properly formatted."""
    try:
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        parsed = urlparse(base_url)
        if not parsed.netloc:
            return False

        if not path.startswith("/"):
            path = f"/{path}"

        return True
    except Exception:
        return False


class MCPClient:
    """Client for communicating with MCP servers using the official SDK + AAuth agent JWT."""

    def __init__(
        self,
        base_url: str | None = None,
        mcp_path: str | None = None,
        connection_timeout: int | None = None,
        read_timeout: int | None = None,
        token_svc: Optional["AgentTokenService"] = None,
    ):
        self.base_url = base_url or os.getenv("MCP_SERVER_BASE_URL", "http://localhost:3000")
        self.mcp_path = mcp_path or os.getenv("MCP_SERVER_PATH", "/general/mcp")
        self.connection_timeout = connection_timeout or int(
            os.getenv("MCP_CONNECTION_TIMEOUT", "30")
        )
        self.read_timeout = read_timeout or int(os.getenv("MCP_READ_TIMEOUT", "60"))
        if token_svc is not None:
            self._token_svc: Optional[AgentTokenService] = token_svc
        else:
            from agent_token_service import agent_token_service as _default

            self._token_svc = _default
        if not validate_mcp_url(self.base_url, self.mcp_path):
            logger.warning("Invalid MCP server URL configuration: %s%s", self.base_url, self.mcp_path)

        logger.info("MCP Client: server %s%s (AAuth agent JWT for outbound)", self.base_url, self.mcp_path)
        logger.info(
            "MCP Client timeouts: connection=%ss read=%ss",
            self.connection_timeout,
            self.read_timeout,
        )

    def get_config(self) -> Dict[str, Any]:
        """Get the current MCP client configuration."""
        return {
            "base_url": self.base_url,
            "mcp_path": self.mcp_path,
            "full_url": f"{self.base_url}{self.mcp_path}",
            "connection_timeout": self.connection_timeout,
            "read_timeout": self.read_timeout,
            "aauth_mcp": True,
        }

    async def __aenter__(self) -> "MCPClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    async def discover_tools(self) -> List[Dict[str, Any]]:
        """
        Discover available tools from the MCP server.
        All Streamable HTTP requests are signed with the Agent Server token (httpx hook).
        """
        try:
            factory = create_httpx_client_factory_with_aauth(self._token_svc)
            async with streamablehttp_client(
                f"{self.base_url}{self.mcp_path}",
                headers=None,
                timeout=float(self.connection_timeout),
                sse_read_timeout=float(self.read_timeout),
                httpx_client_factory=factory,
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools_response = await session.list_tools()
                    tools = []
                    for tool in tools_response.tools:
                        tool_info = {
                            "name": tool.name,
                            "description": tool.description or "No description available",
                            "type": "tool",
                        }
                        if hasattr(tool, "title") and tool.title:
                            tool_info["display_name"] = tool.title
                        if hasattr(tool, "annotations") and tool.annotations:
                            tool_info["annotations"] = tool.annotations
                        tools.append(tool_info)
                    return tools
        except Exception as e:
            logger.error("Failed to connect to MCP server: %s", e)
            raise Exception("Could not connect to MCP servers") from e
