#!/usr/bin/env python3
"""HTTP Headers Middleware for A2A Server.

This middleware captures HTTP headers from incoming requests and stores them
in a context variable so they can be accessed by the AgentExecutor.

This is necessary because the A2A SDK's RequestContext doesn't expose raw HTTP
headers by default, but we need them for AAuth signature verification and
trace context propagation.
"""

import logging
import os
from contextvars import ContextVar
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, urlunparse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Configure logging
logger = logging.getLogger(__name__)

# Check DEBUG mode from environment
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# Derive canonical authority from MARKET_ANALYSIS_AGENT_ID_URL
# Per AAuth SPEC Section 10.3.1, receivers MUST use configured canonical authority
# not derived from request headers. The canonical authority consists of:
# - The host (DNS name or IP address)
# - The port, if non-default for the scheme (80 for HTTP, 443 for HTTPS)
# We derive this from MARKET_ANALYSIS_AGENT_ID_URL which is exposed in JWKS metadata
_canonical_authority_url = os.getenv("MARKET_ANALYSIS_AGENT_ID_URL")
if not _canonical_authority_url:
    # Fallback to MARKET_ANALYSIS_AGENT_URL if ID_URL not set
    _canonical_authority_url = os.getenv("MARKET_ANALYSIS_AGENT_URL", "http://localhost:9998/")

_canonical_parsed = urlparse(_canonical_authority_url)
CANONICAL_SCHEME = _canonical_parsed.scheme or "http"
_canonical_host = _canonical_parsed.hostname or _canonical_parsed.netloc.split(':')[0]
_canonical_port = _canonical_parsed.port

# Format canonical authority: host:port if port is non-default, otherwise just host
# Per SPEC 10.3.1: port only included if non-default for the scheme
if _canonical_port:
    if (CANONICAL_SCHEME == "http" and _canonical_port != 80) or \
       (CANONICAL_SCHEME == "https" and _canonical_port != 443):
        CANONICAL_AUTHORITY = f"{_canonical_host}:{_canonical_port}"
    else:
        CANONICAL_AUTHORITY = _canonical_host
else:
    # No port specified, use default for scheme
    CANONICAL_AUTHORITY = _canonical_host

# Context variable to store HTTP headers for the current request
# This allows the AgentExecutor to access headers even though they're not
# directly passed through the A2A SDK's RequestContext
_http_headers: ContextVar[Optional[Dict[str, str]]] = ContextVar('http_headers', default=None)

# Context variable to store HTTP request metadata (method, URI, body)
# Needed for AAuth signature verification
# URI is reconstructed using canonical authority + request path/query per SPEC 10.3.1
_http_request_info: ContextVar[Optional[Tuple[str, str, Optional[bytes]]]] = ContextVar('http_request_info', default=None)


def get_current_request_headers() -> Optional[Dict[str, str]]:
    """Get the HTTP headers for the current request.
    
    Returns:
        Dictionary of HTTP headers, or None if not in a request context.
    """
    return _http_headers.get()


def get_current_request_info() -> Optional[Tuple[str, str, Optional[bytes]]]:
    """Get the HTTP request info (method, URI, body) for the current request.
    
    Returns:
        Tuple of (method, uri, body_bytes), or None if not in a request context.
        body_bytes may be None if there's no body.
    """
    return _http_request_info.get()


class HTTPHeadersCaptureMiddleware(BaseHTTPMiddleware):
    """Middleware that captures HTTP headers and makes them available via context variable.
    
    This middleware intercepts all incoming HTTP requests, extracts the headers,
    and stores them in a context variable. The AgentExecutor can then retrieve
    these headers using get_current_request_headers().
    
    This is particularly important for:
    - AAuth signature headers (Signature-Input, Signature, Signature-Key)
    - OpenTelemetry trace context (traceparent, tracestate)
    - Authorization headers
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Extract all headers from the request
        headers = dict(request.headers)
        
        # Extract request method
        method = request.method
        
        # Reconstruct URI using canonical authority + request path/query
        # Per AAuth SPEC Section 10.3.1: receiver MUST use configured canonical authority
        # but path and query come from the actual request
        request_path = request.url.path or "/"
        request_query = request.url.query if request.url.query else ""
        
        # Reconstruct URI: scheme + canonical_authority + path + query
        # This matches what the signer used (agent_card.url + path)
        uri = urlunparse((
            CANONICAL_SCHEME,
            CANONICAL_AUTHORITY,
            request_path,
            "",  # params
            request_query,
            ""   # fragment
        ))
        
        # Read request body if present
        # Note: Reading the body consumes it, so we need to recreate it for downstream handlers
        body_bytes = None
        if request.method in ("POST", "PUT", "PATCH"):
            body_bytes = await request.body()
            # Recreate the request receive function so downstream handlers can read the body
            # We wrap the original receive function to return the cached body
            original_receive = request._receive
            body_sent = False
            async def receive():
                nonlocal body_sent
                if not body_sent:
                    body_sent = True
                    return {"type": "http.request", "body": body_bytes}
                else:
                    # Return empty body for subsequent reads
                    return {"type": "http.request", "body": b""}
            request._receive = receive
        
        # Log captured headers for debugging (only in DEBUG mode)
        if DEBUG:
            logger.debug(f"🔍 HTTPHeadersCaptureMiddleware: Captured {len(headers)} headers")
            logger.debug(f"🔍 Request: {method} {uri}")
            logger.debug(f"🔍 Canonical authority: {CANONICAL_AUTHORITY} (derived from MARKET_ANALYSIS_AGENT_ID_URL)")
            logger.debug(f"🔍 Request path: {request_path}, query: {request_query}")
            if body_bytes:
                logger.debug(f"🔍 Body length: {len(body_bytes)} bytes")
        
        # Log AAuth-specific headers if present (and reconstructed URI for verification debugging)
        aauth_headers = {k: v for k, v in headers.items() 
                        if k.lower() in ['signature-input', 'signature', 'signature-key']}
        if aauth_headers:
            logger.info(f"🔐 AAuth headers received: {list(aauth_headers.keys())}")
            logger.info(f"🔐 Reconstructed URI for verification: {method} {uri}")
            if DEBUG:
                for name, value in aauth_headers.items():
                    display_value = value if len(value) <= 80 else f"{value[:80]}..."
                    logger.debug(f"🔐   {name}: {display_value}")
        
        # Log trace headers if present (only in DEBUG mode)
        if DEBUG:
            trace_headers = {k: v for k, v in headers.items() 
                            if k.lower() in ['traceparent', 'tracestate']}
            if trace_headers:
                logger.debug(f"🔗 Trace headers: {trace_headers}")
        
        # Store headers and request info in context variables
        headers_token = _http_headers.set(headers)
        request_info_token = _http_request_info.set((method, uri, body_bytes))
        
        try:
            # Process the request
            response = await call_next(request)
            return response
        finally:
            # Reset the context variables after the request is processed
            _http_headers.reset(headers_token)
            _http_request_info.reset(request_info_token)

