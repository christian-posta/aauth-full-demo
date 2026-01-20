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
from typing import Dict, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Configure logging
logger = logging.getLogger(__name__)

# Check DEBUG mode from environment
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# Context variable to store HTTP headers for the current request
# This allows the AgentExecutor to access headers even though they're not
# directly passed through the A2A SDK's RequestContext
_http_headers: ContextVar[Optional[Dict[str, str]]] = ContextVar('http_headers', default=None)


def get_current_request_headers() -> Optional[Dict[str, str]]:
    """Get the HTTP headers for the current request.
    
    Returns:
        Dictionary of HTTP headers, or None if not in a request context.
    """
    return _http_headers.get()


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
        
        # Log captured headers for debugging (only in DEBUG mode)
        if DEBUG:
            logger.debug(f"🔍 HTTPHeadersCaptureMiddleware: Captured {len(headers)} headers")
        
        # Log AAuth-specific headers if present
        aauth_headers = {k: v for k, v in headers.items() 
                        if k.lower() in ['signature-input', 'signature', 'signature-key']}
        if aauth_headers:
            logger.info(f"🔐 AAuth headers received: {list(aauth_headers.keys())}")
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
        
        # Store headers in context variable
        token = _http_headers.set(headers)
        
        try:
            # Process the request
            response = await call_next(request)
            return response
        finally:
            # Reset the context variable after the request is processed
            _http_headers.reset(token)

