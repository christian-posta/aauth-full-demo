import asyncio
import base64
import json
import uuid
import logging
from typing import AsyncGenerator, Dict, Any, List, Optional, Tuple
import httpx
from datetime import datetime
from aauth import sign_request as _aauth_sign_request, exchange_resource_token, extract_resource_token
from aauth.errors import TokenError, MetadataError

from a2a.client import ClientFactory, ClientConfig
from a2a.client.errors import A2AClientHTTPError
from a2a.types import TransportProtocol, Message, Role
from a2a.client.helpers import create_text_message_object
from a2a.client import minimal_agent_card

from app.config import settings
from app.models import OptimizationRequest, OptimizationProgress, OptimizationResults
from app.tracing_config import span, add_event, set_attribute, extract_context_from_headers
from app.services.aauth_interceptor import AAuthSigningInterceptor
from app.services.agent_token_service import agent_token_service

# Configure logging
logger = logging.getLogger(__name__)
token_logger = logging.getLogger("aauth.tokens")  # For token/challenge visibility - not suppressed


def _httpx_response_for_a2a_http_error(
    e: A2AClientHTTPError | httpx.HTTPStatusError,
) -> Optional[httpx.Response]:
    """A2A JSON-RPC wraps `HTTPStatusError` in `A2AClientHTTPError` with the cause chained."""
    if isinstance(e, A2AClientHTTPError) and e.__cause__ and isinstance(
        e.__cause__, httpx.HTTPStatusError
    ):
        return e.__cause__.response
    if isinstance(e, httpx.HTTPStatusError):
        return e.response
    return None


def _aauth_headers_from_response(response: httpx.Response) -> List[Tuple[str, str]]:
    return [
        (k, v) for k, v in response.headers.items() if "aauth" in k.lower()
    ]


def _jwt_claims_unverified(token: str) -> Dict[str, Any]:
    try:
        payload = token.split(".", 2)[1]
        padded = payload + "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        claims = json.loads(decoded)
        return claims if isinstance(claims, dict) else {}
    except Exception:
        return {}


def _log_auth_token_summary(auth_token: str) -> None:
    claims = _jwt_claims_unverified(auth_token)
    token_logger.info(
        "PS exchange returned auth_token: typ=%s iss=%s aud=%s agent=%s scope=%s exp=%s len=%d",
        claims.get("typ"),
        claims.get("iss"),
        claims.get("aud"),
        claims.get("agent"),
        claims.get("scope"),
        claims.get("exp"),
        len(auth_token),
    )


def _log_and_collect_aauth_401(
    e: A2AClientHTTPError | httpx.HTTPStatusError,
) -> Dict[str, Any]:
    """Log 401 AAuth / resource-token (SPEC §6) from response headers; return compact telemetry fields."""
    out: Dict[str, Any] = {
        "aauth_header_present": False,
        "resource_token_in_challenge": False,
        "resource_token_len": 0,
    }
    r = _httpx_response_for_a2a_http_error(e)
    if r is None:
        token_logger.info(
            "401: no httpx response on exception chain; cannot list AAuth headers (expected "
            "A2AClientHTTPError from JSON-RPC with chained HTTPStatusError)"
        )
        return out
    aauth = _aauth_headers_from_response(r)
    if not aauth:
        token_logger.info(
            "401: no AAuth / aauth response header. Header names: %s",
            list(r.headers.keys()),
        )
        if settings.debug and r.text:
            token_logger.debug("401 response body (debug): %s", r.text[:2000])
        return out
    out["aauth_header_present"] = True
    max_len = 20000 if settings.debug else 1200
    for k, v in aauth:
        vis = v if len(v) <= max_len else v[: max_len - 3] + "…"
        token_logger.info("401 AAuth / aauth | %s: %s", k, vis)
        logger.info("401 AAuth challenge header | %s: %s", k, vis)
    raw = extract_resource_token(r.headers)
    if raw:
        out["resource_token_in_challenge"] = True
        out["resource_token_len"] = len(raw)
        if len(raw) > 48:
            preview = f"{raw[:24]}…{raw[-16:]} (len={len(raw)})"
        else:
            preview = raw
        token_logger.info("401 parsed resource_token from AAuth: %s", preview)
        logger.info("401 resource_token (from challenge): %s", preview)
    return out




class A2AService:
    """Service for communicating with A2A supply-chain optimization agents"""
    
    def __init__(self):
        self.agent_url = settings.supply_chain_agent_url
        self.timeout = httpx.Timeout(
            connect=30.0,      # 30 seconds to establish connection
            read=60.0,         # 1 minute to read response
            write=30.0,        # 30 seconds to write request
            pool=30.0          # 30 seconds for connection pool
        )
    
    async def _create_client(self, trace_context: Any = None) -> tuple[Any, httpx.AsyncClient]:
        """Create A2A client and HTTP client with AAuth agent-token signing."""
        with span("a2a_service.create_client", {
            "agent_url": self.agent_url,
            "has_trace_context": trace_context is not None,
        }) as span_obj:
            
            if settings.debug:
                logger.debug(f"🔧 Creating A2A client for URL: {self.agent_url}")
                logger.debug(f"🔐 Using AAuth HTTP message signing")
            add_event("creating_a2a_client", {
                "agent_url": self.agent_url,
            })
            
            httpx_client = httpx.AsyncClient(
                timeout=self.timeout,
            )
            if settings.debug:
                logger.debug("✅ HTTPX client created")
            add_event("httpx_client_created")
            
            # Create client configuration
            config = ClientConfig(
                httpx_client=httpx_client,
                supported_transports=[TransportProtocol.jsonrpc],
                streaming=False
            )
            if settings.debug:
                logger.debug("✅ Client config created")
            add_event("client_config_created")
            
            # Create client factory
            factory = ClientFactory(config)
            if settings.debug:
                logger.debug("✅ Client factory created")
            add_event("client_factory_created")
            
            # Create agent card
            agent_card = minimal_agent_card(
                url=self.agent_url,
                transports=["JSONRPC"]
            )
            if settings.debug:
                logger.debug(f"✅ Agent card created: {agent_card}")
            add_event("agent_card_created", {"agent_url": self.agent_url})
            
            aauth_interceptor = AAuthSigningInterceptor(
                agent_token_service=agent_token_service
            )
            if settings.debug:
                logger.debug("🔐 AAuth signing interceptor created")
            add_event("aauth_interceptor_created")
            
            # Create client with AAuth signing interceptor
            client = factory.create(agent_card, interceptors=[aauth_interceptor])
            if settings.debug:
                logger.debug("✅ A2A client created with AAuth signing")
            add_event("a2a_client_created_with_aauth_signing")
            
            return client, httpx_client

    async def _create_client_with_auth(
        self, auth_token: str, trace_context: Any = None
    ) -> tuple[Any, httpx.AsyncClient]:
        """Create A2A client using an auth_token (aa-auth+jwt) in Signature-Key.

        Per AAuth spec §9.4.2 the auth token replaces the agent token in the
        Signature-Key header for subsequent signed requests.
        """
        httpx_client = httpx.AsyncClient(timeout=self.timeout)
        config = ClientConfig(
            httpx_client=httpx_client,
            supported_transports=[TransportProtocol.jsonrpc],
            streaming=False,
        )
        factory = ClientFactory(config)
        agent_card = minimal_agent_card(url=self.agent_url, transports=["JSONRPC"])
        interceptor = AAuthSigningInterceptor(
            agent_token_service=agent_token_service,
            auth_token=auth_token,
        )
        client = factory.create(agent_card, interceptors=[interceptor])
        return client, httpx_client

    async def optimize_supply_chain(
        self,
        request: OptimizationRequest,
        user_id: str,
        trace_context: Any = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Optimize supply chain using a single signed A2A call to the supply-chain agent."""
        
        with span("a2a_service.optimize_supply_chain", {
            "user_id": user_id,
            "request_type": request.effective_optimization_type,
            "has_trace_context": trace_context is not None,
        }, parent_context=trace_context) as span_obj:
            
            client, httpx_client = None, None
            
            try:
                if settings.debug:
                    logger.debug(f"🚀 Starting A2A optimization for user: {user_id}")
                    logger.debug(f"📝 Request: {request}")
                
                add_event("optimization_started", {
                    "user_id": user_id,
                    "request_type": request.effective_optimization_type
                })
                
                if settings.debug:
                    logger.debug("🔧 Creating A2A client...")
                client, httpx_client = await self._create_client(trace_context)
                if settings.debug:
                    logger.debug("✅ A2A client created successfully")
                add_event("a2a_client_created_successfully")
                
                # Create optimization message
                message_content = self._create_optimization_message(request)
                if settings.debug:
                    logger.debug(f"💬 Created message: {message_content}")
                    logger.debug(f"🔍 Custom prompt was: {request.custom_prompt}")
                    logger.debug(f"🔍 Final message length: {len(message_content)}")
                add_event("optimization_message_created", {
                    "message_length": len(message_content),
                    "custom_prompt": request.custom_prompt,
                    "final_message": message_content[:100] + "..." if len(message_content) > 100 else message_content
                })
                
                message = create_text_message_object(
                    role=Role.user, 
                    content=message_content
                )
                if settings.debug:
                    logger.debug(f"📤 Message object created: {message}")
                add_event("message_object_created")
                
                # Send message to agent and get response
                if settings.debug:
                    logger.debug(f"📡 Sending message to agent at: {self.agent_url}")
                add_event("sending_message_to_agent", {"agent_url": self.agent_url})
                
                response_content = None
                response_count = 0

                def _content_from_event(event: Any) -> None:
                    nonlocal response_content
                    if hasattr(event, "content") and event.content:
                        if isinstance(event.content, str):
                            response_content = event.content
                        elif isinstance(event.content, dict) and "content" in event.content:
                            response_content = event.content["content"]
                    elif hasattr(event, "text"):
                        response_content = event.text
                    elif hasattr(event, "parts") and event.parts:
                        for part in event.parts:
                            if hasattr(part, "root") and hasattr(part.root, "text"):
                                response_content = part.root.text
                                break

                try:
                    async for event in client.send_message(message):
                        response_count += 1
                        if settings.debug:
                            logger.debug(f"📨 Received event #{response_count}: {event}")
                        add_event("agent_response_received", {
                            "event_number": response_count,
                            "event_type": str(type(event))
                        })
                        _content_from_event(event)
                        break
                # JSON-RPC transport wraps httpx failures as A2AClientHTTPError (see
                # a2a.client.transports.jsonrpc.JsonRpcTransport._send_request), so a gateway
                # 401 is never an httpx.HTTPStatusError at this call site.
                except (A2AClientHTTPError, httpx.HTTPStatusError) as e:
                    if httpx_client:
                        try:
                            await httpx_client.aclose()
                        except Exception:
                            pass
                    if isinstance(e, A2AClientHTTPError):
                        status_code = e.status_code
                        err_detail = e.message
                    else:
                        status_code = e.response.status_code
                        err_detail = str(e.response.url)
                    if status_code == 401:
                        token_logger.info(
                            "401 from supply-chain-agent: configure policy on agentgateway or fix signatures (%s)",
                            err_detail,
                        )
                        logger.warning(
                            "A2A supply-chain HTTP 401 (agentgateway or signing): %s", err_detail
                        )
                        aauth_401 = _log_and_collect_aauth_401(e)
                        add_event("a2a_http_error", {"status_code": 401, **aauth_401})

                        # --- AAuth three-party (PS-managed) token exchange (spec §4.1.3) ---
                        # Extract response headers from wrapped exception
                        response_headers = None
                        if isinstance(e, A2AClientHTTPError) and e.__cause__ and isinstance(e.__cause__, httpx.HTTPStatusError):
                            response_headers = e.__cause__.response.headers
                        elif isinstance(e, httpx.HTTPStatusError):
                            response_headers = e.response.headers

                        resource_token = extract_resource_token(response_headers) if response_headers else None
                        if resource_token:
                            logger.info(
                                "401 has resource_token — attempting PS exchange (three-party mode)"
                            )
                            try:
                                await agent_token_service.ensure_valid_token()
                                signing_priv, agent_jwt = agent_token_service.get_http_signing_private_key_and_token()
                                auth_token = await exchange_resource_token(
                                    resource_token=resource_token,
                                    private_key=signing_priv,
                                    agent_jwt=agent_jwt,
                                )
                            except (TokenError, MetadataError) as exc:
                                token_logger.error("PS exchange failed: %s", exc)
                                auth_token = None

                            if auth_token:
                                _log_auth_token_summary(auth_token)
                                logger.info(
                                    "PS exchange succeeded; retrying with auth_token"
                                )
                                client2, httpx_client2 = None, None
                                try:
                                    client2, httpx_client2 = (
                                        await self._create_client_with_auth(
                                            auth_token, trace_context
                                        )
                                    )
                                    async for event in client2.send_message(message):
                                        response_count += 1
                                        _content_from_event(event)
                                        break
                                    await httpx_client2.aclose()
                                    if response_content:
                                        add_event(
                                            "agent_response_processed_after_auth_exchange",
                                            {"response_length": len(response_content)},
                                        )
                                        return {
                                            "type": "success",
                                            "agent_response": response_content,
                                            "timestamp": datetime.now().isoformat(),
                                            "user_id": user_id,
                                            "request_id": str(uuid.uuid4()),
                                        }
                                except Exception as retry_exc:
                                    token_logger.error(
                                        "Retry with auth_token failed: %s", retry_exc
                                    )
                                    if httpx_client2:
                                        try:
                                            await httpx_client2.aclose()
                                        except Exception:
                                            pass

                        return {
                            "type": "error",
                            "message": "A2A request failed: HTTP 401 (use agentgateway for policy; verify request signing).",
                            "timestamp": datetime.now().isoformat(),
                        }
                    add_event("a2a_http_error", {"status_code": status_code})
                    raise
                
                if response_content:
                    if settings.debug:
                        logger.debug(f"✅ Got response from agent: {response_content[:100]}...")
                    add_event("agent_response_processed", {
                        "response_length": len(response_content),
                        "response_preview": response_content[:100]
                    })
                    
                    # Close HTTP client
                    await httpx_client.aclose()
                    add_event("httpx_client_closed")
                    
                    return {
                        "type": "success",
                        "agent_response": response_content,
                        "timestamp": datetime.now().isoformat(),
                        "user_id": user_id,
                        "request_id": str(uuid.uuid4())
                    }
                else:
                    if settings.debug:
                        logger.debug("❌ No response content received from agent")
                    add_event("no_agent_response_received")
                    
                    # Close HTTP client
                    await httpx_client.aclose()
                    add_event("httpx_client_closed")
                    
                    return {
                        "type": "error",
                        "message": "No response received from A2A agent",
                        "timestamp": datetime.now().isoformat()
                    }
                    
            except Exception as e:
                if settings.debug:
                    logger.debug(f"💥 Exception in A2A optimization: {e}")
                    logger.debug(f"💥 Exception type: {type(e)}")
                    import traceback
                    logger.debug(traceback.format_exc())
                
                add_event("a2a_optimization_exception", {
                    "error": str(e),
                    "error_type": str(type(e))
                })
                
                # Close HTTP client if it exists
                if httpx_client:
                    try:
                        await httpx_client.aclose()
                        add_event("httpx_client_closed_on_error")
                    except:
                        pass
                
                return {
                    "type": "error",
                    "message": f"Exception in A2A optimization: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }

    def _create_optimization_message(self, request: OptimizationRequest) -> str:
        """Create optimization message for A2A agent"""
        with span("a2a_service.create_optimization_message", {
            "request_type": request.effective_optimization_type,
            "has_constraints": bool(request.effective_constraints),
            "has_custom_prompt": bool(request.custom_prompt)
        }) as span_obj:
            
            # Start with custom prompt if provided, otherwise use base message
            if request.custom_prompt:
                message = request.custom_prompt
                # If custom prompt doesn't end with a period, add one
                if not message.endswith('.'):
                    message += '.'
            else:
                # Base message
                message = f"Please optimize our supply chain for {request.effective_optimization_type}"
            
            # Add constraints if specified
            if request.effective_constraints:
                constraints_text = ", ".join(request.effective_constraints)
                message += f" with the following constraints: {constraints_text}"
            
            # Add priority if specified
            if request.priority:
                message += f". Priority level: {request.priority}"
            
            # Add additional context if using base message
            if not request.custom_prompt:
                message += ". Please provide detailed analysis and recommendations."
            
            add_event("optimization_message_created", {
                "message_length": len(message),
                "has_constraints": bool(request.effective_constraints),
                "has_priority": bool(request.priority),
                "has_custom_prompt": bool(request.custom_prompt),
                "custom_prompt_used": bool(request.custom_prompt)
            })
            
            return message
    
    def _process_agent_response(
        self, 
        event: Any, 
        request: OptimizationRequest, 
        user_id: str
    ) -> Optional[Dict[str, Any]]:
        """Process agent response and convert to progress data"""
        
        try:
            # Extract relevant information from the event
            # This will depend on the actual A2A response format
            if hasattr(event, 'content') and event.content:
                content = event.content
                if isinstance(content, str):
                    return {
                        "type": "progress",
                        "message": content,
                        "timestamp": datetime.utcnow().isoformat(),
                        "user_id": user_id,
                        "request_id": str(uuid.uuid4())
                    }
                elif isinstance(content, dict):
                    return {
                        "type": "progress",
                        "message": content.get("message", "Processing optimization..."),
                        "data": content,
                        "timestamp": datetime.utcnow().isoformat(),
                        "user_id": user_id,
                        "request_id": str(uuid.uuid4())
                    }
            
            # If no content, return a generic progress update
            return {
                "type": "progress",
                "message": "Agent processing optimization request...",
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": user_id,
                "request_id": str(uuid.uuid4())
            }
            
        except Exception as e:
            # Return error information
            return {
                "type": "error",
                "message": f"Error processing agent response: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": user_id,
                "request_id": str(uuid.uuid4())
            }
    
    def _is_optimization_complete(self, event: Any) -> bool:
        """Check if the optimization is complete based on the event"""
        
        # This logic will depend on the actual A2A response format
        # For now, we'll assume completion after receiving a response
        # In a real implementation, you'd check for completion indicators
        
        if hasattr(event, 'content'):
            content = event.content
            if isinstance(content, str):
                # Check for completion keywords
                completion_indicators = [
                    "complete", "completed", "finished", "done", 
                    "optimization complete", "recommendations"
                ]
                return any(indicator in content.lower() for indicator in completion_indicators)
            elif isinstance(content, dict):
                # Check for completion status in structured response
                return content.get("status") == "complete" or content.get("completed", False)
        
        return False
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to the A2A agent with AAuth request signing."""
        with span("a2a_service.test_connection", {
            "agent_url": self.agent_url,
            "auth_method": "aauth_hwk"
        }) as span_obj:
            
            try:
                add_event("connection_test_started", {
                    "agent_url": self.agent_url,
                    "auth_method": "aauth_hwk"
                })
                
                if settings.debug:
                    logger.debug(f"🔐 Testing connection with AAuth HWK signing...")
                
                # Create a simple test client with AAuth signing
                client, httpx_client = await self._create_client()
                
                # Test with a simple message
                test_message = create_text_message_object(
                    role=Role.user, 
                    content="test connection"
                )
                
                add_event("test_message_created")
                
                # Try to send the message
                response_received = False
                async for event in client.send_message(test_message):
                    response_received = True
                    break
                
                # Close HTTP client
                await httpx_client.aclose()
                add_event("httpx_client_closed")
                
                if response_received:
                    add_event("connection_test_successful")
                    return {
                        "status": "connected",
                        "url": self.agent_url,
                        "message": "Successfully connected to A2A agent with AAuth HWK signing",
                        "auth_method": "aauth_hwk"
                    }
                else:
                    add_event("connection_test_no_response")
                    return {
                        "status": "warning",
                        "url": self.agent_url,
                        "message": "Connected but no response received"
                    }
                    
            except Exception as e:
                add_event("connection_test_failed", {"error": str(e)})
                return {
                    "status": "error",
                    "url": self.agent_url,
                    "error": str(e)
                }


# Global instance
a2a_service = A2AService()
