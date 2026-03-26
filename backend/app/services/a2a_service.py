import asyncio
import json
import uuid
import os
import logging
from typing import AsyncGenerator, Dict, Any, Optional
import httpx
from datetime import datetime

from a2a.client import ClientFactory, ClientConfig
from a2a.types import TransportProtocol, Message, Role
from a2a.client.helpers import create_text_message_object
from a2a.client import minimal_agent_card

from app.config import settings
from app.models import OptimizationRequest, OptimizationProgress, OptimizationResults
from app.tracing_config import span, add_event, set_attribute, extract_context_from_headers
from app.services.aauth_interceptor import AAuthSigningInterceptor
from app.services.aauth_protocol import parse_aauth_header
from app.services.aauth_token_service import aauth_token_service

# Configure logging
logger = logging.getLogger(__name__)
token_logger = logging.getLogger("aauth.tokens")  # For token/challenge visibility - not suppressed


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
        self._last_401_response = None
    
    async def _create_client(self, trace_context: Any = None, auth_token: str = None) -> tuple[Any, httpx.AsyncClient]:
        """Create A2A client and HTTP client with AAuth signing.
        
        Args:
            trace_context: Optional trace context for distributed tracing
            auth_token: Optional auth token for scheme=jwt (if provided, will use JWT scheme)
        """
        with span("a2a_service.create_client", {
            "agent_url": self.agent_url,
            "has_trace_context": trace_context is not None,
            "has_auth_token": auth_token is not None
        }) as span_obj:
            
            if settings.debug:
                logger.debug(f"🔧 Creating A2A client for URL: {self.agent_url}")
                if auth_token:
                    logger.debug(f"🔐 Using AAuth JWT signing with auth_token")
                else:
                    logger.debug(f"🔐 Using AAuth signature signing (will trigger challenge if needed)")
            add_event("creating_a2a_client", {
                "agent_url": self.agent_url,
                "has_auth_token": auth_token is not None
            })
            
            # Create httpx client with event hook to intercept 401 responses
            service_instance = self  # Capture self for use in closure
            async def response_hook(response: httpx.Response):
                """Hook to intercept HTTP responses and extract AAuth header from 401."""
                if response.status_code == 401:
                    token_logger.info(f"🔐 401 from supply-chain-agent (url={response.url}): headers={dict(response.headers)}")
                    agent_auth_header = response.headers.get("AAuth")
                    if agent_auth_header:
                        service_instance._last_401_response = response
                        add_event("agent_auth_challenge_received", {
                            "has_agent_auth": bool(agent_auth_header)
                        })
            
            httpx_client = httpx.AsyncClient(
                timeout=self.timeout,
                event_hooks={"response": [response_hook]}
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
            
            # Create AAuth signing interceptor
            # IMPORTANT: On first attempt, auth_token MUST be None to use JWKS and trigger 401 challenge
            # Only on retry after getting auth_token should we pass it here
            if settings.debug:
                if auth_token:
                    logger.debug(f"🔐 Creating interceptor WITH auth_token (retry after challenge)")
                else:
                    logger.debug(f"🔐 Creating interceptor WITHOUT auth_token (first attempt - will use JWKS)")
            aauth_interceptor = AAuthSigningInterceptor(auth_token=auth_token)
            if settings.debug:
                logger.debug("🔐 AAuth signing interceptor created")
            add_event("aauth_interceptor_created")
            
            # Create client with AAuth signing interceptor
            client = factory.create(agent_card, interceptors=[aauth_interceptor])
            if settings.debug:
                logger.debug("✅ A2A client created with AAuth signing")
            add_event("a2a_client_created_with_aauth_signing")
            
            return client, httpx_client
    
    async def optimize_supply_chain(
                self,
        request: OptimizationRequest, 
        user_id: str,
        trace_context: Any = None,
        auth_token: str = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Optimize supply chain using A2A agent with tracing support.
        
        Note: auth_token parameter is for AAuth auth_token (obtained from Keycloak AAuth endpoint),
        NOT the OIDC token. The OIDC token should NOT be passed here.
        
        Returns direct success, or an interaction/approval pending state when the
        auth server defers token issuance.
        """
        
        with span("a2a_service.optimize_supply_chain", {
            "user_id": user_id,
            "request_type": request.effective_optimization_type,
            "has_trace_context": trace_context is not None,
            "has_aauth_auth_token": auth_token is not None
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
                
                # Create A2A client with tracing
                # auth_token is provided in two valid cases:
                # 1. Retry after 401 challenge (autonomous flow, same request)
                # 2. User-delegated flow: callback runs workflow with auth_token from consent
                if settings.debug:
                    logger.debug(f"🔐 auth_token={'present' if auth_token else 'None'}, scheme={'jwt' if auth_token else 'JWKS'}")
                if settings.debug:
                    logger.debug("🔧 Creating A2A client...")
                client, httpx_client = await self._create_client(trace_context, auth_token)
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
                agent_auth_header = None
                
                try:
                    async for event in client.send_message(message):
                        response_count += 1
                        if settings.debug:
                            logger.debug(f"📨 Received event #{response_count}: {event}")
                            logger.debug(f"📨 Event type: {type(event)}")
                            logger.debug(f"📨 Event attributes: {dir(event)}")
                        
                        add_event("agent_response_received", {
                            "event_number": response_count,
                            "event_type": str(type(event))
                        })
                        
                        # Get the response content from the A2A message structure
                        if hasattr(event, 'content') and event.content:
                            if isinstance(event.content, str):
                                response_content = event.content
                                if settings.debug:
                                    logger.debug(f"📝 String content: {response_content[:100]}...")
                            elif isinstance(event.content, dict) and 'content' in event.content:
                                response_content = event.content['content']
                                if settings.debug:
                                    logger.debug(f"📝 Dict content: {response_content[:100]}...")
                        elif hasattr(event, 'text'):
                            response_content = event.text
                            if settings.debug:
                                logger.debug(f"📝 Text attribute: {response_content[:100]}...")
                        elif hasattr(event, 'parts') and event.parts:
                            # Handle parts structure
                            for part in event.parts:
                                if hasattr(part, 'root') and hasattr(part.root, 'text'):
                                    response_content = part.root.text
                                    if settings.debug:
                                        logger.debug(f"📝 Part text: {response_content[:100]}...")
                                    break
                        
                        # Just get the first response for now
                        break
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 401:
                        agent_auth_header = e.response.headers.get("AAuth")
                        if agent_auth_header:
                            add_event("agent_auth_challenge_received", {
                                "has_agent_auth": True
                            })
                        else:
                            # 401 without AAuth - re-raise
                            raise
                    else:
                        # Other HTTP error - re-raise
                        raise
                except Exception as e:
                    if self._last_401_response:
                        agent_auth_header = self._last_401_response.headers.get("AAuth")
                        if agent_auth_header:
                            add_event("agent_auth_challenge_detected", {
                                "has_agent_auth": True
                            })
                            self._last_401_response = None
                        else:
                            raise
                    else:
                        raise
                
                if agent_auth_header:
                    add_event("processing_agent_auth_challenge")
                    parsed_header = parse_aauth_header(agent_auth_header)
                    resource_token = parsed_header.resource_token
                    auth_server = parsed_header.auth_server

                    if resource_token:
                        add_event("resource_token_extracted", {
                            "has_resource_token": bool(resource_token),
                            "has_auth_server": bool(auth_server)
                        })

                        try:
                            token_result = await aauth_token_service.request_auth_token(
                                resource_token=resource_token,
                                purpose=request.custom_prompt or request.effective_optimization_type,
                            )

                            if token_result.get("status") == "interaction_required":
                                await httpx_client.aclose()
                                return {
                                    "type": "interaction_required",
                                    "request_id": request_id,
                                    "pending_url": token_result.get("pending_url"),
                                    "interaction_code": token_result.get("interaction_code"),
                                    "interaction_endpoint": token_result.get("interaction_endpoint"),
                                    "retry_after": token_result.get("retry_after", 0),
                                }

                            if token_result.get("status") == "approval_pending":
                                await httpx_client.aclose()
                                return {
                                    "type": "approval_pending",
                                    "request_id": request_id,
                                    "pending_url": token_result.get("pending_url"),
                                    "retry_after": token_result.get("retry_after", 0),
                                }

                            auth_token = token_result.get("auth_token")
                            expires_in = token_result.get("expires_in", 3600)

                            if auth_token:
                                add_event("auth_token_received", {
                                    "has_auth_token": True,
                                    "expires_in": expires_in
                                })
                                agent_id = os.getenv("BACKEND_AGENT_URL", f"http://{settings.host}:{settings.port}")
                                scope = "supply-chain:optimize"
                                aauth_token_service.cache_token(
                                    agent_id=agent_id,
                                    scope=scope,
                                    auth_token=auth_token,
                                    expires_in=expires_in
                                )

                            add_event("retrying_request_with_auth_token")
                            await httpx_client.aclose()
                            client, httpx_client = await self._create_client(trace_context, auth_token)

                            async for event in client.send_message(message):
                                response_count += 1
                                add_event("agent_response_received_retry", {
                                    "event_number": response_count
                                })
                                if hasattr(event, 'content') and event.content:
                                    if isinstance(event.content, str):
                                        response_content = event.content
                                    elif isinstance(event.content, dict) and 'content' in event.content:
                                        response_content = event.content['content']
                                elif hasattr(event, 'text'):
                                    response_content = event.text
                                elif hasattr(event, 'parts') and event.parts:
                                    for part in event.parts:
                                        if hasattr(part, 'root') and hasattr(part.root, 'text'):
                                            response_content = part.root.text
                                            break
                                
                                break
                        except Exception as token_error:
                            add_event("auth_token_request_failed", {"error": str(token_error)})
                            raise Exception(f"Failed to get auth_token: {token_error}")
                    else:
                        add_event("agent_auth_missing_resource_token")
                        raise Exception("AAuth header missing resource-token")
                
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
    
    async def test_connection(self, auth_token: str = None) -> Dict[str, Any]:
        """Test connection to the A2A agent with AAuth HWK signing.
        
        Note: auth_token parameter is kept for API compatibility but is no longer
        used. Authentication is handled via AAuth HWK request signing.
        """
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
