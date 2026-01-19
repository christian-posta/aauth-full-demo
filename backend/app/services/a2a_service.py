import asyncio
import json
import uuid
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
from app.services.tracing_interceptor import TracingInterceptor
from app.services.agent_sts_service import agent_sts_service


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
    
    async def _create_client(self, trace_context: Any = None, auth_token: str = None) -> tuple[Any, httpx.AsyncClient]:
        """Create A2A client and HTTP client with tracing support and token exchange"""
        with span("a2a_service.create_client", {
            "agent_url": self.agent_url,
            "has_trace_context": trace_context is not None,
            "has_auth_token": auth_token is not None
        }) as span_obj:
            
            print(f"🔧 Creating A2A client for URL: {self.agent_url}")
            add_event("creating_a2a_client", {"agent_url": self.agent_url})
            
            # Exchange access token for OBO token if provided
            obo_token = None
            if auth_token:
                print(f"🔄 Exchanging access token for OBO token...")
                obo_token = await agent_sts_service.exchange_token(
                    access_token=auth_token,
                    resource="supply-chain-agent",
                    actor_token=settings.backend_spiffe_id
                )
                
                if obo_token:
                    print(f"✅ Token exchange successful, using OBO token for agent authentication")
                    add_event("token_exchange_successful_for_client")
                else:
                    print(f"⚠️ Token exchange failed, falling back to original access token")
                    add_event("token_exchange_failed_fallback")
                    obo_token = auth_token  # Fallback to original token
            else:
                print(f"⚠️ No auth token provided, proceeding without authentication")
                add_event("no_auth_token_provided")
            
            httpx_client = httpx.AsyncClient(timeout=self.timeout)
            print("✅ HTTPX client created")
            add_event("httpx_client_created")
            
            # Create client configuration
            config = ClientConfig(
                httpx_client=httpx_client,
                supported_transports=[TransportProtocol.jsonrpc],
                streaming=False
            )
            print("✅ Client config created")
            add_event("client_config_created")
            
            # Create client factory
            factory = ClientFactory(config)
            print("✅ Client factory created")
            add_event("client_factory_created")
            
            # Create agent card
            agent_card = minimal_agent_card(
                url=self.agent_url,
                transports=["JSONRPC"]
            )
            print(f"✅ Agent card created: {agent_card}")
            add_event("agent_card_created", {"agent_url": self.agent_url})
            
            # Create auth token headers for agent authentication
            auth_token_headers = {}
            if obo_token:
                auth_token_headers["Authorization"] = f"Bearer {obo_token}"
                print("🔐 OBO token added to headers for agent authentication")
                add_event("obo_token_added_to_headers")
            
            # Create tracing interceptor with auth token headers
            tracing_interceptor = TracingInterceptor(trace_headers=auth_token_headers)
            add_event("tracing_interceptor_created")
            
            # Create client with tracing interceptor
            client = factory.create(agent_card, interceptors=[tracing_interceptor])
            print("✅ A2A client created with tracing and OBO token authentication")
            add_event("a2a_client_created_with_tracing_and_obo_token")
            
            return client, httpx_client
    
    async def optimize_supply_chain(
        self, 
        request: OptimizationRequest, 
        user_id: str,
        trace_context: Any = None,
        auth_token: str = None
    ) -> Dict[str, Any]:
        """Optimize supply chain using A2A agent with tracing support and access token authentication"""
        
        with span("a2a_service.optimize_supply_chain", {
            "user_id": user_id,
            "request_type": request.effective_optimization_type,
            "has_trace_context": trace_context is not None,
            "has_auth_token": auth_token is not None
        }, parent_context=trace_context) as span_obj:
            
            client, httpx_client = None, None
            
            try:
                print(f"🚀 Starting A2A optimization for user: {user_id}")
                print(f"📝 Request: {request}")
                
                add_event("optimization_started", {
                    "user_id": user_id,
                    "request_type": request.effective_optimization_type
                })
                
                # Create A2A client with tracing
                print("🔧 Creating A2A client...")
                client, httpx_client = await self._create_client(trace_context, auth_token)
                print("✅ A2A client created successfully")
                add_event("a2a_client_created_successfully")
                
                # Create optimization message
                message_content = self._create_optimization_message(request)
                print(f"💬 Created message: {message_content}")
                print(f"🔍 Custom prompt was: {request.custom_prompt}")
                print(f"🔍 Final message length: {len(message_content)}")
                add_event("optimization_message_created", {
                    "message_length": len(message_content),
                    "custom_prompt": request.custom_prompt,
                    "final_message": message_content[:100] + "..." if len(message_content) > 100 else message_content
                })
                
                message = create_text_message_object(
                    role=Role.user, 
                    content=message_content
                )
                print(f"📤 Message object created: {message}")
                add_event("message_object_created")
                
                # Send message to agent and get response
                print(f"📡 Sending message to agent at: {self.agent_url}")
                add_event("sending_message_to_agent", {"agent_url": self.agent_url})
                
                response_content = None
                response_count = 0
                
                async for event in client.send_message(message):
                    response_count += 1
                    print(f"📨 Received event #{response_count}: {event}")
                    print(f"📨 Event type: {type(event)}")
                    print(f"📨 Event attributes: {dir(event)}")
                    
                    add_event("agent_response_received", {
                        "event_number": response_count,
                        "event_type": str(type(event))
                    })
                    
                    # Get the response content from the A2A message structure
                    if hasattr(event, 'content') and event.content:
                        if isinstance(event.content, str):
                            response_content = event.content
                            print(f"📝 String content: {response_content[:100]}...")
                        elif isinstance(event.content, dict) and 'content' in event.content:
                            response_content = event.content['content']
                            print(f"📝 Dict content: {response_content[:100]}...")
                    elif hasattr(event, 'text'):
                        response_content = event.text
                        print(f"📝 Text attribute: {response_content[:100]}...")
                    elif hasattr(event, 'parts') and event.parts:
                        # Handle parts structure
                        for part in event.parts:
                            if hasattr(part, 'root') and hasattr(part.root, 'text'):
                                response_content = part.root.text
                                print(f"📝 Part text: {response_content[:100]}...")
                                break
                    
                    # Just get the first response for now
                    break
                
                if response_content:
                    print(f"✅ Got response from agent: {response_content[:100]}...")
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
                    print("❌ No response content received from agent")
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
                print(f"💥 Exception in A2A optimization: {e}")
                print(f"💥 Exception type: {type(e)}")
                import traceback
                traceback.print_exc()
                
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
        """Test connection to the A2A agent with tracing support and OBO token authentication"""
        with span("a2a_service.test_connection", {
            "agent_url": self.agent_url,
            "has_auth_token": auth_token is not None
        }) as span_obj:
            
            try:
                add_event("connection_test_started", {"agent_url": self.agent_url})
                
                # Exchange access token for OBO token if provided
                obo_token = None
                if auth_token:
                    print(f"🔄 Exchanging access token for OBO token for connection test...")
                    obo_token = await agent_sts_service.exchange_token(
                        access_token=auth_token,
                        resource="supply-chain-agent",
                        actor_token=settings.backend_spiffe_id
                    )
                    
                    if obo_token:
                        print(f"✅ Token exchange successful for connection test")
                        add_event("token_exchange_successful_for_test")
                    else:
                        print(f"⚠️ Token exchange failed for connection test, using original token")
                        add_event("token_exchange_failed_for_test")
                        obo_token = auth_token  # Fallback to original token
                
                # Create a simple test client
                client, httpx_client = await self._create_client(auth_token=obo_token)
                
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
                        "message": "Successfully connected to A2A agent"
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
