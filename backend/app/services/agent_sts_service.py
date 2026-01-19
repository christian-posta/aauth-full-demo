import httpx
from typing import Optional, Dict, Any
from urllib.parse import urlencode

from app.config import settings
from app.tracing_config import span, add_event, set_attribute


class AgentSTSService:
    """Service for exchanging tokens with the Agent STS service"""
    
    def __init__(self):
        self.sts_url = settings.agent_sts_url
        self.api_endpoint = f"{self.sts_url}/api/v1/token"
        self.timeout = httpx.Timeout(
            connect=10.0,      # 10 seconds to establish connection
            read=30.0,         # 30 seconds to read response
            write=10.0,        # 10 seconds to write request
            pool=10.0          # 10 seconds for connection pool
        )
    
    async def exchange_token(
        self, 
        access_token: str, 
        resource: str = "supply-chain-agent",
        actor_token: str = "spiffe://cluster.local/ns/default/sa/backend"
    ) -> Optional[str]:
        """
        Exchange an access token for an OBO (On-Behalf-Of) token
        
        Args:
            access_token: The access token to exchange
            resource: The target resource/audience for the new token
            actor_token: The SPIFFE ID of the calling service
            
        Returns:
            The exchanged OBO token as a JWT string, or None if exchange failed
        """
        with span("agent_sts_service.exchange_token", {
            "resource": resource,
            "actor_token": actor_token,
            "has_access_token": bool(access_token)
        }) as span_obj:
            
            try:
                print(f"🔄 Exchanging access token for OBO token...")
                print(f"📋 Resource: {resource}")
                print(f"👤 Actor: {actor_token}")
                print(f"🔐 Input access token: {access_token[:50]}...")
                add_event("token_exchange_started", {
                    "resource": resource,
                    "actor_token": actor_token
                })
                
                # Prepare the request payload according to RFC 8693
                payload_data = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token": access_token,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
                    "resource": resource,
                    "actor_token": actor_token
                }
                
                # Encode as form data
                payload = urlencode(payload_data)
                
                print(f"📡 Sending token exchange request to: {self.api_endpoint}")
                print(f"📝 Request payload: {payload}")
                add_event("token_exchange_request_sent", {
                    "endpoint": self.api_endpoint,
                    "payload_length": len(payload)
                })
                
                # Make the request
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        self.api_endpoint,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        content=payload
                    )
                
                print(f"📨 Token exchange response status: {response.status_code}")
                print(f"📨 Response body: {response.text}")
                add_event("token_exchange_response_received", {
                    "status_code": response.status_code,
                    "response_length": len(response.text)
                })
                
                # Handle different response statuses
                if response.status_code == 200:
                    try:
                        response_data = response.json()
                        obo_token = response_data.get("access_token")
                        
                        if obo_token:
                            print(f"✅ Token exchange successful! OBO token: {obo_token[:50]}...")
                            print(f"🔐 Full OBO token: {obo_token}")
                            add_event("token_exchange_successful", {
                                "obo_token_length": len(obo_token)
                            })
                            set_attribute("agent_sts.exchange_success", True)
                            return obo_token
                        else:
                            print(f"❌ Token exchange response missing access_token")
                            add_event("token_exchange_missing_token")
                            set_attribute("agent_sts.exchange_success", False)
                            return None
                            
                    except Exception as e:
                        print(f"❌ Failed to parse token exchange response: {e}")
                        add_event("token_exchange_parse_error", {"error": str(e)})
                        set_attribute("agent_sts.exchange_success", False)
                        return None
                        
                elif response.status_code == 400:
                    print(f"❌ Bad Request - JWT validation failed or request format error")
                    add_event("token_exchange_bad_request")
                    set_attribute("agent_sts.exchange_success", False)
                    return None
                    
                elif response.status_code == 401:
                    print(f"❌ Unauthorized - JWT validation failed")
                    add_event("token_exchange_unauthorized")
                    set_attribute("agent_sts.exchange_success", False)
                    return None
                    
                elif response.status_code == 403:
                    print(f"❌ Forbidden - JWT issuer not trusted")
                    add_event("token_exchange_forbidden")
                    set_attribute("agent_sts.exchange_success", False)
                    return None
                    
                else:
                    print(f"❌ Unexpected response status: {response.status_code}")
                    print(f"Response body: {response.text}")
                    add_event("token_exchange_unexpected_status", {
                        "status_code": response.status_code
                    })
                    set_attribute("agent_sts.exchange_success", False)
                    return None
                    
            except httpx.TimeoutException as e:
                print(f"❌ Token exchange timeout: {e}")
                add_event("token_exchange_timeout", {"error": str(e)})
                set_attribute("agent_sts.exchange_success", False)
                return None
                
            except httpx.RequestError as e:
                print(f"❌ Token exchange request error: {e}")
                add_event("token_exchange_request_error", {"error": str(e)})
                set_attribute("agent_sts.exchange_success", False)
                return None
                
            except Exception as e:
                print(f"❌ Unexpected error during token exchange: {e}")
                add_event("token_exchange_unexpected_error", {"error": str(e)})
                set_attribute("agent_sts.exchange_success", False)
                return None
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to the Agent STS service"""
        with span("agent_sts_service.test_connection", {
            "sts_url": self.sts_url
        }) as span_obj:
            
            try:
                print(f"🔍 Testing connection to Agent STS service: {self.sts_url}")
                add_event("sts_connection_test_started")
                
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(f"{self.sts_url}/health")
                
                if response.status_code == 200:
                    print(f"✅ Agent STS service is healthy")
                    add_event("sts_connection_test_successful")
                    set_attribute("agent_sts.connection_status", "healthy")
                    return {
                        "status": "connected",
                        "url": self.sts_url,
                        "message": "Successfully connected to Agent STS service"
                    }
                else:
                    print(f"❌ Agent STS service health check failed: {response.status_code}")
                    add_event("sts_connection_test_failed", {
                        "status_code": response.status_code
                    })
                    set_attribute("agent_sts.connection_status", "unhealthy")
                    return {
                        "status": "error",
                        "url": self.sts_url,
                        "error": f"Health check failed with status {response.status_code}"
                    }
                    
            except Exception as e:
                print(f"❌ Failed to connect to Agent STS service: {e}")
                add_event("sts_connection_test_error", {"error": str(e)})
                set_attribute("agent_sts.connection_status", "error")
                return {
                    "status": "error",
                    "url": self.sts_url,
                    "error": str(e)
                }


# Global instance
agent_sts_service = AgentSTSService()
