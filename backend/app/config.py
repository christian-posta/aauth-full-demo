import os
from typing import List

class Settings:
    # API Configuration
    api_title: str = "Supply Chain Agent API"
    api_version: str = "1.0.0"
    debug: bool = os.getenv("DEBUG", "true").lower() == "true"
    
    # Server Configuration
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    
    # CORS Configuration
    cors_allow_all: bool = os.getenv("CORS_ALLOW_ALL", "true").lower() == "true"
    allowed_origins: List[str] = ["*"] if os.getenv("CORS_ALLOW_ALL", "true").lower() == "true" else os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3050,http://127.0.0.1:3000,http://127.0.0.1:3050,http://localhost:5173,http://127.0.0.1:5173").split(",")
    
    # Keycloak Configuration
    keycloak_url: str = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
    keycloak_realm: str = os.getenv("KEYCLOAK_REALM", "mcp-realm")
    keycloak_client_id: str = os.getenv("KEYCLOAK_CLIENT_ID", "supply-chain-ui")
    
    # Agent Configuration
    max_concurrent_agents: int = 5
    agent_timeout_seconds: int = 300
    
    # A2A Configuration
    supply_chain_agent_url: str = os.getenv("SUPPLY_CHAIN_AGENT_URL", "http://supply-chain-agent.localhost:3000")
    
    # Agent STS Configuration
    agent_sts_url: str = os.getenv("AGENT_STS_URL", "http://localhost:8081")
    backend_spiffe_id: str = os.getenv("BACKEND_SPIFFE_ID", "spiffe://cluster.local/ns/default/sa/backend")

settings = Settings()
