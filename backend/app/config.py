import os
from pathlib import Path
from typing import List

_BACKEND_ROOT = Path(__file__).resolve().parent.parent


def _agent_server_base_from_env() -> str:
    """Agent Server origin; default ``http://127.0.0.1:8765``."""
    raw = (os.environ.get("AGENT_SERVER_BASE") or "").strip()
    return raw or "http://127.0.0.1:8765"


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
    
    # Agent Configuration
    max_concurrent_agents: int = 5
    agent_timeout_seconds: int = 300
    
    # A2A Configuration
    supply_chain_agent_url: str = os.getenv("SUPPLY_CHAIN_AGENT_URL", "http://supply-chain-agent.localhost:3000")

    # Frontend URL — used to build the callback redirect URI sent to the PS/AS
    # so the user is redirected back to the app after consent.
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:3050").rstrip("/")

    # Agent Server (aa-agent+jwt for outbound A2A). Stable keys: ``backend-stable.key`` /
    # ``backend-stable.pub`` in the backend package root (created on first run).
    agent_server_base: str = _agent_server_base_from_env()
    # Required on POST /register per CLIENTS.md (display name, 1–256 chars after trim).
    agent_name: str = (os.getenv("BACKEND_AGENT_NAME") or "Backend App").strip() or "Backend App"
    stable_identity_dir: Path = _BACKEND_ROOT

settings = Settings()
