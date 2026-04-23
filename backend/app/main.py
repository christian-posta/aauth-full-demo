# Load environment variables from .env file FIRST, before any other imports
from contextlib import asynccontextmanager
from dotenv import load_dotenv
load_dotenv()

from app.config import settings
from app.logging_config import configure_logging

configure_logging()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import auth, agents, optimization
from app.tracing_config import initialize_tracing
from app.services.agent_token_service import agent_token_service
import os

# Initialize tracing before creating the FastAPI app
jaeger_host = os.getenv("JAEGER_HOST", "localhost")  # Default to localhost for development
jaeger_port = int(os.getenv("JAEGER_PORT", "4317"))
enable_console_exporter = os.getenv("ENABLE_CONSOLE_EXPORTER", "true").lower() == "true"

if settings.debug:
    print(f"🔗 Initializing tracing with Jaeger at {jaeger_host}:{jaeger_port}")
    print(f"🔗 Environment variables loaded from .env file")
    print(f"🔗 JAEGER_HOST: {os.getenv('JAEGER_HOST', 'NOT SET')}")
    print(f"🔗 JAEGER_PORT: {os.getenv('JAEGER_PORT', 'NOT SET')}")
    print(f"🔗 ENABLE_CONSOLE_EXPORTER: {os.getenv('ENABLE_CONSOLE_EXPORTER', 'true')}")

initialize_tracing(
    service_name="supply-chain-backend",
    jaeger_host=jaeger_host,
    jaeger_port=jaeger_port,
    enable_console_exporter=enable_console_exporter
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await agent_token_service.startup()
    yield


app = FastAPI(
    title="Supply Chain Agent API",
    description="Backend API for supply chain optimization with agent workflows",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Global exception handler to ensure CORS headers are always present
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler that ensures CORS headers are always present"""
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "error": str(exc),
            "type": type(exc).__name__
        }
    )

# Preflight handler for CORS
@app.options("/{full_path:path}")
async def preflight_handler(request: Request):
    """Handle preflight OPTIONS requests for CORS"""
    return JSONResponse(
        content={},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(agents.router, prefix="/agents", tags=["Agents"])
app.include_router(optimization.router, prefix="/optimization", tags=["Optimization"])

@app.get("/")
async def root():
    return {"message": "Supply Chain Agent API", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "supply-chain-api"}

def main():
    """Main function to run the FastAPI server with uvicorn.

    Auto-reload is off by default so Ctrl+C reliably stops the process (reload spawns a
    supervisor + worker and often leaves extra PIDs or a stuck listener). Enable with
    ``UVICORN_RELOAD=1`` when developing.
    """
    import uvicorn

    reload = os.getenv("UVICORN_RELOAD", "").lower() in ("1", "true", "yes")
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=reload,
        log_level="info",
    )

if __name__ == "__main__":
    main()
