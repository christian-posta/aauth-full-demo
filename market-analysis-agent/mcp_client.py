"""
MCP Client for Market Analysis Agent

This module uses the official Model Context Protocol Python SDK to communicate
with MCP servers and discover available tools.
"""

import logging
import os
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


def validate_mcp_url(base_url: str, path: str) -> bool:
    """Validate that the MCP server URL is properly formatted."""
    try:
        # Ensure base_url has a scheme
        if not base_url.startswith(('http://', 'https://')):
            base_url = f"http://{base_url}"
        
        # Parse the URL to validate format
        parsed = urlparse(base_url)
        if not parsed.netloc:
            return False
            
        # Ensure path starts with /
        if not path.startswith('/'):
            path = f"/{path}"
            
        return True
    except Exception:
        return False


class MCPClient:
    """Client for communicating with MCP servers using the official SDK."""
    
    def __init__(self, base_url: str = None, mcp_path: str = None, 
                 connection_timeout: int = None, read_timeout: int = None,
                 jwt_token: str = None):
        # Read environment variables at runtime when they are available
        self.base_url = base_url or os.getenv("MCP_SERVER_BASE_URL", "http://localhost:3000")
        self.mcp_path = mcp_path or os.getenv("MCP_SERVER_PATH", "/general/mcp")
        self.connection_timeout = connection_timeout or int(os.getenv("MCP_CONNECTION_TIMEOUT", "30"))
        self.read_timeout = read_timeout or int(os.getenv("MCP_READ_TIMEOUT", "60"))
        self.jwt_token = jwt_token
        
        # Validate the URL configuration
        if not validate_mcp_url(self.base_url, self.mcp_path):
            logger.warning(f"Invalid MCP server URL configuration: {self.base_url}{self.mcp_path}")
        
        # Log the configuration being used
        logger.info(f"MCP Client initialized with server: {self.base_url}{self.mcp_path}")
        logger.info(f"MCP Client timeouts - connection: {self.connection_timeout}s, read: {self.read_timeout}s")
        if self.jwt_token:
            logger.info(f"MCP Client JWT token: {len(self.jwt_token)} characters")
        else:
            logger.info("MCP Client: No JWT token provided")
        
    def get_config(self) -> Dict[str, Any]:
        """Get the current MCP client configuration."""
        return {
            "base_url": self.base_url,
            "mcp_path": self.mcp_path,
            "full_url": f"{self.base_url}{self.mcp_path}",
            "connection_timeout": self.connection_timeout,
            "read_timeout": self.read_timeout,
            "has_jwt_token": bool(self.jwt_token)
        }
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
        
    async def discover_tools(self) -> List[Dict[str, Any]]:
        """
        Discover available tools from the MCP server.
        
        Returns:
            List of available tools with their descriptions
            
        Raises:
            Exception: If connection to MCP server fails
        """
        try:
            # Prepare headers with JWT token if available
            headers = {}
            if self.jwt_token:
                headers['Authorization'] = f'Bearer {self.jwt_token}'
                logger.info(f"Adding JWT authorization header for MCP server call")
            
            # Use the official MCP SDK to connect and discover tools
            async with streamablehttp_client(
                f"{self.base_url}{self.mcp_path}",
                headers=headers if headers else None,
                timeout=self.connection_timeout
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    # Initialize the connection
                    await session.initialize()
                    
                    # List available tools
                    tools_response = await session.list_tools()
                    
                    # Format tools for our response
                    tools = []
                    for tool in tools_response.tools:
                        tool_info = {
                            "name": tool.name,
                            "description": tool.description or "No description available",
                            "type": "tool"
                        }
                        
                        # Add additional metadata if available
                        if hasattr(tool, 'title') and tool.title:
                            tool_info["display_name"] = tool.title
                        if hasattr(tool, 'annotations') and tool.annotations:
                            tool_info["annotations"] = tool.annotations
                            
                        tools.append(tool_info)
                    
                    return tools
                    
        except Exception as e:
            logger.error(f"Failed to connect to MCP server: {e}")
            raise Exception("Could not connect to MCP servers")

    def set_jwt_token(self, jwt_token: str):
        """Update the JWT token for this client."""
        self.jwt_token = jwt_token
        if jwt_token:
            logger.info(f"MCP Client JWT token updated: {len(jwt_token)} characters")
        else:
            logger.info("MCP Client JWT token cleared")
