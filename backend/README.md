# Supply Chain Agent API Backend

This is the Python FastAPI backend for the Supply Chain Agent system.

## Features

- **Authentication**: JWT-based authentication system
- **Agent Management**: Simulated supply chain agent workflows
- **Optimization**: Supply chain optimization requests and progress tracking
- **Real-time Updates**: Progress tracking for optimization workflows

## API Endpoints

### Authentication
- `POST /auth/login` - Login with username/password
- `POST /auth/refresh` - Refresh JWT token
- `GET /auth/me` - Get current user info
- `POST /auth/logout` - Logout

### Agents
- `GET /agents/status` - Get all agent statuses
- `GET /agents/status/{agent_id}` - Get specific agent status
- `GET /agents/activities` - Get agent activities
- `POST /agents/start` - Start agent workflow
- `DELETE /agents/activities` - Clear activities

### Optimization
- `POST /optimization/start` - Start optimization
- `GET /optimization/progress/{request_id}` - Get progress
- `GET /optimization/results/{request_id}` - Get results
- `GET /optimization/all` - Get all optimizations
- `DELETE /optimization/clear` - Clear optimizations

## Setup

1. **Install uv** (if not already installed):
   ```bash
   pip install uv
   ```

2. **Run the server with uv**:
   ```bash
   cd backend
   uv run run_server.py
   ```

   Or run the app module directly:
   ```bash
   uv run -m app.main
   ```

   Or with uvicorn directly:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Access the API**:
   - API: http://localhost:8000
   - Interactive docs: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

## Testing

### Login
```bash
curl -X POST "http://localhost:8000/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "christian", "password": "password123"}'
```

### Start Optimization
```bash
# First get a token from login
TOKEN="your-jwt-token-here"

curl -X POST "http://localhost:8000/optimization/start" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"optimization_type": "laptop_supply_chain"}'
```

## Development

The backend uses:
- **FastAPI**: Modern, fast web framework
- **Pydantic**: Data validation and serialization
- **JWT**: Authentication tokens
- **Async/Await**: For handling concurrent requests

## Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration settings
│   ├── models.py            # Pydantic data models
│   ├── api/                 # API routes
│   │   ├── __init__.py
│   │   ├── auth.py          # Authentication routes
│   │   ├── agents.py        # Agent management routes
│   │   └── optimization.py  # Optimization routes
│   └── services/            # Business logic
│       ├── __init__.py
│       ├── auth_service.py  # Authentication service
│       ├── agent_service.py # Agent workflow service
│       └── optimization_service.py # Optimization service
├── requirements.txt
├── run.py                   # Startup script
└── README.md
```
