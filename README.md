# Supply Chain Agent with AAuth for Agent Identity and Authorization


## 🏗️ Architecture

- **Frontend**: React with Tailwind CSS
- **Backend**: Python FastAPI with Keycloak OIDC and AAuth integration
- **Agents**: Simulated supply chain optimization workflows
- **Authentication**: Keycloak OIDC and AAuth


## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Node.js 16+
- npm or yarn
- Keycloak 26.2.5 running locally

### 1. Setup Virtual Environment
Each project has its own virtual env. Can set up like this:

```bash
# Backend
cd backend && \
python3.12 -m venv .venv && \
source .venv/bin/activate && \
pip install uv && \
uv pip install -e . && \
cd ..

# Market Analysis Agent
cd market-analysis-agent && \
python3.12 -m venv .venv && \
source .venv/bin/activate && \
pip install uv && \
uv pip install -e . && \
cd ..

# Supply Chain Agent
cd supply-chain-agent && \
python3.12 -m venv .venv && \
source .venv/bin/activate && \
pip install uv && \
uv pip install -e . && \
cd ..

# Frontend
cd supply-chain-ui && \
npm install && \
cd ..
```

### 2. Keycloak Setup

We will need to use Keycloak with AAuth support. 

**Configure Keycloak:**
1. Access Admin Console: http://localhost:8080
2. Create realm: `aauth-test`
3. Create client: `supply-chain-ui`
4. Create user: `mcp-user` with password `user123`


### 3. Backend Setup
```bash
# Install Python dependencies
cd backend
pip install -r requirements.txt

# Start the backend server
python run.py
```

The backend will be available at:
- **API**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 4. Frontend Setup
```bash
# In a new terminal, install frontend dependencies
cd supply-chain-ui
npm install

# Copy environment template
cp env.template .env

# Start the React development server
npm start
```

The frontend will be available at:
- **App**: http://localhost:3000

## 🔐 Authentication

**Keycloak Integration:**
- **Realm**: `mcp-realm`
- **Client**: `supply-chain-ui`
- **Test User**: `christian` / `password123`

## 🧪 Testing

### Test Backend API
```bash
# From project root with activated virtual environment
python test_api.py
```

### Test Frontend Build
```bash
cd supply-chain-ui
npm run build
```

## 📁 Project Structure

```
agent-auth-istio-keycloak/
├── .venv/                    # Python virtual environment
├── backend/                  # Python FastAPI backend
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py          # FastAPI application
│   │   ├── config.py        # Configuration settings
│   │   ├── models.py        # Pydantic data models
│   │   ├── api/             # API routes
│   │   │   ├── auth.py      # Authentication endpoints
│   │   │   ├── agents.py    # Agent management
│   │   │   └── optimization.py # Optimization endpoints
│   │   └── services/        # Business logic
│   │       ├── auth_service.py
│   │       ├── agent_service.py
│   │       └── optimization_service.py
│   ├── requirements.txt
│   ├── run.py               # Startup script
│   └── README.md
├── supply-chain-ui/          # React frontend
│   ├── src/
│   │   ├── components/      # React components
│   │   │   └── Login.js     # Login component
│   │   ├── hooks/           # Custom React hooks
│   │   │   ├── useAuth.js   # Authentication hook
│   │   │   └── useOptimization.js # Optimization hook
│   │   ├── api.js           # API service
│   │   ├── App.js           # Main application
│   │   └── index.js         # Entry point
│   ├── package.json
│   ├── tailwind.config.js   # Tailwind CSS config
│   └── postcss.config.js    # PostCSS config
├── test_api.py              # API testing script
├── .gitignore               # Git ignore rules
└── README.md                # This file
```

## 🔌 API Endpoints

### Authentication
- `POST /auth/login` - Login with username/password
- `POST /auth/refresh` - Refresh JWT token
- `GET /auth/me` - Get current user info
- `POST /auth/logout` - Logout

### Agents
- `GET /agents/status` - Get all agent statuses
- `GET /agents/status/{agent_id}` - Get specific agent status
- `GET /agents/activities` - Get agent activities
- `DELETE /agents/activities` - Clear activities

### Optimization
- `POST /optimization/start` - Start optimization
- `GET /optimization/progress/{request_id}` - Get progress
- `GET /optimization/results/{request_id}` - Get results
- `GET /optimization/all` - Get all optimizations

## 🎯 Features

### Frontend
- **Modern UI**: Built with React and Tailwind CSS
- **Real-time Updates**: Live progress tracking
- **Responsive Design**: Works on all device sizes
- **Error Handling**: Comprehensive error states
- **Loading States**: Smooth user experience

### Backend
- **FastAPI**: High-performance Python web framework
- **JWT Authentication**: Secure token-based auth
- **Async Processing**: Non-blocking agent workflows
- **Data Validation**: Pydantic models
- **Auto-documentation**: Interactive API docs

### Agent Workflow
- **Supply Chain Optimizer**: Main orchestrator
- **Inventory Service**: Stock level analysis
- **Financial Service**: Budget and cost analysis
- **Market Analysis**: Demand trend analysis
- **Vendor Service**: Supplier performance evaluation
- **Procurement Agent**: Purchase recommendations

## 🚀 Development

### Backend Development
```bash
cd backend
source ../.venv/bin/activate

# Run with auto-reload
python run.py

# Or with uvicorn directly
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Development
```bash
cd supply-chain-ui
npm start
```

### Adding New Features
1. **Backend**: Add new models, services, and API endpoints
2. **Frontend**: Create new components and hooks
3. **Integration**: Update API service and state management

## 🐛 Troubleshooting

### Common Issues

**Backend won't start:**
- Ensure virtual environment is activated
- Check if port 8000 is available
- Verify all dependencies are installed

**Frontend can't connect to backend:**
- Ensure backend is running on port 8000
- Check CORS configuration
- Verify API_BASE_URL in api.js

**Authentication fails:**
- Check backend logs for errors
- Verify JWT secret key
- Ensure user credentials are correct

### Logs
- **Backend**: Check terminal where `python run.py` is running
- **Frontend**: Check browser console and terminal

## 🔮 Future Enhancements

- **Real Agent Integration**: Connect to actual supply chain systems
- **Database**: Persistent storage for optimization history
- **WebSocket**: Real-time bidirectional communication
- **Kubernetes**: Container orchestration
- **Istio**: Service mesh integration
- **Keycloak**: Enterprise SSO integration
- **Monitoring**: Metrics and observability
- **Testing**: Comprehensive test suite

## 📚 Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://reactjs.org/docs/)
- [Tailwind CSS](https://tailwindcss.com/)
- [JWT Authentication](https://jwt.io/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is for educational and demonstration purposes.
