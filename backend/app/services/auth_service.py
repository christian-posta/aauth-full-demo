import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict
from app.config import settings

class AuthService:
    def __init__(self):
        self.secret_key = settings.secret_key
        self.algorithm = settings.algorithm
        self.access_token_expire_minutes = settings.access_token_expire_minutes
        
        # Mock user database
        self.users = {
            "christian": {
                "id": "christian",
                "username": "christian",
                "email": "christian.martinez@acmecorp.com",
                "role": "IT Administrator",
                "is_active": True,
                "password": "password123"  # In real app, this would be hashed
            }
        }
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user with username and password"""
        user = self.users.get(username)
        if user and user["password"] == password:
            return {k: v for k, v in user.items() if k != "password"}
        return None
    
    def create_access_token(self, data: Dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.PyJWTError:
            return None
    
    def get_current_user(self, token: str) -> Optional[Dict]:
        """Get current user from token"""
        payload = self.verify_token(token)
        if payload:
            username = payload.get("sub")
            if username in self.users:
                user = self.users[username]
                return {k: v for k, v in user.items() if k != "password"}
        return None

# Global instance
auth_service = AuthService()
