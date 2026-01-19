import requests
import jwt
from typing import Optional, Dict
from app.config import settings

class KeycloakService:
    def __init__(self):
        self.server_url = settings.keycloak_url
        self.realm = settings.keycloak_realm
        self.client_id = settings.keycloak_client_id
        self.public_key = None
        self._load_public_key()
    
    def _load_public_key(self):
        """Load public key from Keycloak"""
        try:
            url = f"{self.server_url}/realms/{self.realm}"
            response = requests.get(url)
            response.raise_for_status()
            realm_info = response.json()
            self.public_key = f"-----BEGIN PUBLIC KEY-----\n{realm_info['public_key']}\n-----END PUBLIC KEY-----"
            print(f"Loaded Keycloak public key for realm: {self.realm}")
        except Exception as e:
            print(f"Failed to load Keycloak public key: {e}")
            print(f"Make sure Keycloak is running at {self.server_url}")
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token from Keycloak"""
        try:
            if not self.public_key:
                print("No public key available for token verification")
                return None
            
            print(f"Attempting to verify token with public key: {self.public_key[:100]}...")
            print(f"Token to verify: {token[:50]}...")
            
            # First, let's decode the token without verification to see what algorithm it claims to use
            try:
                unverified_payload = jwt.decode(token, options={"verify_signature": False})
                print(f"Unverified token payload: {unverified_payload}")
                print(f"Token algorithm: {unverified_payload.get('alg', 'unknown')}")
            except Exception as e:
                print(f"Failed to decode unverified token: {e}")
            
            # Decode and verify the JWT token
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=['RS256'],
                audience='account',
                options={'verify_aud': False}  # Allow any audience for now
            )
            
            print(f"Token verified successfully for user: {payload.get('preferred_username', 'unknown')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            print("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f"Invalid token: {e}")
            return None
        except Exception as e:
            print(f"Token verification failed: {e}")
            print(f"Exception type: {type(e)}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_user_info(self, token: str) -> Optional[Dict]:
        """Get user info from Keycloak"""
        try:
            url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/userinfo"
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            user_info = response.json()
            print(f"Retrieved user info for: {user_info.get('preferred_username', 'unknown')}")
            return user_info
        except Exception as e:
            print(f"Failed to get user info: {e}")
            return None
    
    def refresh_public_key(self):
        """Refresh the public key (useful if Keycloak restarts)"""
        print("Refreshing Keycloak public key...")
        self._load_public_key()

    def get_id_token(self, access_token: str) -> Optional[str]:
        """Get ID token from Keycloak using the access token"""
        try:
            # Use the token introspection endpoint to get token info
            url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/userinfo"
            headers = {'Authorization': f'Bearer {access_token}'}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            # For now, we'll use the access token as the ID token
            # In a production system, you might want to implement proper token exchange
            # or configure the client to request ID tokens explicitly
            print(f"Using access token as ID token for agent authentication")
            return access_token
            
        except Exception as e:
            print(f"Failed to get ID token: {e}")
            return None

# Global instance
keycloak_service = KeycloakService()
