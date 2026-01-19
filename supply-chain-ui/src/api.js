const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000';

class ApiService {
  constructor() {
    this.baseURL = API_BASE_URL;
    this.keycloak = null;
  }

  setKeycloak(keycloakInstance) {
    this.keycloak = keycloakInstance;
  }

  getToken() {
    if (this.keycloak && this.keycloak.token) {
      return this.keycloak.token;
    }
    return null;
  }

  async refreshTokenIfNeeded() {
    if (this.keycloak) {
      try {
        await this.keycloak.updateToken(70);
        return true;
      } catch (error) {
        console.error('Token refresh failed:', error);
        return false;
      }
    }
    return false;
  }

  async getHeaders() {
    const headers = {
      'Content-Type': 'application/json',
    };
    
    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    // Add ID token for agent-to-agent authentication if available
    if (this.keycloak && this.keycloak.idToken) {
      headers['X-ID-Token'] = this.keycloak.idToken;
    }
    
    return headers;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const headers = await this.getHeaders();
    const config = {
      headers,
      ...options,
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  // Authentication endpoints - now handled by Keycloak
  async getCurrentUser() {
    return await this.request('/auth/me');
  }

  // Agent endpoints
  async getAgentStatus() {
    return await this.request('/agents/status');
  }

  async getAgentActivities() {
    return await this.request('/agents/activities');
  }

  // Optimization endpoints
  async startOptimization(requestData) {
    return await this.request('/optimization/start', {
      method: 'POST',
      body: JSON.stringify(requestData),
    });
  }

  async getOptimizationProgress(requestId) {
    return await this.request(`/optimization/progress/${requestId}`);
  }

  async getOptimizationResults(requestId) {
    return await this.request(`/optimization/${requestId}/results`);
  }
}

const apiService = new ApiService();
export default apiService;
