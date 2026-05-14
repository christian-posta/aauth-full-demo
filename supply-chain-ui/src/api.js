const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000';

class ApiService {
  constructor() {
    this.baseURL = API_BASE_URL;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
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

  async getCurrentUser() {
    return await this.request('/auth/me');
  }

  async getAgentStatus() {
    return await this.request('/agents/status');
  }

  async getAgentActivities() {
    return await this.request('/agents/activities');
  }

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
    return await this.request(`/optimization/results/${requestId}`);
  }
}

const apiService = new ApiService();
export default apiService;
