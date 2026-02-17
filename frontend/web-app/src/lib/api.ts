import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3005';

// Create axios instance with default configuration
export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for authentication
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = typeof window !== 'undefined' ? localStorage.getItem('auth_token') : null;
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized access
      if (typeof window !== 'undefined') {
        localStorage.removeItem('auth_token');
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// Service-specific API functions
export const lldapApi = {
  getUsers: (params?: { limit?: number; offset?: number }) =>
    api.get('/api/lldap/users', { params }),
  
  getUser: (userId: string) =>
    api.get(`/api/lldap/users/${userId}`),
  
  searchUsers: (query: string) =>
    api.get('/api/lldap/users/search', { params: { q: query } }),
  
  getGroups: () =>
    api.get('/api/lldap/groups'),
  
  getUserGroups: (userId: string) =>
    api.get(`/api/lldap/users/${userId}/groups`),
  
  getStats: () =>
    api.get('/api/lldap/stats'),
  
  getStatus: () =>
    api.get('/api/lldap/status'),
};

export const prometheusApi = {
  query: (query: string) =>
    api.get('/api/prometheus/query', { params: { query } }),
  
  queryRange: (query: string, start: number, end: number, step: string) =>
    api.get('/api/prometheus/query_range', { params: { query, start, end, step } }),
  
  getKPIs: (timeRange?: string) =>
    api.get('/api/prometheus/kpis', { params: { timeRange } }),
  
  getServiceMetrics: () =>
    api.get('/api/prometheus/service-metrics'),
  
  getSystemMetrics: () =>
    api.get('/api/prometheus/system-metrics'),
  
  getDashboardData: (timeRange?: string) =>
    api.get('/api/prometheus/dashboard-data', { params: { timeRange } }),
  
  getTimeseries: (query: string, start?: number, end?: number, step?: string) =>
    api.get('/api/prometheus/timeseries', { params: { query, start, end, step } }),
  
  getStatus: () =>
    api.get('/api/prometheus/status'),
};

export const grafanaApi = {
  getDashboards: () =>
    api.get('/api/grafana/dashboards'),
  
  getOpenDirectoryDashboards: () =>
    api.get('/api/grafana/dashboards/opendirectory'),
  
  getDashboard: (uid: string) =>
    api.get(`/api/grafana/dashboards/uid/${uid}`),
  
  getDashboardEmbedUrl: (uid: string, options?: any) =>
    api.get(`/api/grafana/embed/dashboard/${uid}`, { params: options }),
  
  getPanelEmbedUrl: (uid: string, panelId: number, options?: any) =>
    api.get(`/api/grafana/embed/panel/${uid}/${panelId}`, { params: options }),
  
  getStatus: () =>
    api.get('/api/grafana/status'),
  
  setupOpenDirectory: () =>
    api.post('/api/grafana/setup/opendirectory'),
};

export const vaultApi = {
  getSecrets: (path?: string) =>
    api.get('/api/vault/secrets', { params: { path } }),
  
  getSecret: (path: string) =>
    api.get(`/api/vault/secrets/${path}`),
  
  putSecret: (path: string, data: Record<string, any>) =>
    api.put(`/api/vault/secrets/${path}`, { data }),
  
  deleteSecret: (path: string) =>
    api.delete(`/api/vault/secrets/${path}`),
  
  getServiceCredentials: (service: string) =>
    api.get(`/api/vault/opendirectory/services/${service}/credentials`),
  
  storeServiceCredentials: (service: string, credentials: Record<string, string>) =>
    api.put(`/api/vault/opendirectory/services/${service}/credentials`, { credentials }),
  
  getAPIKey: (keyName: string) =>
    api.get(`/api/vault/opendirectory/api-keys/${keyName}`),
  
  storeAPIKey: (keyName: string, apiKey: string, metadata?: Record<string, any>) =>
    api.put(`/api/vault/opendirectory/api-keys/${keyName}`, { apiKey, metadata }),
  
  getHealth: () =>
    api.get('/api/vault/sys/health'),
  
  getStatus: () =>
    api.get('/api/vault/status'),
};

export const healthApi = {
  getOverallHealth: () =>
    api.get('/health'),
  
  getLLDAPHealth: () =>
    api.get('/health/lldap'),
  
  getGrafanaHealth: () =>
    api.get('/health/grafana'),
  
  getPrometheusHealth: () =>
    api.get('/health/prometheus'),
  
  getVaultHealth: () =>
    api.get('/health/vault'),
};

// Utility functions
export const formatError = (error: any): string => {
  if (error.response?.data?.error) {
    return error.response.data.error;
  }
  if (error.message) {
    return error.message;
  }
  return 'An unexpected error occurred';
};

export default api;