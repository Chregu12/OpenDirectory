import axios from 'axios';

// Empty string = relative URLs → requests go through Next.js rewrites (cluster-internal proxy)
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? '';

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

// Authentication API
export const authApi = {
  login: (credentials: { username: string; password: string; mfaCode?: string }) =>
    api.post('/api/auth/login', credentials),
  
  logout: () =>
    api.post('/api/auth/logout'),
  
  register: (userData: any) =>
    api.post('/api/auth/register', userData),
  
  refreshToken: (refreshToken: string) =>
    api.post('/api/auth/refresh', { refreshToken }),
  
  validateToken: (token: string) =>
    api.post('/api/auth/validate', { token }),
  
  getProfile: () =>
    api.get('/api/auth/profile'),
  
  updateProfile: (data: any) =>
    api.put('/api/auth/profile', data),
  
  changePassword: (data: { currentPassword: string; newPassword: string }) =>
    api.post('/api/auth/change-password', data),
  
  setupMFA: () =>
    api.post('/api/auth/mfa/setup'),
  
  verifyMFA: (code: string) =>
    api.post('/api/auth/mfa/verify', { code }),
  
  getTrustScore: () =>
    api.get('/api/auth/trust-score'),
  
  getSessions: () =>
    api.get('/api/auth/sessions'),
  
  revokeSession: (sessionId: string) =>
    api.delete(`/api/auth/sessions/${sessionId}`),
};

// Network Infrastructure API
export const networkApi = {
  // DNS Management
  getDNSZones: () =>
    api.get('/api/network/dns/zones'),
  
  createDNSZone: (zoneData: any) =>
    api.post('/api/network/dns/zones', zoneData),
  
  getDNSRecords: (zone?: string, type?: string) =>
    api.get('/api/network/dns/records', { params: { zone, type } }),
  
  createDNSRecord: (recordData: any) =>
    api.post('/api/network/dns/records', recordData),
  
  deleteDNSRecord: (recordId: string) =>
    api.delete(`/api/network/dns/records/${recordId}`),
  
  // DHCP Management
  getDHCPScopes: () =>
    api.get('/api/network/dhcp/scopes'),
  
  createDHCPScope: (scopeData: any) =>
    api.post('/api/network/dhcp/scopes', scopeData),
  
  updateDHCPScope: (scopeId: string, scopeData: any) =>
    api.put(`/api/network/dhcp/scopes/${scopeId}`, scopeData),
  
  getDHCPLeases: () =>
    api.get('/api/network/dhcp/leases'),
  
  getDHCPReservations: () =>
    api.get('/api/network/dhcp/reservations'),
  
  createDHCPReservation: (reservationData: any) =>
    api.post('/api/network/dhcp/reservations', reservationData),
  
  // File Shares
  getFileShares: () =>
    api.get('/api/network/shares'),
  
  createFileShare: (shareData: any) =>
    api.post('/api/network/shares', shareData),
  
  updateFileShare: (shareId: string, shareData: any) =>
    api.put(`/api/network/shares/${shareId}`, shareData),
  
  deleteFileShare: (shareId: string) =>
    api.delete(`/api/network/shares/${shareId}`),
  
  getSharePermissions: (shareId: string) =>
    api.get(`/api/network/shares/${shareId}/permissions`),
  
  updateSharePermissions: (shareId: string, permissions: any) =>
    api.put(`/api/network/shares/${shareId}/permissions`, permissions),
  
  // Network Discovery
  startNetworkScan: (range: string, methods?: string[]) =>
    api.post('/api/network/discovery/scan', { range, methods }),
  
  getDiscoveredDevices: () =>
    api.get('/api/network/discovery/devices'),
  
  getNetworkTopology: () =>
    api.get('/api/network/discovery/topology'),
  
  // Network Monitoring
  getNetworkStatus: () =>
    api.get('/api/network/monitoring/status'),
  
  getNetworkMetrics: (period?: string, devices?: string[]) =>
    api.get('/api/network/monitoring/metrics', { params: { period, devices } }),
  
  getNetworkAlerts: (severity?: string, acknowledged?: boolean) =>
    api.get('/api/network/monitoring/alerts', { params: { severity, acknowledged } }),
  
  getBandwidthUsage: (networkInterface?: string, period?: string) =>
    api.get('/api/network/monitoring/bandwidth', { params: { interface: networkInterface, period } }),
};

// Device Management API
export const deviceApi = {
  getDevices: () =>
    api.get('/api/devices'),
  
  getDevice: (deviceId: string) =>
    api.get(`/api/devices/${deviceId}`),
  
  enrollDevice: (enrollmentData: any) =>
    api.post('/api/devices/enroll', enrollmentData),

  generateEnrollmentToken: () =>
    api.post('/api/devices/enroll/token', {}),
  
  updateDevice: (deviceId: string, updates: any) =>
    api.put(`/api/devices/${deviceId}`, updates),
  
  deleteDevice: (deviceId: string) =>
    api.delete(`/api/devices/${deviceId}`),
  
  getDevicePolicies: (deviceId: string) =>
    api.get(`/api/devices/${deviceId}/policies`),
  
  applyPolicy: (deviceId: string, policyId: string) =>
    api.post(`/api/devices/${deviceId}/policies`, { policyId }),
  
  getDeviceCompliance: (deviceId: string) =>
    api.get(`/api/devices/${deviceId}/compliance`),
  
  syncDevice: (deviceId: string) =>
    api.post(`/api/devices/${deviceId}/sync`),
};

// Printer Management API
export const printerApi = {
  getPrinters: () =>
    api.get('/api/printer/printers'),
  
  addPrinter: (printerData: any) =>
    api.post('/api/printer/printers', printerData),
  
  deletePrinter: (printerId: string) =>
    api.delete(`/api/printer/printers/${printerId}`),
  
  getPrintJobs: () =>
    api.get('/api/printer/jobs'),
  
  submitPrintJob: (jobData: any) =>
    api.post('/api/printer/jobs', jobData),
  
  cancelPrintJob: (jobId: string) =>
    api.delete(`/api/printer/jobs/${jobId}`),
  
  getPrintQuotas: () =>
    api.get('/api/printer/quotas'),
  
  updatePrintQuota: (userId: string, quota: number) =>
    api.put(`/api/printer/quotas/${userId}`, { quota }),
  
  discoverPrinters: () =>
    api.post('/api/printer/discover'),
  
  // Scanner functions
  getScanners: () =>
    api.get('/api/printer/scanners'),
  
  startScan: (scannerId: string, settings: any) =>
    api.post(`/api/printer/scanners/${scannerId}/scan`, settings),
  
  getScanHistory: () =>
    api.get('/api/printer/scans'),
};

// Configuration API
export const configApi = {
  getModules: () =>
    api.get('/api/config/modules'),
  
  getModule: (moduleId: string) =>
    api.get(`/api/config/modules/${moduleId}`),
  
  updateModule: (moduleId: string, config: any) =>
    api.post(`/api/config/modules/${moduleId}`, config),
  
  getFeatures: () =>
    api.get('/api/config/features'),
  
  getSettings: () =>
    api.get('/api/config/settings'),
  
  updateSettings: (moduleId: string, settings: any) =>
    api.put(`/api/config/settings/${moduleId}`, settings),
  
  exportConfig: () =>
    api.get('/api/config/export'),
  
  importConfig: (config: any) =>
    api.post('/api/config/import', config),
  
  getSetupStatus: () =>
    api.get('/api/config/setup-status'),

  getAvailableModules: () =>
    api.get('/api/config/wizard/available-modules'),

  runSetupWizard: (setupData: any) =>
    api.post('/api/config/wizard/setup', setupData),
};

// System Resources API
export const systemApi = {
  getResources: () =>
    api.get('/api/system/resources'),
};

// Monitoring & Analytics API
export const monitoringApi = {
  getSystemStatus: () =>
    api.get('/api/monitoring/status'),

  getMetrics: (period?: string) =>
    api.get('/api/monitoring/metrics', { params: { period } }),

  getAlerts: (severity?: string) =>
    api.get('/api/monitoring/alerts', { params: { severity } }),

  acknowledgeAlert: (alertId: string) =>
    api.post(`/api/monitoring/alerts/${alertId}/acknowledge`),

  getAnalytics: () =>
    api.get('/api/monitoring/analytics'),

  getPredictions: () =>
    api.get('/api/monitoring/predictions'),

  configureAlerts: (rules: any) =>
    api.post('/api/monitoring/alerts/configure', rules),

  configureNotifications: (channels: any) =>
    api.post('/api/monitoring/notifications', channels),
};

// Service-specific API functions (Legacy - now proxied through gateway)
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

  // User & Group CRUD
  createUser: (userData: { email: string; displayName: string; firstName: string; lastName: string; password: string; groups?: string[] }) =>
    api.post('/api/lldap/users', userData),

  createUsers: (users: Array<{ email: string; displayName: string; firstName: string; lastName: string; password: string; groups?: string[] }>) =>
    api.post('/api/lldap/users/bulk', { users }),

  createGroup: (groupData: { name: string; description?: string }) =>
    api.post('/api/lldap/groups', groupData),

  updateGroupMembers: (groupId: string, members: string[]) =>
    api.put(`/api/lldap/groups/${groupId}/members`, { members }),
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
  
  getDetailedHealth: () =>
    api.get('/health/detailed'),
  
  getServiceHealth: (serviceName: string) =>
    api.get(`/health/service/${serviceName}`),
  
  checkReadiness: () =>
    api.get('/health/ready'),
  
  checkLiveness: () =>
    api.get('/health/live'),
  
  // Individual service health checks
  getLLDAPHealth: () =>
    api.get('/health/service/lldap'),
  
  getGrafanaHealth: () =>
    api.get('/health/service/grafana'),
  
  getPrometheusHealth: () =>
    api.get('/health/service/prometheus'),
  
  getVaultHealth: () =>
    api.get('/health/service/vault'),
  
  getNetworkHealth: () =>
    api.get('/health/service/network-infrastructure'),
  
  getPrinterHealth: () =>
    api.get('/health/service/printer-service'),
  
  getDeviceHealth: () =>
    api.get('/health/service/device-service'),
};

// API Gateway Service Registry
export const gatewayApi = {
  getServices: () =>
    api.get('/api/services'),
  
  getServiceHealth: (serviceId: string) =>
    api.get(`/api/services/${serviceId}/health`),
  
  getRoutes: () =>
    api.get('/api/gateway/routes'),
  
  getStats: () =>
    api.get('/api/gateway/stats'),
};

// Security API
export const securityApi = {
  getThreatIntel: () =>
    api.get('/api/security/threats'),

  getPAMSessions: () =>
    api.get('/api/security/pam/sessions'),

  getDLPPolicies: () =>
    api.get('/api/security/dlp/policies'),

  createDLPPolicy: (policy: any) =>
    api.post('/api/security/dlp/policies', policy),

  getSecurityAlerts: () =>
    api.get('/api/security/alerts'),

  getComplianceStatus: () =>
    api.get('/api/security/compliance'),

  // Antivirus / ClamAV
  scanAntivirus: (config: { type: string; targets?: string[] }) =>
    api.post('/api/antivirus/scan', config),

  scheduleAntivirusScan: (schedule: any) =>
    api.post('/api/antivirus/schedule', schedule),

  getAntivirusSchedules: () =>
    api.get('/api/antivirus/schedules'),

  updateSignatures: () =>
    api.post('/api/antivirus/signatures/update'),

  getAntivirusStats: () =>
    api.get('/api/antivirus/statistics'),

  getAntivirusDashboard: () =>
    api.get('/api/antivirus/dashboard'),

  // Compliance
  getComplianceFrameworks: () =>
    api.get('/api/compliance/frameworks'),

  createComplianceBaseline: (baseline: any) =>
    api.post('/api/compliance/baselines', baseline),

  getComplianceBaselines: () =>
    api.get('/api/compliance/baselines'),

  evaluateCompliance: (deviceId: string) =>
    api.post(`/api/compliance/evaluate/${deviceId}`),

  getFleetComplianceScore: () =>
    api.get('/api/compliance/score/fleet'),

  // Security setup wizard
  runSecuritySetup: (config: any) =>
    api.post('/api/security/setup', config),
};

// Backup & DR API
export const backupApi = {
  getBackups: () =>
    api.get('/api/backup/backups'),

  createBackup: (backupData: any) =>
    api.post('/api/backup/backups', backupData),

  restoreBackup: (backupId: string) =>
    api.post(`/api/backup/backups/${backupId}/restore`),

  getBackupStatus: () =>
    api.get('/api/backup/status'),

  getDRStatus: () =>
    api.get('/api/dr/status'),

  configureSchedule: (schedule: any) =>
    api.post('/api/backup/schedule', schedule),

  configureStorage: (storage: any) =>
    api.post('/api/backup/storage', storage),

  validateBackup: (backupId: string) =>
    api.post(`/api/backup/backups/${backupId}/validate`),

  getRecoveryPoints: () =>
    api.get('/api/backup/recovery-points'),
};

// Automation API
export const automationApi = {
  getWorkflows: () =>
    api.get('/api/workflows'),
  
  createWorkflow: (workflowData: any) =>
    api.post('/api/workflows', workflowData),
  
  executeWorkflow: (workflowId: string) =>
    api.post(`/api/workflows/${workflowId}/execute`),
  
  getScheduledTasks: () =>
    api.get('/api/automation/tasks'),
  
  createScheduledTask: (taskData: any) =>
    api.post('/api/automation/tasks', taskData),
};

// Container & Cloud API
export const containerApi = {
  getContainers: () =>
    api.get('/api/containers'),
  
  getKubernetesClusters: () =>
    api.get('/api/k8s/clusters'),
  
  getDockerImages: () =>
    api.get('/api/docker/images'),
  
  deployApp: (appData: any) =>
    api.post('/api/containers/deploy', appData),
};

// AI & ML API
export const aiApi = {
  getPredictions: () =>
    api.get('/api/ai/predictions'),
  
  getAnomalies: () =>
    api.get('/api/ai/anomalies'),
  
  getRecommendations: () =>
    api.get('/api/ai/recommendations'),
  
  trainModel: (modelData: any) =>
    api.post('/api/ai/models/train', modelData),
};

// App Store API
export const appStoreApi = {
  // Admin - Catalog
  getCatalog: (params?: { search?: string; category?: string; platform?: string; tags?: string; enabled?: string; page?: number; limit?: number }) =>
    api.get('/api/store/catalog', { params }),

  createApp: (appData: any) =>
    api.post('/api/store/catalog', appData),

  updateApp: (appId: string, updates: any) =>
    api.put(`/api/store/catalog/${appId}`, updates),

  deleteApp: (appId: string) =>
    api.delete(`/api/store/catalog/${appId}`),

  assignApp: (appId: string, data: { targets: Array<{ target_type: string; target_id: string; target_name?: string }>; install_type?: string }) =>
    api.post(`/api/store/catalog/${appId}/assign`, data),

  removeAssignment: (appId: string, assignId: string) =>
    api.delete(`/api/store/catalog/${appId}/assign/${assignId}`),

  getAssignments: (appId: string) =>
    api.get(`/api/store/catalog/${appId}/assignments`),

  getCategories: () =>
    api.get('/api/store/categories'),

  seedCatalog: () =>
    api.post('/api/store/catalog/seed'),

  // Client / Self-Service
  getAvailable: (deviceId: string) =>
    api.get(`/api/store/available/${deviceId}`),

  getRequired: (deviceId: string) =>
    api.get(`/api/store/required/${deviceId}`),

  getInstalled: (deviceId: string) =>
    api.get(`/api/store/installed/${deviceId}`),

  requestInstall: (data: { appId: string; deviceId: string }) =>
    api.post('/api/store/install', data),

  requestUninstall: (data: { appId: string; deviceId: string }) =>
    api.post('/api/store/uninstall', data),

  getInstallStatus: (installId: string) =>
    api.get(`/api/store/install/${installId}/status`),

  // Reporting
  getHistory: (params?: { deviceId?: string; appId?: string; status?: string; page?: number; limit?: number }) =>
    api.get('/api/store/history', { params }),

  getLicenses: () =>
    api.get('/api/store/licenses'),

  getStats: () =>
    api.get('/api/store/stats'),
};

// Compliance API
export const complianceApi = {
  getStatus: () =>
    api.get('/api/compliance/dashboard'),

  getBaselines: () =>
    api.get('/api/compliance/baselines'),

  getWaivers: () =>
    api.get('/api/compliance/waivers'),

  deleteWaiver: (waiverId: string) =>
    api.delete(`/api/compliance/waivers/${waiverId}`),

  triggerScan: (deviceId: string) =>
    api.post(`/api/compliance/evaluate/${deviceId}`),

  generateReport: (options: any) =>
    api.post('/api/compliance/reports/generate', options),

  getFleetScore: () =>
    api.get('/api/compliance/score/fleet'),
};

// Policy API
export const policyApi = {
  getPolicies: (params?: { type?: string; status?: string; platform?: string; page?: number; limit?: number }) =>
    api.get('/api/policies', { params }),

  getPolicy: (id: string) =>
    api.get(`/api/policies/${id}`),

  createPolicy: (data: any) =>
    api.post('/api/policies', data),

  updatePolicy: (id: string, data: any) =>
    api.put(`/api/policies/${id}`, data),

  deletePolicy: (id: string) =>
    api.delete(`/api/policies/${id}`),

  getTemplates: () =>
    api.get('/api/policies/templates'),

  createFromTemplate: (data: any) =>
    api.post('/api/policies/from-template', data),

  assignPolicy: (id: string, targets: any) =>
    api.post(`/api/policies/${id}/assign`, targets),

  linkPolicy: (id: string, link: any) =>
    api.post(`/api/policies/${id}/link`, link),

  activatePolicy: (id: string) =>
    api.post(`/api/policies/${id}/activate`),

  deactivatePolicy: (id: string) =>
    api.post(`/api/policies/${id}/deactivate`),

  getConflicts: () =>
    api.get('/api/policies/conflicts'),

  compilePolicy: (id: string, platform: string) =>
    api.post(`/api/policies/${id}/compile/${platform}`),
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