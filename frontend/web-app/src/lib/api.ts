import axios from 'axios';
import { getAccessToken } from './auth';

// Empty string = relative URLs → requests go through Next.js rewrites (cluster-internal proxy)
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? '';

// Create axios instance with default configuration
export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  withCredentials: true, // Send httpOnly auth cookie automatically
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: attach the PKCE access token (localStorage, see
// lib/auth.ts) as a Bearer header. Several backend services (e.g.
// device-service) now require OIDC-authenticated requests, and the httpOnly
// cookie sent via withCredentials is not sufficient for those. Mirrors the
// manual buildHeaders() approach in lib/quickActionsApi.ts. Never throws if
// there is no token or we're running outside the browser (SSR) — the header
// is simply omitted and the request proceeds unauthenticated.
api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = getAccessToken();
    if (token) {
      config.headers.set('Authorization', `Bearer ${token}`);
    }
  }
  return config;
});

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      if (typeof window !== 'undefined') {
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

  getDeviceSoftware: (deviceId: string) =>
    api.get(`/api/devices/${deviceId}/software`),

  installSoftware: (deviceId: string, data: { name: string; version: string; category: string }) =>
    api.post(`/api/devices/${deviceId}/software`, data),

  updateSoftware: (deviceId: string, appId: string) =>
    api.post(`/api/devices/${deviceId}/software/${appId}/update`),

  updateAllSoftware: (deviceId: string) =>
    api.post(`/api/devices/${deviceId}/software/update-all`),

  uninstallSoftware: (deviceId: string, appId: string) =>
    api.delete(`/api/devices/${deviceId}/software/${appId}`),

  getDeviceHardware: (deviceId: string) =>
    api.get(`/api/devices/${deviceId}/hardware`),

  getDeviceNetwork: (deviceId: string) =>
    api.get(`/api/devices/${deviceId}/network`),

  getDeviceLogs: (deviceId: string, limit = 50) =>
    api.get(`/api/devices/${deviceId}/logs`, { params: { limit } }),

  getEnrollmentToken: (expiresInHours = 24) =>
    api.post('/api/devices/enrollment-token', { expires_in_hours: expiresInHours }),

  getStammdaten: (deviceId: string) =>
    api.get(`/api/devices/${deviceId}/stammdaten`),

  updateStammdaten: (deviceId: string, data: Record<string, string>) =>
    api.put(`/api/devices/${deviceId}/stammdaten`, data),

  uploadPhoto: (deviceId: string, photoDataUrl: string) =>
    api.post(`/api/devices/${deviceId}/photo`, { photo: photoDataUrl }),

  getPhotoUrl: (deviceId: string) =>
    `/api/devices/${deviceId}/photo`,
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

  probePrinter: (ip: string) =>
    api.post('/api/printer/probe', { ip }),

  testScan: (ip: string, name?: string) =>
    api.post('/api/printer/test-scan', { ip, name }),

  // Scanner functions
  getScanners: () =>
    api.get('/api/printer/scanners'),

  updateScannerProfiles: (scannerId: string, profiles: any[]) =>
    api.put(`/api/printer/scanners/${scannerId}/profiles`, { profiles }),

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
  
  getAvailableModules: () =>
    api.get('/api/config/wizard/available-modules'),
  
  runSetupWizard: (setupData: any) =>
    api.post('/api/config/wizard/setup', setupData),
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
  // Antivirus endpoints → antivirus-protection service (/api/antivirus/*)
  getThreatIntel: () =>
    api.get('/api/antivirus/threats'),

  getThreats: () =>
    api.get('/api/antivirus/threats'),

  getScans: () =>
    api.get('/api/antivirus/scans'),

  getAvDevices: () =>
    api.get('/api/antivirus/devices'),

  getAvStatistics: () =>
    api.get('/api/antivirus/statistics'),

  getAvDashboard: () =>
    api.get('/api/antivirus/dashboard'),

  getQuarantine: () =>
    api.get('/api/antivirus/quarantine'),

  getSignatures: () =>
    api.get('/api/antivirus/signatures'),

  updateSignatures: () =>
    api.post('/api/antivirus/signatures/update', {}),

  startScan: (deviceIds?: string[], scanType?: string) =>
    api.post('/api/antivirus/scan', { deviceIds, scanType: scanType ?? 'quick' }),

  restoreQuarantine: (fileId: string) =>
    api.post(`/api/antivirus/quarantine/${fileId}/restore`, {}),

  deleteQuarantine: (fileId: string) =>
    api.delete(`/api/antivirus/quarantine/${fileId}`),

  // Security scanner endpoints → security-scanner service (/api/scanner/*)
  getComplianceStatus: () =>
    api.get('/api/scanner/findings'),

  getFindings: () =>
    api.get('/api/scanner/findings'),

  getRiskScore: () =>
    api.get('/api/scanner/risk-score'),

  getTrends: () =>
    api.get('/api/scanner/trends'),

  getBenchmarks: () =>
    api.get('/api/scanner/benchmarks'),

  startSecurityScan: (target?: string) =>
    api.post('/api/scanner/scan', { target }),

  getSecurityAlerts: () =>
    api.get('/api/scanner/findings'),

  // Legacy paths kept for other callers
  getPAMSessions: () =>
    api.get('/api/security/pam/sessions'),

  getDLPPolicies: () =>
    api.get('/api/security/dlp/policies'),
};

// Compliance API → compliance-engine service (/api/compliance/*)
// Consumed by ComplianceView (fleet compliance dashboard: baselines,
// per-device scores, violations, waivers, report export).
export const complianceApi = {
  getStatus: () =>
    api.get('/api/compliance/dashboard'),

  getBaselines: () =>
    api.get('/api/compliance/baselines'),

  getWaivers: () =>
    api.get('/api/compliance/waivers'),

  triggerScan: (deviceId: string) =>
    api.post(`/api/compliance/evaluate/${deviceId}`),

  deleteWaiver: (waiverId: string) =>
    api.delete(`/api/compliance/waivers/${waiverId}`),

  generateReport: (params?: Record<string, unknown>) =>
    api.post('/api/compliance/reports/generate', params),
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

// Audit Log API (enterprise-directory service, port 3000)
const DIRECTORY_BASE = process.env.NEXT_PUBLIC_DIRECTORY_URL || '';

export const auditApi = {
  getEvents: (params?: {
    from?: string;
    to?: string;
    actorId?: string;
    targetDn?: string;
    operation?: string;
    category?: string;
    severity?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.from)      query.set('from',      params.from);
    if (params?.to)        query.set('to',        params.to);
    if (params?.actorId)   query.set('actorId',   params.actorId);
    if (params?.targetDn)  query.set('targetDn',  params.targetDn);
    if (params?.operation) query.set('operation', params.operation);
    if (params?.category)  query.set('category',  params.category);
    if (params?.severity)  query.set('severity',  params.severity);
    if (params?.search)    query.set('search',    params.search);
    query.set('limit',  String(params?.limit  ?? 100));
    query.set('offset', String(params?.offset ?? 0));
    return api.get(`${DIRECTORY_BASE}/api/audit/log?${query.toString()}`);
  },

  getActorActivity: (actorId: string, params?: { from?: string; to?: string }) => {
    const query = new URLSearchParams();
    if (params?.from) query.set('from', params.from);
    if (params?.to)   query.set('to',   params.to);
    return api.get(`${DIRECTORY_BASE}/api/audit/actors/${encodeURIComponent(actorId)}/activity?${query.toString()}`);
  },

  getObjectHistory: (dn: string) =>
    api.get(`${DIRECTORY_BASE}/api/audit/objects/${encodeURIComponent(dn)}/history`),

  getStats: () =>
    api.get(`${DIRECTORY_BASE}/api/audit/stats`),

  getIntegrity: () =>
    api.get(`${DIRECTORY_BASE}/api/audit/integrity`),

  getCorrelations: (correlationId: string) =>
    api.get(`${DIRECTORY_BASE}/api/audit/correlations/${correlationId}`),

  exportEvents: (params?: { format?: string; category?: string; severity?: string }) =>
    api.post(`${DIRECTORY_BASE}/api/audit/export`, params),
};

// PIM Sessions API (conditional-access service, port 3007)
const PIM_BASE = process.env.NEXT_PUBLIC_PIM_URL || '';

export const pimSessionsApi = {
  getSessions: () =>
    api.get(`${PIM_BASE}/api/v1/pim/sessions`),

  getSession: (id: string) =>
    api.get(`${PIM_BASE}/api/v1/pim/sessions/${id}`),

  getSessionReplay: (id: string) =>
    api.get(`${PIM_BASE}/api/v1/pim/sessions/${id}/replay`),

  getBreakGlassEvents: () =>
    api.get(`${PIM_BASE}/api/v1/pim/breakglass`),

  requestBreakGlass: (data: { reason: string; systemsAffected: string; estimatedDuration: number }) =>
    api.post(`${PIM_BASE}/api/v1/pim/breakglass/request`, data),

  activateBreakGlass: (id: string) =>
    api.post(`${PIM_BASE}/api/v1/pim/breakglass/${id}/activate`, {}),

  terminateBreakGlass: (id: string) =>
    api.post(`${PIM_BASE}/api/v1/pim/breakglass/${id}/terminate`, {}),
};

// Quick Actions API (port 3950)
const QUICK_ACTIONS_BASE = process.env.NEXT_PUBLIC_QUICK_ACTIONS_URL || '';

export const quickActionsApi = {
  getComplianceSnapshot: () =>
    api.get(`${QUICK_ACTIONS_BASE}/api/quick/compliance/snapshot`),

  deployPolicy: (data: {
    policyId?: string;
    policy_id?: string;
    targetType?: string;
    target_type?: string;
    targetId?: string;
    target_value?: string;
    enforced?: boolean;
    dryRun?: boolean;
    dry_run?: boolean;
  }) =>
    api.post(`${QUICK_ACTIONS_BASE}/api/quick/policies/deploy`, data),

  getDeployment: (id: string) =>
    api.get(`${QUICK_ACTIONS_BASE}/api/quick/policies/deployments/${id}`),
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

// Policy Management API
export const policyApi = {
  getPolicies: () =>
    api.get('/api/policies'),

  getPolicy: (policyId: string) =>
    api.get(`/api/policies/${policyId}`),

  createPolicy: (data: any) =>
    api.post('/api/policies', data),

  updatePolicy: (policyId: string, data: any) =>
    api.put(`/api/policies/${policyId}`, data),

  deletePolicy: (policyId: string) =>
    api.delete(`/api/policies/${policyId}`),

  getOUTree: () =>
    api.get('/api/policies/ou-tree'),
};

// App Store API
export const appStoreApi = {
  getCatalog: (params?: { search?: string; category?: string }) =>
    api.get('/api/store/catalog', { params }),

  getCategories: () =>
    api.get('/api/store/categories'),

  getStats: () =>
    api.get('/api/store/stats'),

  seedCatalog: () =>
    api.post('/api/store/catalog/seed'),

  createApp: (data: any) =>
    api.post('/api/store/catalog', data),

  scanShare: (shareId: string) =>
    api.post(`/api/store/shares/${shareId}/scan`),

  deleteApp: (appId: string) =>
    api.delete(`/api/store/catalog/${appId}`),

  assignApp: (appId: string, data: any) =>
    api.post(`/api/store/catalog/${appId}/assign`, data),

  getAssignments: (appId: string) =>
    api.get(`/api/store/catalog/${appId}/assignments`),

  removeAssignment: (appId: string, assignId: string) =>
    api.delete(`/api/store/catalog/${appId}/assignments/${assignId}`),

  getInstalled: (deviceId: string) =>
    api.get(`/api/store/installed/${deviceId}`),

  requestInstall: (data: { appId: string; deviceId: string }) =>
    api.post('/api/store/install', data),

  requestUninstall: (data: { appId: string; deviceId: string }) =>
    api.post('/api/store/uninstall', data),
};

// Groups & Organisational Units API
export const groupApi = {
  getGroups: () =>
    api.get('/api/groups'),

  createGroup: (data: any) =>
    api.post('/api/groups', data),

  updateGroup: (id: string, data: any) =>
    api.put(`/api/groups/${id}`, data),

  deleteGroup: (id: string) =>
    api.delete(`/api/groups/${id}`),

  getGroup: (id: string) =>
    api.get(`/api/groups/${id}`),

  addMember: (groupId: string, userId: string) =>
    api.post(`/api/groups/${groupId}/members`, { userId }),

  removeMember: (groupId: string, userId: string) =>
    api.delete(`/api/groups/${groupId}/members/${userId}`),

  getOUs: () =>
    api.get('/api/ous'),

  createOU: (data: any) =>
    api.post('/api/ous', data),

  updateOU: (id: string, data: any) =>
    api.put(`/api/ous/${id}`, data),

  deleteOU: (id: string) =>
    api.delete(`/api/ous/${id}`),
};

export default api;