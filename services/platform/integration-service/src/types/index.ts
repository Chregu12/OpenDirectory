export interface ServiceConfig {
  name: string;
  baseUrl: string;
  port: number;
  healthEndpoint?: string;
  authentication?: {
    type: 'basic' | 'bearer' | 'api-key' | 'none';
    credentials?: {
      username?: string;
      password?: string;
      token?: string;
      apiKey?: string;
    };
  };
}

export interface LLDAPUser {
  id: string;
  email: string;
  displayName: string;
  firstName: string;
  lastName: string;
  groups: string[];
  createdAt: string;
  lastLogin?: string;
}

export interface LLDAPGroup {
  id: string;
  displayName: string;
  members: string[];
  createdAt: string;
}

export interface PrometheusMetric {
  metric: Record<string, string>;
  value: [number, string];
}

export interface PrometheusQueryResult {
  status: string;
  data: {
    resultType: string;
    result: PrometheusMetric[];
  };
}

export interface GrafanaDashboard {
  id: number;
  uid: string;
  title: string;
  tags: string[];
  uri: string;
  url: string;
  slug: string;
  type: string;
  folderTitle: string;
}

export interface VaultSecret {
  path: string;
  data: Record<string, any>;
  metadata: {
    created_time: string;
    custom_metadata?: Record<string, string>;
    deletion_time?: string;
    destroyed: boolean;
    version: number;
  };
}

export interface ServiceStatus {
  name: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  version?: string;
  uptime?: number;
  lastCheck: string;
  details?: Record<string, any>;
}

export interface IntegrationError {
  service: string;
  operation: string;
  message: string;
  code?: string;
  timestamp: string;
}