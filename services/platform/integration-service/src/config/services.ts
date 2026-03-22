import { ServiceConfig } from '../types';

export const SERVICES: Record<string, ServiceConfig> = {
  lldap: {
    name: 'LLDAP',
    baseUrl: process.env.LLDAP_URL || 'http://localhost:30170',
    port: 30170,
    healthEndpoint: '/health',
    authentication: {
      type: 'basic',
      credentials: {
        username: process.env.LLDAP_ADMIN_USER || 'admin',
        password: process.env.LLDAP_ADMIN_PASSWORD || 'changeme',
      },
    },
  },
  grafana: {
    name: 'Grafana',
    baseUrl: process.env.GRAFANA_URL || 'http://localhost:30300',
    port: 30300,
    healthEndpoint: '/api/health',
    authentication: {
      type: 'basic',
      credentials: {
        username: process.env.GRAFANA_ADMIN_USER || 'admin',
        password: process.env.GRAFANA_ADMIN_PASSWORD || 'changeme',
      },
    },
  },
  prometheus: {
    name: 'Prometheus',
    baseUrl: process.env.PROMETHEUS_URL || 'http://localhost:30909',
    port: 30909,
    healthEndpoint: '/-/healthy',
    authentication: {
      type: 'none',
    },
  },
  vault: {
    name: 'HashiCorp Vault',
    baseUrl: process.env.VAULT_URL || 'http://vault:8200',
    port: 8200,
    healthEndpoint: '/v1/sys/health',
    authentication: {
      type: 'bearer',
      credentials: {
        token: process.env.VAULT_TOKEN,
      },
    },
  },
  'network-infrastructure': {
    name: 'Network Infrastructure',
    baseUrl: process.env.NETWORK_INFRA_URL || 'http://network-infrastructure:3007',
    port: 3007,
    healthEndpoint: '/health',
    authentication: { type: 'none' },
  },
  wazuh: {
    name: 'Wazuh Security',
    baseUrl: process.env.WAZUH_URL || process.env.SECURITY_SCANNER_URL || 'http://security-scanner:3902',
    port: 3902,
    healthEndpoint: '/health',
    authentication: { type: 'none' },
  },
};

export const API_CONFIG = {
  port: process.env.PORT || 3005,
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  rateLimit: {
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 300, // 300 requests per minute per IP (UI polls multiple endpoints)
  },
  timeout: 30000, // 30 seconds
  retries: 3,
};