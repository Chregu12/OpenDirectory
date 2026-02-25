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
    baseUrl: process.env.VAULT_URL || 'http://localhost:30820',
    port: 30820,
    healthEndpoint: '/v1/sys/health',
    authentication: {
      type: 'bearer',
      credentials: {
        token: process.env.VAULT_TOKEN,
      },
    },
  },
};

export const API_CONFIG = {
  port: process.env.PORT || 3005,
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
  },
  timeout: 30000, // 30 seconds
  retries: 3,
};