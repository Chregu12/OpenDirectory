import axios from 'axios';
import { ServiceStatus } from '../types';
import logger from '../lib/logger';

// Prefers real Wazuh API (port 55000) if configured, falls back to security-scanner (port 3902)
const BASE_URL = process.env.WAZUH_URL || process.env.SECURITY_SCANNER_URL || 'http://security-scanner:3902';

function isUnavailable(error: any): boolean {
  const code = error?.code || error?.cause?.code || '';
  return ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNRESET'].includes(code);
}

export class WazuhService {
  async getServiceStatus(): Promise<ServiceStatus> {
    const lastCheck = new Date().toISOString();
    try {
      const response = await axios.get(`${BASE_URL}/health`, { timeout: 5000 });
      const data = response.data;
      const s = (data?.status ?? '').toLowerCase();
      const status = s === 'healthy' || s === 'ok' || s === 'up' || s === 'active' ? 'healthy' : 'unhealthy';
      return {
        name: 'Wazuh Security',
        status,
        lastCheck,
        details: {
          service: data?.service ?? data?.name,
          version: data?.version,
        },
      };
    } catch (error: any) {
      if (isUnavailable(error)) {
        return {
          name: 'Wazuh Security',
          status: 'unhealthy',
          lastCheck,
          details: { error: 'Service unreachable' },
        };
      }
      logger.error('Wazuh health check failed:', error);
      return {
        name: 'Wazuh Security',
        status: 'unhealthy',
        lastCheck,
        details: { error: error?.message ?? 'Unknown error' },
      };
    }
  }
}
