import axios from 'axios';
import { ServiceStatus } from '../types';
import logger from '../lib/logger';

const BASE_URL = process.env.NETWORK_INFRA_URL || 'http://network-infrastructure:3007';

function isUnavailable(error: any): boolean {
  const code = error?.code || error?.cause?.code || '';
  return ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNRESET'].includes(code);
}

export class NetworkInfrastructureService {
  async getServiceStatus(): Promise<ServiceStatus> {
    const lastCheck = new Date().toISOString();
    try {
      const response = await axios.get(`${BASE_URL}/health`, { timeout: 5000 });
      const data = response.data;
      const s = (data?.status ?? '').toLowerCase();
      const status = s === 'healthy' || s === 'ok' || s === 'up' ? 'healthy' : 'unhealthy';
      return {
        name: 'Network Infrastructure',
        status,
        lastCheck,
        details: {
          dns:   data?.services?.dns   ?? data?.dns,
          dhcp:  data?.services?.dhcp  ?? data?.dhcp,
          samba: data?.services?.samba ?? data?.samba,
        },
      };
    } catch (error: any) {
      if (isUnavailable(error)) {
        return {
          name: 'Network Infrastructure',
          status: 'unhealthy',
          lastCheck,
          details: { error: 'Service unreachable' },
        };
      }
      logger.error('Network infrastructure health check failed:', error);
      return {
        name: 'Network Infrastructure',
        status: 'unhealthy',
        lastCheck,
        details: { error: error?.message ?? 'Unknown error' },
      };
    }
  }
}
