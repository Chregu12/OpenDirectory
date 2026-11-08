import { LLDAPService } from './lldap.service';
import { GrafanaService } from './grafana.service';
import { PrometheusService } from './prometheus.service';
import { VaultService } from './vault.service';
import { NetworkInfrastructureService } from './network-infrastructure.service';
import { WazuhService } from './wazuh.service';
import { SERVICES, isServiceEnabled } from '../config/services';
import { ServiceStatus } from '../types';

const clients = {
  lldap: new LLDAPService(),
  grafana: new GrafanaService(),
  prometheus: new PrometheusService(),
  vault: new VaultService(),
  'network-infrastructure': new NetworkInfrastructureService(),
  wazuh: new WazuhService(),
};

export async function checkService(id: string): Promise<ServiceStatus & { id: string }> {
  const client = clients[id as keyof typeof clients];
  if (!client) throw new Error('Unknown service');
  const base = { id, name: SERVICES[id].name, lastCheck: new Date().toISOString() };
  if (!isServiceEnabled(id)) return { ...base, status: 'disabled', details: { reason: 'not_configured' } };
  try {
    return { ...await client.getServiceStatus(), id };
  } catch {
    return { ...base, status: 'unknown' };
  }
}

export async function checkServices() {
  const services = await Promise.all(Object.keys(clients).map(checkService));
  const enabled = services.filter(service => service.status !== 'disabled');
  const healthy = enabled.filter(service => service.status === 'healthy').length;
  return {
    status: healthy === enabled.length && healthy > 0 ? 'healthy' : healthy > 0 ? 'degraded' : 'unhealthy',
    timestamp: new Date().toISOString(),
    services,
    summary: { healthy, total: enabled.length, disabled: services.length - enabled.length },
  };
}
