import { Router, Request, Response } from 'express';
import { LLDAPService } from '../services/lldap.service';
import { GrafanaService } from '../services/grafana.service';
import { PrometheusService } from '../services/prometheus.service';
import { VaultService } from '../services/vault.service';
import { SERVICES } from '../config/services';

const router = Router();

const lldapService      = new LLDAPService();
const grafanaService    = new GrafanaService();
const prometheusService = new PrometheusService();
const vaultService      = new VaultService();

const SERVICE_CHECKS: Record<string, { name: string; fn: () => Promise<any> }> = {
  lldap:      { name: 'LLDAP',      fn: () => lldapService.getServiceStatus() },
  grafana:    { name: 'Grafana',    fn: () => grafanaService.getServiceStatus() },
  prometheus: { name: 'Prometheus', fn: () => prometheusService.getServiceStatus() },
  vault:      { name: 'Vault',      fn: () => vaultService.getServiceStatus() },
};

router.get('/', async (req: Request, res: Response) => {
  const results = await Promise.allSettled(
    Object.entries(SERVICE_CHECKS).map(async ([id, { name, fn }]) => {
      const start = Date.now();
      try {
        const status = await fn();
        return {
          id,
          name,
          status: status.status as string,
          port: SERVICES[id]?.port,
          responseTime: Date.now() - start,
          lastCheck: status.lastCheck || new Date().toISOString(),
          description: status.details?.description,
        };
      } catch {
        return {
          id,
          name,
          status: 'unknown',
          port: SERVICES[id]?.port,
          responseTime: null,
          lastCheck: new Date().toISOString(),
        };
      }
    })
  );

  const services = results.map(r =>
    r.status === 'fulfilled' ? r.value : { status: 'unknown' }
  );

  res.json(services);
});

router.get('/:serviceId/health', async (req: Request, res: Response) => {
  const { serviceId } = req.params;
  const check = SERVICE_CHECKS[serviceId];
  if (!check) {
    return res.status(404).json({ error: 'Service not found' });
  }
  const start = Date.now();
  try {
    const status = await check.fn();
    res.json({
      id: serviceId,
      name: check.name,
      status: status.status,
      port: SERVICES[serviceId]?.port,
      responseTime: Date.now() - start,
      lastCheck: status.lastCheck || new Date().toISOString(),
    });
  } catch {
    res.json({
      id: serviceId,
      name: check.name,
      status: 'unknown',
      port: SERVICES[serviceId]?.port,
      responseTime: null,
      lastCheck: new Date().toISOString(),
    });
  }
});

export default router;
