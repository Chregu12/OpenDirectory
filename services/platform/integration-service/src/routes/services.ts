import { Router, Request, Response } from 'express';

const router = Router();

const SERVICE_LIST = [
  { id: 'lldap',           name: 'LLDAP',              type: 'identity',      url: process.env.LLDAP_URL || 'http://lldap:17170' },
  { id: 'grafana',         name: 'Grafana',             type: 'monitoring',    url: process.env.GRAFANA_URL || 'http://grafana:3000' },
  { id: 'prometheus',      name: 'Prometheus',          type: 'monitoring',    url: process.env.PROMETHEUS_URL || 'http://prometheus:9090' },
  { id: 'vault',           name: 'Vault',               type: 'secrets',       url: process.env.VAULT_URL || 'http://vault:8200' },
];

router.get('/', (req: Request, res: Response) => {
  res.json(SERVICE_LIST.map(s => ({ ...s, status: 'unknown' })));
});

router.get('/:serviceId/health', (req: Request, res: Response) => {
  const { serviceId } = req.params;
  const service = SERVICE_LIST.find(s => s.id === serviceId);
  if (!service) {
    return res.status(404).json({ error: 'Service not found' });
  }
  res.json({ id: serviceId, status: 'unknown', timestamp: new Date().toISOString() });
});

export default router;
