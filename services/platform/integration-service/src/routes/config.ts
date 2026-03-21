import { Router, Request, Response } from 'express';
import logger from '../lib/logger';

const router = Router();

// In-memory module config (persists for process lifetime)
const moduleConfig: Record<string, { enabled: boolean; name: string; description: string }> = {
  'monitoring-analytics':   { enabled: true,  name: 'Monitoring & Analytics',   description: 'Grafana dashboards and Prometheus metrics' },
  'secrets-management':     { enabled: true,  name: 'Secrets Management',        description: 'HashiCorp Vault integration' },
  'device-management':      { enabled: true,  name: 'Device Management',         description: 'Endpoint lifecycle and enrollment' },
  'network-infrastructure': { enabled: true,  name: 'Network Infrastructure',    description: 'DNS, DHCP, and network topology' },
  'security-suite':         { enabled: true,  name: 'Security Suite',            description: 'Vulnerability scanning and threat detection' },
};

router.get('/modules', (req: Request, res: Response) => {
  res.json(moduleConfig);
});

router.get('/modules/:moduleId', (req: Request, res: Response) => {
  const { moduleId } = req.params;
  if (!moduleConfig[moduleId]) {
    return res.status(404).json({ error: 'Module not found' });
  }
  res.json(moduleConfig[moduleId]);
});

router.post('/modules/:moduleId', (req: Request, res: Response) => {
  const { moduleId } = req.params;
  const { enabled } = req.body;
  if (!moduleConfig[moduleId]) {
    return res.status(404).json({ error: 'Module not found' });
  }
  moduleConfig[moduleId].enabled = Boolean(enabled);
  logger.info(`Module ${moduleId} ${enabled ? 'enabled' : 'disabled'}`);
  res.json(moduleConfig[moduleId]);
});

router.get('/features', (req: Request, res: Response) => {
  res.json({
    lldapIntegration: true,
    grafanaDashboards: true,
    prometheusMetrics: true,
    vaultSecrets: true,
    deviceEnrollment: true,
  });
});

router.get('/settings', (req: Request, res: Response) => {
  res.json({
    siteName: 'OpenDirectory',
    version: '1.0.0',
    theme: 'light',
    language: 'en',
  });
});

export default router;
