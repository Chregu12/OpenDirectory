import { Router } from 'express';
import { SERVICES } from '../config/services';
import { checkService, checkServices } from '../services/service-status';

const router = Router();

router.get(['/', '/detailed'], async (_req, res) => {
  const start = Date.now();
  const health = await checkServices();
  res.status(health.status === 'healthy' ? 200 : health.status === 'degraded' ? 207 : 503)
    .json({ ...health, responseTime: Date.now() - start });
});

router.get('/live', (_req, res) => res.json({ status: 'alive', timestamp: new Date().toISOString() }));

router.get('/ready', async (_req, res) => {
  const health = await checkServices();
  res.status(health.status === 'healthy' ? 200 : 503).json({
    status: health.status === 'healthy' ? 'ready' : 'not ready',
    summary: health.summary,
    timestamp: health.timestamp,
  });
});

router.get('/metrics', async (_req, res) => {
  try {
    const register = await import('prom-client').then(module => module.register);
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch {
    res.status(500).json({ error: 'Failed to generate metrics' });
  }
});

router.get(['/service/:name', '/:name'], async (req, res) => {
  if (!Object.prototype.hasOwnProperty.call(SERVICES, req.params.name)) return res.status(404).json({ error: 'Service not found' });
  const service = await checkService(req.params.name);
  return res.status(service.status === 'healthy' ? 200 : 503).json(service);
});

export default router;
