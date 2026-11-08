import { Router } from 'express';
import { SERVICES } from '../config/services';
import { checkService, checkServices } from '../services/service-status';

const router = Router();

router.get('/', async (_req, res) => {
  const { services } = await checkServices();
  res.json(services.map(service => ({ ...service, port: SERVICES[service.id].port,
    enabled: service.status !== 'disabled', description: service.status === 'disabled' ? 'Not configured' : service.details?.description })));
});

router.get('/:serviceId/health', async (req, res) => {
  if (!Object.prototype.hasOwnProperty.call(SERVICES, req.params.serviceId)) return res.status(404).json({ error: 'Service not found' });
  const service = await checkService(req.params.serviceId);
  return res.status(service.status === 'healthy' ? 200 : 503).json({ ...service, port: SERVICES[service.id].port });
});

export default router;
