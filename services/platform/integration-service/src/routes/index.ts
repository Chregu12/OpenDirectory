import { Router } from 'express';
import lldapRoutes from './lldap';
import grafanaRoutes from './grafana';
import prometheusRoutes from './prometheus';
import vaultRoutes from './vault';
import healthRoutes from './health';

const router = Router();

// Health check endpoint
router.use('/health', healthRoutes);

// Service integration routes
router.use('/api/lldap', lldapRoutes);
router.use('/api/grafana', grafanaRoutes);
router.use('/api/prometheus', prometheusRoutes);
router.use('/api/vault', vaultRoutes);

// Root endpoint
router.get('/', (req, res) => {
  res.json({
    name: 'OpenDirectory Integration Service',
    version: '1.0.0',
    services: {
      lldap: '/api/lldap',
      grafana: '/api/grafana',
      prometheus: '/api/prometheus',
      vault: '/api/vault',
    },
    health: '/health',
    metrics: '/metrics',
  });
});

export default router;