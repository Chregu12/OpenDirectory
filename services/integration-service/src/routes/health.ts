import { Router } from 'express';
import { LLDAPService } from '../services/lldap.service';
import { GrafanaService } from '../services/grafana.service';
import { PrometheusService } from '../services/prometheus.service';
import { VaultService } from '../services/vault.service';
import { ServiceStatus } from '../types';
import logger from '../lib/logger';

const router = Router();
const lldapService = new LLDAPService();
const grafanaService = new GrafanaService();
const prometheusService = new PrometheusService();
const vaultService = new VaultService();

// Overall health check
router.get('/', async (req, res) => {
  try {
    const startTime = Date.now();
    
    // Check all services in parallel
    const [lldapStatus, grafanaStatus, prometheusStatus, vaultStatus] = await Promise.allSettled([
      lldapService.getServiceStatus(),
      grafanaService.getServiceStatus(),
      prometheusService.getServiceStatus(),
      vaultService.getServiceStatus(),
    ]);

    const services: ServiceStatus[] = [];
    
    if (lldapStatus.status === 'fulfilled') services.push(lldapStatus.value);
    if (grafanaStatus.status === 'fulfilled') services.push(grafanaStatus.value);
    if (prometheusStatus.status === 'fulfilled') services.push(prometheusStatus.value);
    if (vaultStatus.status === 'fulfilled') services.push(vaultStatus.value);

    const healthyServices = services.filter(s => s.status === 'healthy').length;
    const totalServices = services.length;
    const overallStatus = healthyServices === totalServices ? 'healthy' : 
                         healthyServices > 0 ? 'degraded' : 'unhealthy';

    const response = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      responseTime: Date.now() - startTime,
      services,
      summary: {
        healthy: healthyServices,
        total: totalServices,
      },
    };

    // Return appropriate HTTP status code
    if (overallStatus === 'healthy') {
      res.status(200).json(response);
    } else if (overallStatus === 'degraded') {
      res.status(207).json(response); // Multi-Status
    } else {
      res.status(503).json(response); // Service Unavailable
    }
  } catch (error) {
    logger.error('Health check failed:', error);
    res.status(500).json({
      status: 'error',
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// Individual service health checks
router.get('/lldap', async (req, res) => {
  try {
    const status = await lldapService.getServiceStatus();
    const httpStatus = status.status === 'healthy' ? 200 : 503;
    res.status(httpStatus).json(status);
  } catch (error) {
    logger.error('LLDAP health check failed:', error);
    res.status(500).json({
      name: 'LLDAP',
      status: 'error',
      lastCheck: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

router.get('/grafana', async (req, res) => {
  try {
    const status = await grafanaService.getServiceStatus();
    const httpStatus = status.status === 'healthy' ? 200 : 503;
    res.status(httpStatus).json(status);
  } catch (error) {
    logger.error('Grafana health check failed:', error);
    res.status(500).json({
      name: 'Grafana',
      status: 'error',
      lastCheck: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

router.get('/prometheus', async (req, res) => {
  try {
    const status = await prometheusService.getServiceStatus();
    const httpStatus = status.status === 'healthy' ? 200 : 503;
    res.status(httpStatus).json(status);
  } catch (error) {
    logger.error('Prometheus health check failed:', error);
    res.status(500).json({
      name: 'Prometheus',
      status: 'error',
      lastCheck: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

router.get('/vault', async (req, res) => {
  try {
    const status = await vaultService.getServiceStatus();
    const httpStatus = status.status === 'healthy' ? 200 : 503;
    res.status(httpStatus).json(status);
  } catch (error) {
    logger.error('Vault health check failed:', error);
    res.status(500).json({
      name: 'Vault',
      status: 'error',
      lastCheck: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// Liveness probe (for Kubernetes)
router.get('/live', (req, res) => {
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
  });
});

// Readiness probe (for Kubernetes)
router.get('/ready', async (req, res) => {
  try {
    // Quick health check - just verify we can connect to at least one service
    const prometheusStatus = await prometheusService.getServiceStatus();
    
    if (prometheusStatus.status === 'healthy') {
      res.status(200).json({
        status: 'ready',
        timestamp: new Date().toISOString(),
      });
    } else {
      res.status(503).json({
        status: 'not ready',
        timestamp: new Date().toISOString(),
        reason: 'Core services not available',
      });
    }
  } catch (error) {
    res.status(503).json({
      status: 'not ready',
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// Metrics endpoint for Prometheus scraping
router.get('/metrics', async (req, res) => {
  try {
    const register = await import('prom-client').then(m => m.register);
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (error) {
    logger.error('Failed to generate metrics:', error);
    res.status(500).json({
      error: 'Failed to generate metrics',
    });
  }
});

export default router;