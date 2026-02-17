import { Router, Request, Response } from 'express';
import { PrometheusService } from '../services/prometheus.service';
import logger from '../lib/logger';

const router = Router();
const prometheusService = new PrometheusService();

// Query endpoints
router.get('/query', async (req: Request, res: Response) => {
  try {
    const query = req.query.query as string;
    if (!query) {
      return res.status(400).json({ error: 'Query parameter is required' });
    }

    const result = await prometheusService.query(query);
    if (result) {
      res.json(result);
    } else {
      res.status(404).json({ error: 'Query failed or returned no results' });
    }
  } catch (error) {
    logger.error('Failed to execute Prometheus query:', error);
    res.status(500).json({ error: 'Failed to execute query' });
  }
});

router.get('/query_range', async (req: Request, res: Response) => {
  try {
    const { query, start, end, step } = req.query as {
      query: string;
      start: string;
      end: string;
      step: string;
    };

    if (!query || !start || !end || !step) {
      return res.status(400).json({ 
        error: 'Query, start, end, and step parameters are required' 
      });
    }

    const startTime = parseInt(start);
    const endTime = parseInt(end);

    const result = await prometheusService.queryRange(query, startTime, endTime, step);
    if (result) {
      res.json(result);
    } else {
      res.status(404).json({ error: 'Range query failed or returned no results' });
    }
  } catch (error) {
    logger.error('Failed to execute Prometheus range query:', error);
    res.status(500).json({ error: 'Failed to execute range query' });
  }
});

// Labels and metrics discovery
router.get('/labels', async (req: Request, res: Response) => {
  try {
    const labels = await prometheusService.getLabels();
    res.json({ data: labels });
  } catch (error) {
    logger.error('Failed to fetch Prometheus labels:', error);
    res.status(500).json({ error: 'Failed to fetch labels' });
  }
});

router.get('/label/:labelName/values', async (req: Request, res: Response) => {
  try {
    const { labelName } = req.params;
    const values = await prometheusService.getLabelValues(labelName);
    res.json({ data: values });
  } catch (error) {
    logger.error(`Failed to fetch values for label ${req.params.labelName}:`, error);
    res.status(500).json({ error: 'Failed to fetch label values' });
  }
});

router.get('/metrics', async (req: Request, res: Response) => {
  try {
    const metrics = await prometheusService.getMetrics();
    res.json({ data: metrics });
  } catch (error) {
    logger.error('Failed to fetch Prometheus metrics:', error);
    res.status(500).json({ error: 'Failed to fetch metrics' });
  }
});

// OpenDirectory-specific endpoints
router.get('/service-metrics', async (req: Request, res: Response) => {
  try {
    const metrics = await prometheusService.getServiceMetrics();
    res.json({
      data: metrics,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Failed to fetch service metrics:', error);
    res.status(500).json({ error: 'Failed to fetch service metrics' });
  }
});

router.get('/system-metrics', async (req: Request, res: Response) => {
  try {
    const metrics = await prometheusService.getSystemMetrics();
    res.json({
      data: metrics,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Failed to fetch system metrics:', error);
    res.status(500).json({ error: 'Failed to fetch system metrics' });
  }
});

router.get('/dashboard-data', async (req: Request, res: Response) => {
  try {
    const timeRange = (req.query.timeRange as string) || '1h';
    const data = await prometheusService.getDashboardData(timeRange);
    res.json(data);
  } catch (error) {
    logger.error('Failed to fetch dashboard data:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Alerts and rules
router.get('/alerts', async (req: Request, res: Response) => {
  try {
    const alerts = await prometheusService.getAlerts();
    res.json({ data: { alerts } });
  } catch (error) {
    logger.error('Failed to fetch Prometheus alerts:', error);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

router.get('/rules', async (req: Request, res: Response) => {
  try {
    const rules = await prometheusService.getRules();
    res.json({ data: { groups: rules } });
  } catch (error) {
    logger.error('Failed to fetch Prometheus rules:', error);
    res.status(500).json({ error: 'Failed to fetch rules' });
  }
});

router.get('/targets', async (req: Request, res: Response) => {
  try {
    const targets = await prometheusService.getTargets();
    res.json({ data: { activeTargets: targets } });
  } catch (error) {
    logger.error('Failed to fetch Prometheus targets:', error);
    res.status(500).json({ error: 'Failed to fetch targets' });
  }
});

// Service status
router.get('/status', async (req: Request, res: Response) => {
  try {
    const status = await prometheusService.getServiceStatus();
    const httpStatus = status.status === 'healthy' ? 200 : 503;
    res.status(httpStatus).json(status);
  } catch (error) {
    logger.error('Failed to get Prometheus service status:', error);
    res.status(500).json({ error: 'Failed to get service status' });
  }
});

// Common query shortcuts for OpenDirectory
router.get('/kpis', async (req: Request, res: Response) => {
  try {
    const timeRange = (req.query.timeRange as string) || '1h';
    
    const kpis = {
      // Service availability
      serviceUptime: await prometheusService.query('avg(up{job=~".*-service"}) * 100'),
      
      // Request metrics
      totalRequests: await prometheusService.query(`sum(increase(http_requests_total[${timeRange}]))`),
      errorRate: await prometheusService.query('sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100'),
      avgResponseTime: await prometheusService.query('histogram_quantile(0.50, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))'),
      
      // Authentication metrics
      activeUsers: await prometheusService.query('sum(auth_sessions_active)'),
      authFailureRate: await prometheusService.query('sum(rate(auth_failures_total[5m])) / sum(rate(auth_attempts_total[5m])) * 100'),
      
      // System resources
      memoryUsage: await prometheusService.query('(1 - avg(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100'),
      cpuUsage: await prometheusService.query('100 - avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100'),
      diskUsage: await prometheusService.query('100 - avg(node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100'),
      
      // Device metrics
      connectedDevices: await prometheusService.query('sum(device_connections_active)'),
      deviceRegistrations: await prometheusService.query(`sum(increase(device_registrations_total[${timeRange}]))`),
    };

    res.json({
      kpis,
      timeRange,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Failed to fetch KPIs:', error);
    res.status(500).json({ error: 'Failed to fetch KPIs' });
  }
});

// Time series data for charts
router.get('/timeseries', async (req: Request, res: Response) => {
  try {
    const { query, start, end, step } = req.query as {
      query: string;
      start?: string;
      end?: string;
      step?: string;
    };

    if (!query) {
      return res.status(400).json({ error: 'Query parameter is required' });
    }

    // Default time range: last hour
    const endTime = end ? parseInt(end) : Math.floor(Date.now() / 1000);
    const startTime = start ? parseInt(start) : endTime - 3600;
    const stepSize = step || '30s';

    const result = await prometheusService.queryRange(query, startTime, endTime, stepSize);
    
    if (result && result.data.result.length > 0) {
      // Transform data for easier consumption by frontend charts
      const timeseries = result.data.result.map((series: any) => ({
        metric: series.metric,
        values: series.values?.map(([timestamp, value]: [number, string]) => ({
          timestamp: timestamp * 1000, // Convert to milliseconds
          value: parseFloat(value),
        })) || [],
      }));

      res.json({
        data: timeseries,
        query,
        timeRange: {
          start: startTime * 1000,
          end: endTime * 1000,
          step: stepSize,
        },
        timestamp: new Date().toISOString(),
      });
    } else {
      res.json({
        data: [],
        query,
        timeRange: {
          start: startTime * 1000,
          end: endTime * 1000,
          step: stepSize,
        },
        timestamp: new Date().toISOString(),
      });
    }
  } catch (error) {
    logger.error('Failed to fetch time series data:', error);
    res.status(500).json({ error: 'Failed to fetch time series data' });
  }
});

export default router;