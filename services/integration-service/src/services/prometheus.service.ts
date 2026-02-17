import { HttpClient } from '../lib/http-client';
import { SERVICES } from '../config/services';
import { PrometheusQueryResult, ServiceStatus } from '../types';
import logger from '../lib/logger';

export class PrometheusService {
  private client: HttpClient;

  constructor() {
    this.client = new HttpClient(SERVICES.prometheus);
  }

  async query(query: string): Promise<PrometheusQueryResult | null> {
    try {
      const result = await this.client.get<PrometheusQueryResult>(
        `/api/v1/query?query=${encodeURIComponent(query)}`
      );
      return result;
    } catch (error) {
      logger.error('Failed to execute Prometheus query:', error);
      return null;
    }
  }

  async queryRange(query: string, start: number, end: number, step: string): Promise<PrometheusQueryResult | null> {
    try {
      const result = await this.client.get<PrometheusQueryResult>(
        `/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=${step}`
      );
      return result;
    } catch (error) {
      logger.error('Failed to execute Prometheus range query:', error);
      return null;
    }
  }

  async getLabels(): Promise<string[]> {
    try {
      const response = await this.client.get<{ data: string[] }>('/api/v1/labels');
      return response.data || [];
    } catch (error) {
      logger.error('Failed to fetch Prometheus labels:', error);
      return [];
    }
  }

  async getLabelValues(labelName: string): Promise<string[]> {
    try {
      const response = await this.client.get<{ data: string[] }>(
        `/api/v1/label/${labelName}/values`
      );
      return response.data || [];
    } catch (error) {
      logger.error(`Failed to fetch values for label ${labelName}:`, error);
      return [];
    }
  }

  async getMetrics(): Promise<string[]> {
    try {
      const response = await this.client.get<string>('/api/v1/label/__name__/values');
      // Prometheus returns plain text for this endpoint
      return typeof response === 'string' ? response.split('\n').filter(Boolean) : [];
    } catch (error) {
      logger.error('Failed to fetch Prometheus metrics:', error);
      return [];
    }
  }

  // OpenDirectory specific metric queries
  async getServiceMetrics(): Promise<Record<string, any>> {
    try {
      const queries = {
        // Service health
        serviceHealth: 'up{job=~".*-service"}',
        
        // HTTP request metrics
        httpRequests: 'sum by (service) (rate(http_requests_total[5m]))',
        httpErrors: 'sum by (service) (rate(http_requests_total{status=~"5.."}[5m]))',
        httpLatency: 'histogram_quantile(0.95, sum by (service, le) (rate(http_request_duration_seconds_bucket[5m])))',
        
        // Database metrics
        dbConnections: 'sum by (service) (db_connections_active)',
        dbQueries: 'sum by (service) (rate(db_queries_total[5m]))',
        
        // Memory and CPU
        memoryUsage: 'sum by (service) (process_resident_memory_bytes)',
        cpuUsage: 'sum by (service) (rate(process_cpu_seconds_total[5m]))',
        
        // Authentication metrics
        authAttempts: 'sum by (method) (rate(auth_attempts_total[5m]))',
        authFailures: 'sum by (method) (rate(auth_failures_total[5m]))',
        
        // Device metrics
        deviceConnections: 'sum(device_connections_active)',
        deviceRegistrations: 'sum(rate(device_registrations_total[5m]))',
      };

      const results: Record<string, any> = {};
      
      for (const [key, query] of Object.entries(queries)) {
        const result = await this.query(query);
        results[key] = result?.data?.result || [];
      }

      return results;
    } catch (error) {
      logger.error('Failed to fetch service metrics:', error);
      return {};
    }
  }

  async getSystemMetrics(): Promise<Record<string, any>> {
    try {
      const queries = {
        // System resource utilization
        nodeMemory: '(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100',
        nodeCPU: '100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
        nodeDisk: '100 - (node_filesystem_avail_bytes{fstype!="tmpfs"} / node_filesystem_size_bytes{fstype!="tmpfs"} * 100)',
        nodeLoad: 'node_load1',
        
        // Network metrics
        networkIn: 'rate(node_network_receive_bytes_total[5m])',
        networkOut: 'rate(node_network_transmit_bytes_total[5m])',
        
        // Container metrics (if using Docker/K8s)
        containerMemory: 'sum by (name) (container_memory_usage_bytes{container!=""})',
        containerCPU: 'sum by (name) (rate(container_cpu_usage_seconds_total{container!=""}[5m]))',
      };

      const results: Record<string, any> = {};
      
      for (const [key, query] of Object.entries(queries)) {
        const result = await this.query(query);
        results[key] = result?.data?.result || [];
      }

      return results;
    } catch (error) {
      logger.error('Failed to fetch system metrics:', error);
      return {};
    }
  }

  async getAlerts(): Promise<any[]> {
    try {
      const response = await this.client.get('/api/v1/alerts');
      return response.data?.alerts || [];
    } catch (error) {
      logger.error('Failed to fetch Prometheus alerts:', error);
      return [];
    }
  }

  async getRules(): Promise<any[]> {
    try {
      const response = await this.client.get('/api/v1/rules');
      return response.data?.groups || [];
    } catch (error) {
      logger.error('Failed to fetch Prometheus rules:', error);
      return [];
    }
  }

  async getTargets(): Promise<any[]> {
    try {
      const response = await this.client.get('/api/v1/targets');
      return response.data?.activeTargets || [];
    } catch (error) {
      logger.error('Failed to fetch Prometheus targets:', error);
      return [];
    }
  }

  async getServiceStatus(): Promise<ServiceStatus> {
    const lastCheck = new Date().toISOString();
    
    try {
      const isHealthy = await this.client.healthCheck();
      
      if (isHealthy) {
        // Get additional status info
        const targets = await this.getTargets();
        const healthyTargets = targets.filter(t => t.health === 'up').length;
        const totalTargets = targets.length;
        
        return {
          name: SERVICES.prometheus.name,
          status: 'healthy',
          lastCheck,
          details: {
            targets: {
              healthy: healthyTargets,
              total: totalTargets,
            },
          },
        };
      }
      
      return {
        name: SERVICES.prometheus.name,
        status: 'unhealthy',
        lastCheck,
      };
    } catch (error) {
      return {
        name: SERVICES.prometheus.name,
        status: 'unknown',
        lastCheck,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
      };
    }
  }

  // Custom dashboard data aggregation
  async getDashboardData(timeRange = '1h'): Promise<Record<string, any>> {
    try {
      const endTime = Math.floor(Date.now() / 1000);
      const startTime = endTime - this.parseTimeRange(timeRange);
      
      const serviceMetrics = await this.getServiceMetrics();
      const systemMetrics = await this.getSystemMetrics();
      
      // Aggregate key performance indicators
      const kpis = {
        totalRequests: await this.query(`sum(increase(http_requests_total[${timeRange}]))`),
        errorRate: await this.query(`sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100`),
        avgResponseTime: await this.query(`histogram_quantile(0.5, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))`),
        activeUsers: await this.query('sum(auth_sessions_active)'),
        systemLoad: await this.query('avg(node_load1)'),
      };

      return {
        kpis,
        serviceMetrics,
        systemMetrics,
        timeRange,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error('Failed to fetch dashboard data:', error);
      return {};
    }
  }

  private parseTimeRange(timeRange: string): number {
    const unit = timeRange.slice(-1);
    const value = parseInt(timeRange.slice(0, -1));
    
    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 60 * 60;
      case 'd': return value * 60 * 60 * 24;
      default: return 3600; // 1 hour default
    }
  }
}