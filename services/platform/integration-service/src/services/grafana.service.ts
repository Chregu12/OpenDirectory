import { HttpClient } from '../lib/http-client';
import { SERVICES } from '../config/services';
import { GrafanaDashboard, ServiceStatus } from '../types';
import logger from '../lib/logger';

export class GrafanaService {
  private client: HttpClient;

  constructor() {
    this.client = new HttpClient(SERVICES.grafana);
  }

  async getDashboards(): Promise<GrafanaDashboard[]> {
    try {
      const dashboards = await this.client.get<GrafanaDashboard[]>('/api/search?type=dash-db');
      return dashboards;
    } catch (error) {
      logger.error('Failed to fetch Grafana dashboards:', error);
      return [];
    }
  }

  async getDashboard(uid: string): Promise<any> {
    try {
      const dashboard = await this.client.get(`/api/dashboards/uid/${uid}`);
      return dashboard;
    } catch (error) {
      logger.error(`Failed to fetch dashboard ${uid}:`, error);
      return null;
    }
  }

  async getDashboardBySlug(slug: string): Promise<any> {
    try {
      const dashboard = await this.client.get(`/api/dashboards/db/${slug}`);
      return dashboard;
    } catch (error) {
      logger.error(`Failed to fetch dashboard by slug ${slug}:`, error);
      return null;
    }
  }

  async createDashboard(dashboard: any): Promise<any> {
    try {
      const result = await this.client.post('/api/dashboards/db', {
        dashboard,
        folderId: 0,
        overwrite: false,
      });
      return result;
    } catch (error) {
      logger.error('Failed to create Grafana dashboard:', error);
      throw new Error('Failed to create dashboard');
    }
  }

  async updateDashboard(dashboard: any): Promise<any> {
    try {
      const result = await this.client.post('/api/dashboards/db', {
        dashboard,
        overwrite: true,
      });
      return result;
    } catch (error) {
      logger.error('Failed to update Grafana dashboard:', error);
      throw new Error('Failed to update dashboard');
    }
  }

  async deleteDashboard(uid: string): Promise<boolean> {
    try {
      await this.client.delete(`/api/dashboards/uid/${uid}`);
      return true;
    } catch (error) {
      logger.error(`Failed to delete dashboard ${uid}:`, error);
      return false;
    }
  }

  async getFolders(): Promise<any[]> {
    try {
      const folders = await this.client.get('/api/folders');
      return folders;
    } catch (error) {
      logger.error('Failed to fetch Grafana folders:', error);
      return [];
    }
  }

  async createFolder(title: string, uid?: string): Promise<any> {
    try {
      const folder = await this.client.post('/api/folders', { title, uid });
      return folder;
    } catch (error) {
      logger.error('Failed to create Grafana folder:', error);
      throw new Error('Failed to create folder');
    }
  }

  async getDataSources(): Promise<any[]> {
    try {
      const dataSources = await this.client.get('/api/datasources');
      return dataSources;
    } catch (error) {
      logger.error('Failed to fetch Grafana data sources:', error);
      return [];
    }
  }

  async createDataSource(dataSource: any): Promise<any> {
    try {
      const result = await this.client.post('/api/datasources', dataSource);
      return result;
    } catch (error) {
      logger.error('Failed to create Grafana data source:', error);
      throw new Error('Failed to create data source');
    }
  }

  // Panel data queries
  async queryPanel(datasourceId: number, query: any): Promise<any> {
    try {
      const result = await this.client.post(`/api/ds/query`, {
        from: query.from || 'now-1h',
        to: query.to || 'now',
        queries: [
          {
            datasource: { uid: datasourceId },
            expr: query.expr,
            interval: query.interval || '30s',
            refId: 'A',
          },
        ],
      });
      return result;
    } catch (error) {
      logger.error('Failed to query panel data:', error);
      return null;
    }
  }

  // Annotations
  async getAnnotations(dashboardId?: number, from?: number, to?: number): Promise<any[]> {
    try {
      let url = '/api/annotations';
      const params = new URLSearchParams();
      
      if (dashboardId) params.append('dashboardId', dashboardId.toString());
      if (from) params.append('from', from.toString());
      if (to) params.append('to', to.toString());
      
      if (params.toString()) url += `?${params.toString()}`;
      
      const annotations = await this.client.get(url);
      return annotations;
    } catch (error) {
      logger.error('Failed to fetch annotations:', error);
      return [];
    }
  }

  async createAnnotation(annotation: any): Promise<any> {
    try {
      const result = await this.client.post('/api/annotations', annotation);
      return result;
    } catch (error) {
      logger.error('Failed to create annotation:', error);
      throw new Error('Failed to create annotation');
    }
  }

  // Alerts
  async getAlerts(): Promise<any[]> {
    try {
      const alerts = await this.client.get('/api/alerts');
      return alerts;
    } catch (error) {
      logger.error('Failed to fetch Grafana alerts:', error);
      return [];
    }
  }

  async getAlertNotifications(): Promise<any[]> {
    try {
      const notifications = await this.client.get('/api/alert-notifications');
      return notifications;
    } catch (error) {
      logger.error('Failed to fetch alert notifications:', error);
      return [];
    }
  }

  // User and org management
  async getCurrentUser(): Promise<any> {
    try {
      const user = await this.client.get('/api/user');
      return user;
    } catch (error) {
      logger.error('Failed to fetch current user:', error);
      return null;
    }
  }

  async getOrganization(): Promise<any> {
    try {
      const org = await this.client.get('/api/org');
      return org;
    } catch (error) {
      logger.error('Failed to fetch organization:', error);
      return null;
    }
  }

  // Health and status
  async getServiceStatus(): Promise<ServiceStatus> {
    const lastCheck = new Date().toISOString();
    
    try {
      const health = await this.client.get('/api/health');
      
      if (health.database === 'ok') {
        const org = await this.getOrganization();
        const dashboards = await this.getDashboards();
        
        return {
          name: SERVICES.grafana.name,
          status: 'healthy',
          lastCheck,
          details: {
            version: health.version,
            organization: org?.name,
            dashboardCount: dashboards.length,
          },
        };
      }
      
      return {
        name: SERVICES.grafana.name,
        status: 'unhealthy',
        lastCheck,
        details: { health },
      };
    } catch (error) {
      return {
        name: SERVICES.grafana.name,
        status: 'unknown',
        lastCheck,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
      };
    }
  }

  // OpenDirectory-specific dashboard operations
  async getOpenDirectoryDashboards(): Promise<GrafanaDashboard[]> {
    try {
      const dashboards = await this.getDashboards();
      return dashboards.filter(d => 
        d.tags?.includes('opendirectory') || 
        d.title.toLowerCase().includes('opendirectory') ||
        d.folderTitle === 'OpenDirectory'
      );
    } catch (error) {
      logger.error('Failed to fetch OpenDirectory dashboards:', error);
      return [];
    }
  }

  async createOpenDirectoryDashboard(): Promise<any> {
    const dashboard = {
      title: 'OpenDirectory Overview',
      tags: ['opendirectory', 'overview'],
      timezone: 'utc',
      panels: [
        {
          title: 'Service Health',
          type: 'stat',
          targets: [
            {
              expr: 'up{job=~".*-service"}',
              refId: 'A',
            },
          ],
          gridPos: { h: 8, w: 12, x: 0, y: 0 },
        },
        {
          title: 'Request Rate',
          type: 'graph',
          targets: [
            {
              expr: 'sum by (service) (rate(http_requests_total[5m]))',
              refId: 'A',
            },
          ],
          gridPos: { h: 8, w: 12, x: 12, y: 0 },
        },
        {
          title: 'Authentication Events',
          type: 'graph',
          targets: [
            {
              expr: 'sum by (method) (rate(auth_attempts_total[5m]))',
              refId: 'A',
            },
          ],
          gridPos: { h: 8, w: 12, x: 0, y: 8 },
        },
        {
          title: 'Active Devices',
          type: 'singlestat',
          targets: [
            {
              expr: 'sum(device_connections_active)',
              refId: 'A',
            },
          ],
          gridPos: { h: 8, w: 12, x: 12, y: 8 },
        },
      ],
      time: {
        from: 'now-1h',
        to: 'now',
      },
      refresh: '5s',
    };

    return this.createDashboard(dashboard);
  }

  // Embed URL generation for iframe integration
  getEmbedUrl(dashboardUid: string, panelId?: number, options: any = {}): string {
    const baseUrl = SERVICES.grafana.baseUrl;
    let url = `${baseUrl}/d-solo/${dashboardUid}`;
    
    if (panelId) {
      url += `?panelId=${panelId}`;
    }
    
    const params = new URLSearchParams();
    
    // Default embed options
    params.append('orgId', '1');
    params.append('theme', options.theme || 'light');
    params.append('from', options.from || 'now-1h');
    params.append('to', options.to || 'now');
    
    if (options.refresh) params.append('refresh', options.refresh);
    if (options.var) {
      Object.entries(options.var).forEach(([key, value]) => {
        params.append(`var-${key}`, value as string);
      });
    }
    
    return `${url}${url.includes('?') ? '&' : '?'}${params.toString()}`;
  }

  getDashboardEmbedUrl(dashboardUid: string, options: any = {}): string {
    return this.getEmbedUrl(dashboardUid, undefined, options);
  }

  getPanelEmbedUrl(dashboardUid: string, panelId: number, options: any = {}): string {
    return this.getEmbedUrl(dashboardUid, panelId, options);
  }
}