import { Router, Request, Response } from 'express';
import { GrafanaService } from '../services/grafana.service';
import logger from '../lib/logger';

const router = Router();
const grafanaService = new GrafanaService();

// Dashboard endpoints
router.get('/dashboards', async (req: Request, res: Response) => {
  try {
    const dashboards = await grafanaService.getDashboards();
    res.json({ dashboards, total: dashboards.length });
  } catch (error) {
    logger.error('Failed to fetch Grafana dashboards:', error);
    res.status(500).json({ error: 'Failed to fetch dashboards' });
  }
});

router.get('/dashboards/opendirectory', async (req: Request, res: Response) => {
  try {
    const dashboards = await grafanaService.getOpenDirectoryDashboards();
    res.json({ dashboards, total: dashboards.length });
  } catch (error) {
    logger.error('Failed to fetch OpenDirectory dashboards:', error);
    res.status(500).json({ error: 'Failed to fetch OpenDirectory dashboards' });
  }
});

router.get('/dashboards/uid/:uid', async (req: Request, res: Response) => {
  try {
    const { uid } = req.params;
    const dashboard = await grafanaService.getDashboard(uid);
    if (!dashboard) {
      return res.status(404).json({ error: 'Dashboard not found' });
    }
    res.json(dashboard);
  } catch (error) {
    logger.error(`Failed to fetch dashboard ${req.params.uid}:`, error);
    res.status(500).json({ error: 'Failed to fetch dashboard' });
  }
});

router.get('/dashboards/db/:slug', async (req: Request, res: Response) => {
  try {
    const { slug } = req.params;
    const dashboard = await grafanaService.getDashboardBySlug(slug);
    if (!dashboard) {
      return res.status(404).json({ error: 'Dashboard not found' });
    }
    res.json(dashboard);
  } catch (error) {
    logger.error(`Failed to fetch dashboard by slug ${req.params.slug}:`, error);
    res.status(500).json({ error: 'Failed to fetch dashboard' });
  }
});

router.post('/dashboards', async (req: Request, res: Response) => {
  try {
    const { dashboard } = req.body;
    if (!dashboard) {
      return res.status(400).json({ error: 'Dashboard object is required' });
    }
    
    const result = await grafanaService.createDashboard(dashboard);
    res.status(201).json(result);
  } catch (error) {
    logger.error('Failed to create dashboard:', error);
    res.status(500).json({ error: 'Failed to create dashboard' });
  }
});

router.put('/dashboards', async (req: Request, res: Response) => {
  try {
    const { dashboard } = req.body;
    if (!dashboard) {
      return res.status(400).json({ error: 'Dashboard object is required' });
    }
    
    const result = await grafanaService.updateDashboard(dashboard);
    res.json(result);
  } catch (error) {
    logger.error('Failed to update dashboard:', error);
    res.status(500).json({ error: 'Failed to update dashboard' });
  }
});

router.delete('/dashboards/uid/:uid', async (req: Request, res: Response) => {
  try {
    const { uid } = req.params;
    const success = await grafanaService.deleteDashboard(uid);
    if (success) {
      res.status(204).send();
    } else {
      res.status(500).json({ error: 'Failed to delete dashboard' });
    }
  } catch (error) {
    logger.error(`Failed to delete dashboard ${req.params.uid}:`, error);
    res.status(500).json({ error: 'Failed to delete dashboard' });
  }
});

// Folder endpoints
router.get('/folders', async (req: Request, res: Response) => {
  try {
    const folders = await grafanaService.getFolders();
    res.json({ folders, total: folders.length });
  } catch (error) {
    logger.error('Failed to fetch Grafana folders:', error);
    res.status(500).json({ error: 'Failed to fetch folders' });
  }
});

router.post('/folders', async (req: Request, res: Response) => {
  try {
    const { title, uid } = req.body;
    if (!title) {
      return res.status(400).json({ error: 'Folder title is required' });
    }
    
    const folder = await grafanaService.createFolder(title, uid);
    res.status(201).json(folder);
  } catch (error) {
    logger.error('Failed to create folder:', error);
    res.status(500).json({ error: 'Failed to create folder' });
  }
});

// Data source endpoints
router.get('/datasources', async (req: Request, res: Response) => {
  try {
    const dataSources = await grafanaService.getDataSources();
    res.json({ dataSources, total: dataSources.length });
  } catch (error) {
    logger.error('Failed to fetch Grafana data sources:', error);
    res.status(500).json({ error: 'Failed to fetch data sources' });
  }
});

router.post('/datasources', async (req: Request, res: Response) => {
  try {
    const dataSource = req.body;
    const result = await grafanaService.createDataSource(dataSource);
    res.status(201).json(result);
  } catch (error) {
    logger.error('Failed to create data source:', error);
    res.status(500).json({ error: 'Failed to create data source' });
  }
});

// Query endpoints
router.post('/query', async (req: Request, res: Response) => {
  try {
    const { datasourceId, query } = req.body;
    if (!datasourceId || !query) {
      return res.status(400).json({ error: 'datasourceId and query are required' });
    }
    
    const result = await grafanaService.queryPanel(datasourceId, query);
    res.json(result);
  } catch (error) {
    logger.error('Failed to execute panel query:', error);
    res.status(500).json({ error: 'Failed to execute query' });
  }
});

// Annotation endpoints
router.get('/annotations', async (req: Request, res: Response) => {
  try {
    const dashboardId = req.query.dashboardId ? parseInt(req.query.dashboardId as string) : undefined;
    const from = req.query.from ? parseInt(req.query.from as string) : undefined;
    const to = req.query.to ? parseInt(req.query.to as string) : undefined;
    
    const annotations = await grafanaService.getAnnotations(dashboardId, from, to);
    res.json({ annotations, total: annotations.length });
  } catch (error) {
    logger.error('Failed to fetch annotations:', error);
    res.status(500).json({ error: 'Failed to fetch annotations' });
  }
});

router.post('/annotations', async (req: Request, res: Response) => {
  try {
    const annotation = req.body;
    const result = await grafanaService.createAnnotation(annotation);
    res.status(201).json(result);
  } catch (error) {
    logger.error('Failed to create annotation:', error);
    res.status(500).json({ error: 'Failed to create annotation' });
  }
});

// Alert endpoints
router.get('/alerts', async (req: Request, res: Response) => {
  try {
    const alerts = await grafanaService.getAlerts();
    res.json({ alerts, total: alerts.length });
  } catch (error) {
    logger.error('Failed to fetch Grafana alerts:', error);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

router.get('/alert-notifications', async (req: Request, res: Response) => {
  try {
    const notifications = await grafanaService.getAlertNotifications();
    res.json({ notifications, total: notifications.length });
  } catch (error) {
    logger.error('Failed to fetch alert notifications:', error);
    res.status(500).json({ error: 'Failed to fetch alert notifications' });
  }
});

// User and organization endpoints
router.get('/user', async (req: Request, res: Response) => {
  try {
    const user = await grafanaService.getCurrentUser();
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    logger.error('Failed to fetch current user:', error);
    res.status(500).json({ error: 'Failed to fetch current user' });
  }
});

router.get('/org', async (req: Request, res: Response) => {
  try {
    const org = await grafanaService.getOrganization();
    if (!org) {
      return res.status(404).json({ error: 'Organization not found' });
    }
    res.json(org);
  } catch (error) {
    logger.error('Failed to fetch organization:', error);
    res.status(500).json({ error: 'Failed to fetch organization' });
  }
});

// Embed URL generation
router.get('/embed/dashboard/:uid', async (req: Request, res: Response) => {
  try {
    const { uid } = req.params;
    const options = req.query;
    const embedUrl = grafanaService.getDashboardEmbedUrl(uid, options);
    res.json({ embedUrl });
  } catch (error) {
    logger.error('Failed to generate dashboard embed URL:', error);
    res.status(500).json({ error: 'Failed to generate embed URL' });
  }
});

router.get('/embed/panel/:uid/:panelId', async (req: Request, res: Response) => {
  try {
    const { uid, panelId } = req.params;
    const options = req.query;
    const embedUrl = grafanaService.getPanelEmbedUrl(uid, parseInt(panelId), options);
    res.json({ embedUrl });
  } catch (error) {
    logger.error('Failed to generate panel embed URL:', error);
    res.status(500).json({ error: 'Failed to generate embed URL' });
  }
});

// Service status
router.get('/status', async (req: Request, res: Response) => {
  try {
    const status = await grafanaService.getServiceStatus();
    const httpStatus = status.status === 'healthy' ? 200 : 503;
    res.status(httpStatus).json(status);
  } catch (error) {
    logger.error('Failed to get Grafana service status:', error);
    res.status(500).json({ error: 'Failed to get service status' });
  }
});

// OpenDirectory dashboard management
router.post('/setup/opendirectory', async (req: Request, res: Response) => {
  try {
    // Create OpenDirectory folder if it doesn't exist
    const folders = await grafanaService.getFolders();
    let odFolder = folders.find(f => f.title === 'OpenDirectory');
    
    if (!odFolder) {
      odFolder = await grafanaService.createFolder('OpenDirectory', 'opendirectory');
    }

    // Create default OpenDirectory dashboard
    const dashboard = await grafanaService.createOpenDirectoryDashboard();
    
    res.status(201).json({
      folder: odFolder,
      dashboard,
      message: 'OpenDirectory Grafana setup completed successfully',
    });
  } catch (error) {
    logger.error('Failed to setup OpenDirectory Grafana integration:', error);
    res.status(500).json({ error: 'Failed to setup OpenDirectory integration' });
  }
});

// Proxy endpoints for direct Grafana integration
router.get('/proxy/*', async (req: Request, res: Response) => {
  try {
    // This allows proxying arbitrary Grafana API calls
    const path = req.path.replace('/proxy', '');
    const method = req.method.toLowerCase() as 'get' | 'post' | 'put' | 'delete';
    
    let result;
    switch (method) {
      case 'get':
        result = await (grafanaService as any).client.get(path, { params: req.query });
        break;
      case 'post':
        result = await (grafanaService as any).client.post(path, req.body);
        break;
      case 'put':
        result = await (grafanaService as any).client.put(path, req.body);
        break;
      case 'delete':
        result = await (grafanaService as any).client.delete(path);
        break;
      default:
        return res.status(405).json({ error: 'Method not allowed' });
    }
    
    res.json(result);
  } catch (error) {
    logger.error('Grafana proxy request failed:', error);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({ error: 'Proxy request failed' });
    }
  }
});

export default router;