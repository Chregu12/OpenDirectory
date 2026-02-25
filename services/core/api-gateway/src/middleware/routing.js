const logger = require('../config/logger');

class RoutingMiddleware {
  constructor() {
    // Define route mappings for all services
    this.routeMappings = {
      // Core Services
      '/api/auth': {
        service: 'authentication-service',
        port: 3001,
        description: 'Authentication & Authorization'
      },
      '/api/config': {
        service: 'configuration-service',
        port: 3002,
        description: 'Configuration Management'
      },
      
      // Device Management
      '/api/devices': {
        service: 'device-service',
        port: 3003,
        description: 'Device Management'
      },
      '/api/device': {
        service: 'device-service',
        port: 3003,
        description: 'Device Management (singular)'
      },
      
      // Policy Management
      '/api/policies': {
        service: 'policy-service',
        port: 3004,
        description: 'Policy Engine'
      },
      '/api/policy': {
        service: 'policy-compliance',
        port: 3010,
        description: 'Policy Compliance'
      },
      '/api/compliance': {
        service: 'policy-compliance',
        port: 3010,
        description: 'Compliance Scanning'
      },
      
      // Integration Services
      '/api/external': {
        service: 'integration-service',
        port: 3005,
        description: 'External Integrations'
      },
      '/api/lldap': {
        service: 'integration-service',
        port: 3005,
        description: 'LLDAP Integration'
      },
      '/api/grafana': {
        service: 'integration-service',
        port: 3005,
        description: 'Grafana Integration'
      },
      '/api/prometheus': {
        service: 'integration-service',
        port: 3005,
        description: 'Prometheus Integration'
      },
      '/api/vault': {
        service: 'integration-service',
        port: 3005,
        description: 'Vault Integration'
      },
      
      // Printer Management
      '/api/printer': {
        service: 'printer-service',
        port: 3006,
        description: 'Printer Management'
      },
      '/api/printers': {
        service: 'printer-service',
        port: 3006,
        description: 'Printer Management (plural)'
      },
      '/api/scanning': {
        service: 'printer-service',
        port: 3006,
        description: 'Scanner Management'
      },
      
      // Network Infrastructure
      '/api/network': {
        service: 'network-infrastructure',
        port: 3007,
        description: 'Network Infrastructure'
      },
      '/api/dns': {
        service: 'network-infrastructure',
        port: 3007,
        description: 'DNS Management'
      },
      '/api/dhcp': {
        service: 'network-infrastructure',
        port: 3007,
        description: 'DHCP Management'
      },
      '/api/shares': {
        service: 'network-infrastructure',
        port: 3007,
        description: 'File Share Management'
      },
      
      // Security Suite
      '/api/security': {
        service: 'security-suite',
        port: 3008,
        description: 'Security Management'
      },
      '/api/threat': {
        service: 'security-suite',
        port: 3008,
        description: 'Threat Intelligence'
      },
      '/api/dlp': {
        service: 'security-suite',
        port: 3008,
        description: 'Data Loss Prevention'
      },
      '/api/pam': {
        service: 'security-suite',
        port: 3008,
        description: 'Privileged Access Management'
      },
      
      // Monitoring & Analytics
      '/api/monitoring': {
        service: 'monitoring-analytics',
        port: 3009,
        description: 'System Monitoring'
      },
      '/api/analytics': {
        service: 'monitoring-analytics',
        port: 3009,
        description: 'Analytics Engine'
      },
      '/api/metrics': {
        service: 'monitoring-analytics',
        port: 3009,
        description: 'Metrics Collection'
      },
      
      // Backup & DR
      '/api/backup': {
        service: 'backup-disaster',
        port: 3011,
        description: 'Backup Management'
      },
      '/api/dr': {
        service: 'backup-disaster',
        port: 3011,
        description: 'Disaster Recovery'
      },
      '/api/restore': {
        service: 'backup-disaster',
        port: 3011,
        description: 'Restore Operations'
      },
      
      // Automation & Workflows
      '/api/automation': {
        service: 'automation-workflows',
        port: 3012,
        description: 'Automation Engine'
      },
      '/api/workflows': {
        service: 'automation-workflows',
        port: 3012,
        description: 'Workflow Management'
      },
      '/api/scheduler': {
        service: 'automation-workflows',
        port: 3012,
        description: 'Task Scheduler'
      },
      
      // Container & Cloud
      '/api/containers': {
        service: 'container-orchestration',
        port: 3013,
        description: 'Container Management'
      },
      '/api/k8s': {
        service: 'container-orchestration',
        port: 3013,
        description: 'Kubernetes Management'
      },
      '/api/docker': {
        service: 'container-orchestration',
        port: 3013,
        description: 'Docker Management'
      },
      '/api/cloud': {
        service: 'container-orchestration',
        port: 3013,
        description: 'Cloud Management'
      },
      
      // Enterprise Integrations
      '/api/integrations': {
        service: 'enterprise-integrations',
        port: 3014,
        description: 'Enterprise Integrations'
      },
      '/api/erp': {
        service: 'enterprise-integrations',
        port: 3014,
        description: 'ERP Connector'
      },
      '/api/sap': {
        service: 'enterprise-integrations',
        port: 3014,
        description: 'SAP Connector'
      },
      '/api/o365': {
        service: 'enterprise-integrations',
        port: 3014,
        description: 'Office 365 Connector'
      },
      
      // AI & ML
      '/api/ai': {
        service: 'ai-intelligence',
        port: 3015,
        description: 'AI Intelligence'
      },
      '/api/ml': {
        service: 'ai-intelligence',
        port: 3015,
        description: 'Machine Learning'
      },
      '/api/predictions': {
        service: 'ai-intelligence',
        port: 3015,
        description: 'Predictive Analytics'
      },
      '/api/anomalies': {
        service: 'ai-intelligence',
        port: 3015,
        description: 'Anomaly Detection'
      },
      
      // Notifications
      '/api/notifications': {
        service: 'notification-service',
        port: 3016,
        description: 'Notification Service'
      },
      '/api/alerts': {
        service: 'notification-service',
        port: 3016,
        description: 'Alert Management'
      },
      
      // Deployment
      '/api/deployment': {
        service: 'deployment-service',
        port: 3017,
        description: 'Deployment Service'
      },
      '/api/apps': {
        service: 'deployment-service',
        port: 3017,
        description: 'App Deployment'
      },
      
      // Identity Management
      '/api/identity': {
        service: 'identity-service',
        port: 3001,
        description: 'Identity Management'
      },
      '/api/users': {
        service: 'identity-service',
        port: 3001,
        description: 'User Management'
      },
      '/api/groups': {
        service: 'identity-service',
        port: 3001,
        description: 'Group Management'
      },
      '/api/roles': {
        service: 'identity-service',
        port: 3001,
        description: 'Role Management'
      }
    };
    
    // Track request metrics
    this.requestMetrics = new Map();
  }

  middleware() {
    return (req, res, next) => {
      const startTime = Date.now();
      
      // Log incoming request
      logger.debug(`Routing request: ${req.method} ${req.path}`);
      
      // Find matching route
      const route = this.findRoute(req.path);
      if (route) {
        req.targetService = route;
        logger.debug(`Route matched: ${req.path} -> ${route.service}:${route.port}`);
      }
      
      // Track metrics
      this.trackRequest(req.path, req.method);
      
      // Add response time tracking
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.performance(`Route ${req.path}`, duration, {
          method: req.method,
          status: res.statusCode,
          service: route?.service
        });
      });
      
      next();
    };
  }

  findRoute(path) {
    // Direct match
    if (this.routeMappings[path]) {
      return this.routeMappings[path];
    }
    
    // Prefix match
    for (const [routePath, routeConfig] of Object.entries(this.routeMappings)) {
      if (path.startsWith(routePath + '/') || path === routePath) {
        return routeConfig;
      }
    }
    
    return null;
  }

  trackRequest(path, method) {
    const key = `${method}:${path}`;
    const current = this.requestMetrics.get(key) || { count: 0, lastAccess: null };
    current.count++;
    current.lastAccess = new Date();
    this.requestMetrics.set(key, current);
  }

  getRouteStats() {
    const stats = {};
    for (const [key, value] of this.requestMetrics) {
      stats[key] = value;
    }
    return stats;
  }

  getAllRoutes() {
    return Object.entries(this.routeMappings).map(([path, config]) => ({
      path,
      ...config
    }));
  }

  getServiceRoutes(serviceName) {
    return Object.entries(this.routeMappings)
      .filter(([path, config]) => config.service === serviceName)
      .map(([path, config]) => ({
        path,
        ...config
      }));
  }

  addRoute(path, service, port, description) {
    this.routeMappings[path] = {
      service,
      port,
      description
    };
    logger.info(`Added route: ${path} -> ${service}:${port}`);
  }

  removeRoute(path) {
    delete this.routeMappings[path];
    logger.info(`Removed route: ${path}`);
  }

  updateRoute(path, updates) {
    if (this.routeMappings[path]) {
      this.routeMappings[path] = {
        ...this.routeMappings[path],
        ...updates
      };
      logger.info(`Updated route: ${path}`);
    }
  }
}

// Singleton instance
const routingMiddleware = new RoutingMiddleware();

module.exports = routingMiddleware.middleware();
module.exports.getAllRoutes = routingMiddleware.getAllRoutes.bind(routingMiddleware);
module.exports.getServiceRoutes = routingMiddleware.getServiceRoutes.bind(routingMiddleware);
module.exports.getRouteStats = routingMiddleware.getRouteStats.bind(routingMiddleware);
module.exports.addRoute = routingMiddleware.addRoute.bind(routingMiddleware);
module.exports.removeRoute = routingMiddleware.removeRoute.bind(routingMiddleware);
module.exports.updateRoute = routingMiddleware.updateRoute.bind(routingMiddleware);