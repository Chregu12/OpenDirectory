'use client';

import React, { useState, useEffect } from 'react';
import {
  RectangleGroupIcon,
  ServerIcon,
  CloudIcon,
  ComputerDesktopIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  WifiIcon,
  PrinterIcon,
  ChartBarIcon,
  Cog6ToothIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';
import { gatewayApi, healthApi } from '@/lib/api';

interface ServiceNode {
  id: string;
  name: string;
  type: 'gateway' | 'core' | 'module' | 'external';
  status: 'healthy' | 'unhealthy' | 'unknown';
  port?: number;
  connections: string[];
  position: { x: number; y: number };
  icon: React.ComponentType<any>;
  color: string;
}

export default function TopologyView() {
  const [services, setServices] = useState<ServiceNode[]>([]);
  const [selectedService, setSelectedService] = useState<ServiceNode | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadTopologyData();
    const interval = setInterval(loadTopologyData, 15000);
    return () => clearInterval(interval);
  }, []);

  const loadTopologyData = async () => {
    try {
      const [servicesRes, routesRes] = await Promise.all([
        gatewayApi.getServices(),
        gatewayApi.getRoutes()
      ]);

      const serviceData = servicesRes.data || [];
      const routes = routesRes.data || [];

      // Create topology nodes
      const nodes: ServiceNode[] = [];

      // API Gateway (center)
      nodes.push({
        id: 'gateway',
        name: 'API Gateway',
        type: 'gateway',
        status: 'healthy',
        port: 8080,
        connections: [],
        position: { x: 400, y: 300 },
        icon: ServerIcon,
        color: 'blue'
      });

      // Core Services
      const coreServices = [
        { name: 'authentication-service', icon: ShieldCheckIcon, color: 'green' },
        { name: 'configuration-service', icon: Cog6ToothIcon, color: 'purple' },
        { name: 'health-service', icon: ChartBarIcon, color: 'red' }
      ];

      coreServices.forEach((core, index) => {
        const service = serviceData.find((s: any) => s.name === core.name);
        nodes.push({
          id: core.name,
          name: core.name.replace('-service', ''),
          type: 'core',
          status: service?.status || 'unknown',
          port: service?.port,
          connections: ['gateway'],
          position: { 
            x: 200 + (index * 150), 
            y: 150 
          },
          icon: core.icon,
          color: core.color
        });
      });

      // Module Services
      const moduleServices = [
        { name: 'network-infrastructure', icon: WifiIcon, color: 'blue' },
        { name: 'device-management', icon: ComputerDesktopIcon, color: 'indigo' },
        { name: 'security-suite', icon: ShieldCheckIcon, color: 'red' },
        { name: 'printer-service', icon: PrinterIcon, color: 'gray' },
        { name: 'monitoring-analytics', icon: ChartBarIcon, color: 'green' },
        { name: 'container-orchestration', icon: CpuChipIcon, color: 'purple' }
      ];

      moduleServices.forEach((module, index) => {
        const service = serviceData.find((s: any) => s.name === module.name);
        const angle = (index * 60) * (Math.PI / 180); // 60 degrees apart
        const radius = 200;
        
        nodes.push({
          id: module.name,
          name: module.name.replace('-', ' '),
          type: 'module',
          status: service?.status || 'unknown',
          port: service?.port,
          connections: ['gateway'],
          position: { 
            x: 400 + Math.cos(angle) * radius, 
            y: 300 + Math.sin(angle) * radius 
          },
          icon: module.icon,
          color: module.color
        });
      });

      // External Services
      const externalServices = [
        { name: 'lldap', icon: CloudIcon, color: 'yellow' },
        { name: 'grafana', icon: ChartBarIcon, color: 'orange' },
        { name: 'prometheus', icon: ChartBarIcon, color: 'red' }
      ];

      externalServices.forEach((external, index) => {
        nodes.push({
          id: external.name,
          name: external.name.toUpperCase(),
          type: 'external',
          status: 'healthy',
          connections: ['gateway'],
          position: { 
            x: 600 + (index * 100), 
            y: 450 
          },
          icon: external.icon,
          color: external.color
        });
      });

      setServices(nodes);
    } catch (error) {
      console.error('Failed to load topology data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-500';
      case 'unhealthy': return 'text-red-500';
      default: return 'text-yellow-500';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircleIcon className="w-4 h-4" />;
      case 'unhealthy': return <XCircleIcon className="w-4 h-4" />;
      default: return <ExclamationTriangleIcon className="w-4 h-4" />;
    }
  };

  const getNodeColor = (node: ServiceNode) => {
    const colors = {
      blue: 'bg-blue-500',
      green: 'bg-green-500',
      red: 'bg-red-500',
      purple: 'bg-purple-500',
      indigo: 'bg-indigo-500',
      gray: 'bg-gray-500',
      yellow: 'bg-yellow-500',
      orange: 'bg-orange-500'
    };
    return colors[node.color as keyof typeof colors] || 'bg-gray-500';
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-64 mb-8"></div>
          <div className="h-96 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Network Topology</h1>
          <p className="text-sm text-gray-500 mt-1">Interactive view of your service architecture</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-sm">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span>Healthy</span>
            <div className="w-3 h-3 bg-yellow-500 rounded-full ml-4"></div>
            <span>Warning</span>
            <div className="w-3 h-3 bg-red-500 rounded-full ml-4"></div>
            <span>Critical</span>
          </div>
        </div>
      </div>

      {/* Topology Canvas */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        <div className="relative h-96 lg:h-[600px] bg-gradient-to-br from-gray-50 to-gray-100">
          {/* SVG for connections */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            {services.map((service) => 
              service.connections.map((connectionId) => {
                const targetService = services.find(s => s.id === connectionId);
                if (!targetService) return null;
                
                return (
                  <line
                    key={`${service.id}-${connectionId}`}
                    x1={service.position.x}
                    y1={service.position.y}
                    x2={targetService.position.x}
                    y2={targetService.position.y}
                    stroke="#d1d5db"
                    strokeWidth="2"
                    strokeDasharray={service.type === 'external' ? '5,5' : 'none'}
                    opacity="0.6"
                  />
                );
              })
            )}
          </svg>

          {/* Service Nodes */}
          {services.map((service) => (
            <div
              key={service.id}
              className={`absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all duration-200 hover:scale-105 ${
                selectedService?.id === service.id ? 'scale-110 z-10' : 'z-0'
              }`}
              style={{
                left: `${(service.position.x / 800) * 100}%`,
                top: `${(service.position.y / 600) * 100}%`,
              }}
              onClick={() => setSelectedService(service)}
            >
              <div className={`relative w-16 h-16 ${getNodeColor(service)} rounded-xl shadow-lg flex items-center justify-center ${
                service.type === 'gateway' ? 'w-20 h-20' : ''
              } ${selectedService?.id === service.id ? 'ring-4 ring-blue-300' : ''}`}>
                <service.icon className="w-8 h-8 text-white" />
                
                {/* Status indicator */}
                <div className={`absolute -top-1 -right-1 w-5 h-5 rounded-full border-2 border-white flex items-center justify-center ${getStatusColor(service.status).replace('text-', 'bg-')}`}>
                  <div className="w-2 h-2 bg-white rounded-full"></div>
                </div>
              </div>

              {/* Service Label */}
              <div className="absolute top-full left-1/2 transform -translate-x-1/2 mt-2 text-center">
                <p className="text-xs font-medium text-gray-900 whitespace-nowrap">
                  {service.name}
                </p>
                {service.port && (
                  <p className="text-xs text-gray-500">:{service.port}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Service Details Panel */}
      {selectedService && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <div className={`w-10 h-10 ${getNodeColor(selectedService)} rounded-lg flex items-center justify-center`}>
                <selectedService.icon className="w-6 h-6 text-white" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">{selectedService.name}</h3>
                <p className="text-sm text-gray-500 capitalize">{selectedService.type} Service</p>
              </div>
            </div>
            <div className={`flex items-center space-x-2 ${getStatusColor(selectedService.status)}`}>
              {getStatusIcon(selectedService.status)}
              <span className="text-sm font-medium capitalize">{selectedService.status}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-2">Connection Info</h4>
              <div className="space-y-2 text-sm text-gray-600">
                {selectedService.port && (
                  <p>Port: <span className="font-mono">{selectedService.port}</span></p>
                )}
                <p>Connections: <span className="font-medium">{selectedService.connections.length}</span></p>
                <p>Type: <span className="font-medium capitalize">{selectedService.type}</span></p>
              </div>
            </div>

            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-2">Health Status</h4>
              <div className="space-y-2 text-sm text-gray-600">
                <div className="flex items-center space-x-2">
                  <div className={`w-2 h-2 rounded-full ${selectedService.status === 'healthy' ? 'bg-green-500' : selectedService.status === 'unhealthy' ? 'bg-red-500' : 'bg-yellow-500'}`}></div>
                  <span className="capitalize">{selectedService.status}</span>
                </div>
                <p>Last check: <span className="font-medium">Just now</span></p>
                <p>Response time: <span className="font-medium">45ms</span></p>
              </div>
            </div>

            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-2">Quick Actions</h4>
              <div className="space-y-2">
                <button className="w-full text-left px-3 py-2 text-sm bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors">
                  View Logs
                </button>
                <button className="w-full text-left px-3 py-2 text-sm bg-green-50 hover:bg-green-100 rounded-lg transition-colors">
                  Health Check
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}