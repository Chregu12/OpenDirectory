'use client';

import React, { useState, useEffect } from 'react';
import {
  ServerIcon,
  ShieldCheckIcon,
  Cog6ToothIcon,
  ChartBarIcon,
  WifiIcon,
  ComputerDesktopIcon,
  CloudIcon,
  PrinterIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';
import { healthApi, gatewayApi } from '@/lib/api';

type Status = 'healthy' | 'unhealthy' | 'unknown';

interface Node {
  id: string;
  name: string;
  type: 'gateway' | 'core' | 'module' | 'external';
  status: Status;
  port?: number;
  connections: string[];
  x: number; // 0–800
  y: number; // 0–600
  icon: React.ComponentType<any>;
  color: string;
}

// Static topology — always shown regardless of API availability
const BASE_NODES: Omit<Node, 'status'>[] = [
  // Gateway – centre
  { id: 'gateway',      name: 'API Gateway',     type: 'gateway',  connections: [],                         x: 400, y: 280, icon: ServerIcon,          color: '#3b82f6' },
  // Core services – top arc
  { id: 'auth',         name: 'Auth',            type: 'core',     connections: ['gateway'],                x: 200, y: 100, icon: ShieldCheckIcon,      color: '#10b981' },
  { id: 'config',       name: 'Config',          type: 'core',     connections: ['gateway'],                x: 400, y:  80, icon: Cog6ToothIcon,         color: '#8b5cf6' },
  { id: 'health',       name: 'Health',          type: 'core',     connections: ['gateway'],                x: 600, y: 100, icon: ChartBarIcon,          color: '#ef4444' },
  // Module services – sides
  { id: 'network',      name: 'Network',         type: 'module',   connections: ['gateway'],                x:  80, y: 280, icon: WifiIcon,             color: '#06b6d4' },
  { id: 'devices',      name: 'Devices',         type: 'module',   connections: ['gateway'],                x: 720, y: 280, icon: ComputerDesktopIcon,  color: '#6366f1' },
  { id: 'printer',      name: 'Printer',         type: 'module',   connections: ['gateway'],                x: 720, y: 420, icon: PrinterIcon,          color: '#6b7280' },
  // External services – bottom arc
  { id: 'lldap',        name: 'LLDAP',           type: 'external', connections: ['gateway', 'auth'],        x: 160, y: 480, icon: CloudIcon,            color: '#f59e0b' },
  { id: 'grafana',      name: 'Grafana',         type: 'external', connections: ['gateway'],                x: 340, y: 500, icon: ChartBarIcon,         color: '#f97316' },
  { id: 'prometheus',   name: 'Prometheus',      type: 'external', connections: ['gateway', 'grafana'],     x: 520, y: 480, icon: ChartBarIcon,         color: '#ef4444' },
  { id: 'vault',        name: 'Vault',           type: 'external', connections: ['gateway'],                x:  80, y: 430, icon: ShieldCheckIcon,      color: '#eab308' },
];

const STATUS_COLOR: Record<Status, string> = {
  healthy:  '#10b981',
  unhealthy:'#ef4444',
  unknown:  '#f59e0b',
};

const TYPE_SIZE: Record<Node['type'], number> = {
  gateway: 36,
  core:    26,
  module:  22,
  external:20,
};

export default function TopologyView() {
  const [nodes, setNodes] = useState<Node[]>(
    BASE_NODES.map(n => ({ ...n, status: 'unknown' as Status }))
  );
  const [selected, setSelected] = useState<Node | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadStatus();
    const interval = setInterval(loadStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const loadStatus = async () => {
    try {
      // Try health endpoint for service statuses
      const statusMap: Record<string, Status> = { gateway: 'healthy' };

      try {
        const healthRes = await healthApi.getOverallHealth();
        const services: { name: string; status: Status }[] = healthRes.data.services || [];
        services.forEach(s => {
          const id = s.name.toLowerCase().replace(/[\s-]service$/i, '').replace(/\s+/g, '-');
          statusMap[id] = s.status;
        });
      } catch {}

      try {
        const gatewayRes = await gatewayApi.getServices();
        const services: { name: string; status: Status }[] = gatewayRes.data || [];
        services.forEach(s => {
          const id = s.name.toLowerCase().replace(/[\s-]service$/i, '').replace(/\s+/g, '-');
          statusMap[id] = s.status;
        });
      } catch {}

      setNodes(BASE_NODES.map(n => ({
        ...n,
        status: statusMap[n.id] ?? 'unknown',
      })));
    } catch {}
    finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const refresh = () => { setRefreshing(true); loadStatus(); };

  // SVG viewport: 800 × 600
  const W = 800, H = 600;

  const getStatusIcon = (status: Status) => {
    if (status === 'healthy')   return <CheckCircleIcon className="w-4 h-4 text-green-500" />;
    if (status === 'unhealthy') return <XCircleIcon className="w-4 h-4 text-red-500" />;
    return <ExclamationTriangleIcon className="w-4 h-4 text-yellow-500" />;
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Network Topology</h1>
          <p className="text-sm text-gray-500 mt-1">Service architecture overview</p>
        </div>
        <div className="flex items-center gap-4">
          {/* Legend */}
          <div className="flex items-center gap-4 text-xs text-gray-600">
            {(['healthy', 'unknown', 'unhealthy'] as Status[]).map(s => (
              <span key={s} className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ backgroundColor: STATUS_COLOR[s] }} />
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </span>
            ))}
          </div>
          <button
            onClick={refresh}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-lg hover:bg-gray-50"
          >
            <ArrowPathIcon className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Canvas */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="w-full"
          style={{ height: 520 }}
        >
          {/* Grid background */}
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#f3f4f6" strokeWidth="1"/>
            </pattern>
          </defs>
          <rect width={W} height={H} fill="url(#grid)" />

          {/* Connection lines */}
          {nodes.map(node =>
            node.connections.map(targetId => {
              const target = nodes.find(n => n.id === targetId);
              if (!target) return null;
              const isExt = node.type === 'external' || target.type === 'external';
              return (
                <line
                  key={`${node.id}→${targetId}`}
                  x1={node.x} y1={node.y}
                  x2={target.x} y2={target.y}
                  stroke={isExt ? '#d1d5db' : '#93c5fd'}
                  strokeWidth={isExt ? 1.5 : 2}
                  strokeDasharray={isExt ? '6 4' : undefined}
                  opacity={0.7}
                />
              );
            })
          )}

          {/* Nodes */}
          {nodes.map(node => {
            const r = TYPE_SIZE[node.type];
            const isSelected = selected?.id === node.id;
            return (
              <g
                key={node.id}
                transform={`translate(${node.x},${node.y})`}
                onClick={() => setSelected(isSelected ? null : node)}
                style={{ cursor: 'pointer' }}
              >
                {/* Outer ring when selected */}
                {isSelected && (
                  <circle r={r + 8} fill="none" stroke="#3b82f6" strokeWidth="2" opacity="0.5" />
                )}
                {/* Node circle */}
                <circle
                  r={r}
                  fill={node.color}
                  opacity={loading ? 0.5 : 1}
                />
                {/* Status dot */}
                <circle
                  cx={r * 0.7}
                  cy={-(r * 0.7)}
                  r={5}
                  fill={STATUS_COLOR[node.status]}
                  stroke="white"
                  strokeWidth="1.5"
                />
                {/* Label */}
                <text
                  y={r + 14}
                  textAnchor="middle"
                  fontSize={10}
                  fontWeight={node.type === 'gateway' ? 700 : 500}
                  fill="#374151"
                >
                  {node.name}
                </text>
                {node.port && (
                  <text y={r + 25} textAnchor="middle" fontSize={9} fill="#9ca3af">
                    :{node.port}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: selected.color + '20' }}>
                <selected.icon className="w-6 h-6" style={{ color: selected.color }} />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">{selected.name}</h3>
                <p className="text-sm text-gray-500 capitalize">{selected.type} service</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {getStatusIcon(selected.status)}
              <span className="text-sm font-medium capitalize text-gray-700">{selected.status}</span>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-6 text-sm">
            <div>
              <p className="text-gray-500 mb-1">Type</p>
              <p className="font-medium text-gray-900 capitalize">{selected.type}</p>
            </div>
            <div>
              <p className="text-gray-500 mb-1">Connections</p>
              <p className="font-medium text-gray-900">{selected.connections.length} upstream</p>
            </div>
            <div>
              <p className="text-gray-500 mb-1">Status</p>
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                selected.status === 'healthy'   ? 'bg-green-100 text-green-800' :
                selected.status === 'unhealthy' ? 'bg-red-100 text-red-800'   :
                                                  'bg-yellow-100 text-yellow-800'
              }`}>
                {selected.status}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
