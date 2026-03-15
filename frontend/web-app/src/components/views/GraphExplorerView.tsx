'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  MagnifyingGlassIcon,
  ArrowPathIcon,
  FunnelIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  UserGroupIcon,
  ComputerDesktopIcon,
  KeyIcon,
  DocumentTextIcon,
  ArrowsPointingOutIcon,
  ArrowsPointingInIcon,
  EyeIcon,
  ChevronRightIcon,
  XMarkIcon,
  CheckCircleIcon,
  UserIcon
} from '@heroicons/react/24/outline';

// ── Types ──────────────────────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  label: string;
  type: 'user' | 'group' | 'device' | 'policy' | 'update_ring' | 'permission' | 'certificate';
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
  properties: Record<string, any>;
  x: number;
  y: number;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  properties?: Record<string, any>;
}

interface AttackPath {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium';
  path: string[];
  description: string;
  mitigation: string;
}

interface ShadowAdmin {
  userId: string;
  userName: string;
  effectivePermissions: string[];
  inheritedFrom: string[];
  riskScore: number;
}

interface GraphStats {
  totalNodes: number;
  totalEdges: number;
  nodesByType: Record<string, number>;
  density: number;
  avgConnections: number;
  riskDistribution: Record<string, number>;
}

// ── Color / Icon Maps ──────────────────────────────────────────────────────────

const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  user:        { bg: 'bg-blue-500/20',   border: 'border-blue-500',   text: 'text-blue-400' },
  group:       { bg: 'bg-purple-500/20', border: 'border-purple-500', text: 'text-purple-400' },
  device:      { bg: 'bg-green-500/20',  border: 'border-green-500',  text: 'text-green-400' },
  policy:      { bg: 'bg-amber-500/20',  border: 'border-amber-500',  text: 'text-amber-400' },
  update_ring: { bg: 'bg-cyan-500/20',   border: 'border-cyan-500',   text: 'text-cyan-400' },
  permission:  { bg: 'bg-red-500/20',    border: 'border-red-500',    text: 'text-red-400' },
  certificate: { bg: 'bg-pink-500/20',   border: 'border-pink-500',   text: 'text-pink-400' },
};

const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-500',
  high:     'text-orange-500',
  medium:   'text-yellow-500',
  low:      'text-blue-400',
  none:     'text-gray-400',
};

const NODE_ICONS: Record<string, React.ComponentType<any>> = {
  user:        UserIcon,
  group:       UserGroupIcon,
  device:      ComputerDesktopIcon,
  policy:      DocumentTextIcon,
  update_ring: ArrowPathIcon,
  permission:  KeyIcon,
  certificate: ShieldExclamationIcon,
};

// ── Mock data generators ───────────────────────────────────────────────────────

function generateMockGraph(): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const cx = 500, cy = 400;

  // Users
  const users = ['admin', 'j.smith', 'm.jones', 'k.chen', 's.patel', 'helpdesk1', 'svc-backup', 'temp-contractor'];
  users.forEach((u, i) => {
    const angle = (i / users.length) * Math.PI * 2;
    nodes.push({
      id: `user-${u}`, label: u, type: 'user',
      riskLevel: u === 'admin' ? 'critical' : u === 'svc-backup' ? 'high' : u === 'temp-contractor' ? 'medium' : 'low',
      properties: { email: `${u}@corp.local`, lastLogin: '2026-03-14', enabled: true },
      x: cx + Math.cos(angle) * 320, y: cy + Math.sin(angle) * 280,
    });
  });

  // Groups
  const groups = ['Domain Admins', 'IT-Staff', 'Developers', 'All-Users', 'Backup-Operators', 'Remote-Desktop'];
  groups.forEach((g, i) => {
    const angle = (i / groups.length) * Math.PI * 2 + 0.3;
    nodes.push({
      id: `group-${g}`, label: g, type: 'group',
      riskLevel: g === 'Domain Admins' ? 'critical' : g === 'Backup-Operators' ? 'high' : 'low',
      properties: { memberCount: Math.floor(Math.random() * 50) + 2, scope: 'Global' },
      x: cx + Math.cos(angle) * 200, y: cy + Math.sin(angle) * 180,
    });
  });

  // Devices
  const devices = ['WS-001', 'WS-002', 'LAPTOP-23', 'SRV-DC01', 'SRV-FILE01', 'MAC-DEV-01'];
  devices.forEach((d, i) => {
    const angle = (i / devices.length) * Math.PI * 2 + 0.6;
    nodes.push({
      id: `device-${d}`, label: d, type: 'device',
      riskLevel: d === 'LAPTOP-23' ? 'high' : d === 'SRV-DC01' ? 'medium' : 'low',
      properties: { os: d.startsWith('MAC') ? 'macOS 15' : d.startsWith('SRV') ? 'Windows Server 2022' : 'Windows 11', compliance: d !== 'LAPTOP-23' },
      x: cx + Math.cos(angle) * 380, y: cy + Math.sin(angle) * 340,
    });
  });

  // Policies & Update Rings
  ['Security-Baseline', 'BitLocker-Policy', 'Firewall-Rules'].forEach((p, i) => {
    nodes.push({
      id: `policy-${p}`, label: p, type: 'policy', riskLevel: 'none',
      properties: { enabled: true, assignments: Math.floor(Math.random() * 100) + 10 },
      x: 100 + i * 150, y: 100,
    });
  });
  ['Ring-Fast', 'Ring-Broad', 'Ring-Slow'].forEach((r, i) => {
    nodes.push({
      id: `ring-${r}`, label: r, type: 'update_ring', riskLevel: 'none',
      properties: { deferralDays: i * 14, deviceCount: [20, 150, 80][i] },
      x: 700 + i * 120, y: 100,
    });
  });

  // Edges – membership
  const membershipMap: Record<string, string[]> = {
    'Domain Admins': ['admin', 'svc-backup'],
    'IT-Staff': ['j.smith', 'helpdesk1'],
    'Developers': ['m.jones', 'k.chen'],
    'All-Users': ['j.smith', 'm.jones', 'k.chen', 's.patel', 'helpdesk1', 'temp-contractor'],
    'Backup-Operators': ['svc-backup', 'helpdesk1'],
    'Remote-Desktop': ['temp-contractor', 'j.smith'],
  };
  Object.entries(membershipMap).forEach(([group, members]) =>
    members.forEach(m => edges.push({ id: `e-${m}-${group}`, source: `user-${m}`, target: `group-${group}`, relationship: 'MEMBER_OF' }))
  );

  // Edges – device ownership
  [['j.smith', 'WS-001'], ['m.jones', 'WS-002'], ['k.chen', 'LAPTOP-23'], ['admin', 'SRV-DC01'], ['s.patel', 'MAC-DEV-01']].forEach(([u, d]) =>
    edges.push({ id: `e-${u}-${d}`, source: `user-${u}`, target: `device-${d}`, relationship: 'OWNS' })
  );

  // Edges – policy assignments
  [['Security-Baseline', 'All-Users'], ['BitLocker-Policy', 'All-Users'], ['Firewall-Rules', 'IT-Staff']].forEach(([p, g]) =>
    edges.push({ id: `e-${p}-${g}`, source: `policy-${p}`, target: `group-${g}`, relationship: 'ASSIGNED_TO' })
  );

  // Edges – update ring assignments
  [['Ring-Fast', 'IT-Staff'], ['Ring-Broad', 'All-Users'], ['Ring-Slow', 'Developers']].forEach(([r, g]) =>
    edges.push({ id: `e-${r}-${g}`, source: `ring-${r}`, target: `group-${g}`, relationship: 'TARGETS' })
  );

  return { nodes, edges };
}

function generateAttackPaths(): AttackPath[] {
  return [
    {
      id: 'ap-1', name: 'Service Account → Domain Admin',
      severity: 'critical',
      path: ['user-svc-backup', 'group-Backup-Operators', 'group-Domain Admins'],
      description: 'svc-backup is member of Backup-Operators, which has indirect admin access through nested group membership.',
      mitigation: 'Remove svc-backup from Backup-Operators or restrict Backup-Operators privileges.',
    },
    {
      id: 'ap-2', name: 'Contractor Lateral Movement',
      severity: 'high',
      path: ['user-temp-contractor', 'group-Remote-Desktop', 'device-SRV-FILE01'],
      description: 'Temporary contractor has Remote Desktop access to file server, enabling lateral movement.',
      mitigation: 'Remove temp-contractor from Remote-Desktop group. Implement just-in-time access.',
    },
    {
      id: 'ap-3', name: 'Non-Compliant Device Exposure',
      severity: 'medium',
      path: ['device-LAPTOP-23', 'user-k.chen', 'group-Developers'],
      description: 'LAPTOP-23 is non-compliant (3 missing updates) and used by developer with source code access.',
      mitigation: 'Enforce compliance policy on LAPTOP-23. Install missing updates.',
    },
  ];
}

function generateShadowAdmins(): ShadowAdmin[] {
  return [
    {
      userId: 'user-svc-backup', userName: 'svc-backup',
      effectivePermissions: ['SeBackupPrivilege', 'SeRestorePrivilege', 'SeDebugPrivilege'],
      inheritedFrom: ['Backup-Operators', 'Domain Admins (nested)'],
      riskScore: 87,
    },
    {
      userId: 'user-helpdesk1', userName: 'helpdesk1',
      effectivePermissions: ['ResetPassword', 'ModifyGroup', 'SeRemoteInteractiveLogon'],
      inheritedFrom: ['IT-Staff', 'Backup-Operators'],
      riskScore: 62,
    },
  ];
}

function generateStats(nodes: GraphNode[], edges: GraphEdge[]): GraphStats {
  const nodesByType: Record<string, number> = {};
  const riskDistribution: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  nodes.forEach(n => {
    nodesByType[n.type] = (nodesByType[n.type] || 0) + 1;
    riskDistribution[n.riskLevel]++;
  });
  return {
    totalNodes: nodes.length,
    totalEdges: edges.length,
    nodesByType,
    density: (2 * edges.length) / (nodes.length * (nodes.length - 1)),
    avgConnections: edges.length / nodes.length,
    riskDistribution,
  };
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function GraphExplorerView() {
  const [nodes, setNodes]               = useState<GraphNode[]>([]);
  const [edges, setEdges]               = useState<GraphEdge[]>([]);
  const [attackPaths, setAttackPaths]    = useState<AttackPath[]>([]);
  const [shadowAdmins, setShadowAdmins] = useState<ShadowAdmin[]>([]);
  const [stats, setStats]               = useState<GraphStats | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [searchQuery, setSearchQuery]   = useState('');
  const [activeTab, setActiveTab]       = useState<'graph' | 'attacks' | 'shadow' | 'stats'>('graph');
  const [filterTypes, setFilterTypes]   = useState<Set<string>>(new Set(['user', 'group', 'device', 'policy', 'update_ring']));
  const [loading, setLoading]           = useState(true);
  const [highlightedPath, setHighlightedPath] = useState<string[]>([]);
  const [zoom, setZoom]                 = useState(1);
  const svgRef = useRef<SVGSVGElement>(null);

  // ── Data Loading ─────────────────────────────────────────────────────────

  const loadGraphData = useCallback(async () => {
    setLoading(true);
    try {
      // In production: fetch from /api/graph/full, /api/graph/attack-paths, etc.
      const { nodes: n, edges: e } = generateMockGraph();
      setNodes(n);
      setEdges(e);
      setAttackPaths(generateAttackPaths());
      setShadowAdmins(generateShadowAdmins());
      setStats(generateStats(n, e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadGraphData(); }, [loadGraphData]);

  // ── Filtering ────────────────────────────────────────────────────────────

  const filteredNodes = nodes.filter(n => {
    if (!filterTypes.has(n.type)) return false;
    if (searchQuery && !n.label.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });
  const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
  const filteredEdges = edges.filter(e => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target));

  const toggleFilter = (type: string) => {
    setFilterTypes(prev => {
      const next = new Set(prev);
      next.has(type) ? next.delete(type) : next.add(type);
      return next;
    });
  };

  // ── Highlight an attack path ─────────────────────────────────────────────

  const highlightAttackPath = (path: AttackPath) => {
    setHighlightedPath(path.path);
    setActiveTab('graph');
  };

  // ── Node positions for edges ─────────────────────────────────────────────

  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  // ── Render ───────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <ArrowPathIcon className="w-8 h-8 animate-spin text-blue-500" />
        <span className="ml-3 text-gray-400">Loading Graph Explorer…</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-gray-950 text-gray-100">
      {/* ── Header ───────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
        <div>
          <h1 className="text-xl font-bold">AD Graph Explorer</h1>
          <p className="text-sm text-gray-500">Unified Endpoint Intelligence – Relationship Graph</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
            <input
              className="pl-9 pr-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm focus:outline-none focus:border-blue-500 w-64"
              placeholder="Search nodes…"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>
          <button onClick={loadGraphData} className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700" title="Refresh">
            <ArrowPathIcon className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* ── Tabs ─────────────────────────────────────────────────────────── */}
      <div className="flex gap-1 px-6 pt-3 border-b border-gray-800">
        {([
          ['graph',   'Relationship Graph'],
          ['attacks', `Attack Paths (${attackPaths.length})`],
          ['shadow',  `Shadow Admins (${shadowAdmins.length})`],
          ['stats',   'Statistics'],
        ] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`px-4 py-2 text-sm rounded-t-lg transition-colors ${activeTab === key ? 'bg-gray-800 text-white border-t border-x border-gray-700' : 'text-gray-500 hover:text-gray-300'}`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-hidden">
        {activeTab === 'graph' && (
          <div className="flex h-full">
            {/* Filter sidebar */}
            <div className="w-48 border-r border-gray-800 p-4 flex flex-col gap-3">
              <h3 className="text-xs font-semibold text-gray-500 uppercase flex items-center gap-1"><FunnelIcon className="w-3 h-3" /> Filters</h3>
              {Object.keys(NODE_COLORS).map(type => (
                <label key={type} className="flex items-center gap-2 cursor-pointer text-sm">
                  <input
                    type="checkbox"
                    checked={filterTypes.has(type)}
                    onChange={() => toggleFilter(type)}
                    className="rounded border-gray-600 bg-gray-800"
                  />
                  <span className={NODE_COLORS[type].text}>{type.replace('_', ' ')}</span>
                </label>
              ))}
              <hr className="border-gray-800" />
              <div className="text-xs text-gray-600">
                {filteredNodes.length} nodes / {filteredEdges.length} edges
              </div>
              {/* Zoom */}
              <div className="flex gap-1 mt-auto">
                <button onClick={() => setZoom(z => Math.min(z + 0.2, 2))} className="p-1 bg-gray-800 rounded text-xs hover:bg-gray-700">
                  <ArrowsPointingOutIcon className="w-4 h-4" />
                </button>
                <button onClick={() => setZoom(z => Math.max(z - 0.2, 0.4))} className="p-1 bg-gray-800 rounded text-xs hover:bg-gray-700">
                  <ArrowsPointingInIcon className="w-4 h-4" />
                </button>
                <span className="text-xs text-gray-500 self-center ml-1">{Math.round(zoom * 100)}%</span>
              </div>
            </div>

            {/* SVG Canvas */}
            <div className="flex-1 relative overflow-auto bg-gray-950">
              <svg ref={svgRef} width="1100" height="850" className="mx-auto" style={{ transform: `scale(${zoom})`, transformOrigin: 'center top' }}>
                {/* Edges */}
                {filteredEdges.map(e => {
                  const src = nodeMap.get(e.source);
                  const tgt = nodeMap.get(e.target);
                  if (!src || !tgt) return null;
                  const isHighlighted = highlightedPath.includes(e.source) && highlightedPath.includes(e.target);
                  return (
                    <g key={e.id}>
                      <line
                        x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                        stroke={isHighlighted ? '#ef4444' : '#374151'}
                        strokeWidth={isHighlighted ? 2.5 : 1}
                        strokeDasharray={isHighlighted ? '' : '4 2'}
                        opacity={isHighlighted ? 1 : 0.6}
                      />
                      <text
                        x={(src.x + tgt.x) / 2} y={(src.y + tgt.y) / 2 - 6}
                        fill="#6b7280" fontSize={9} textAnchor="middle"
                      >
                        {e.relationship}
                      </text>
                    </g>
                  );
                })}
                {/* Nodes */}
                {filteredNodes.map(n => {
                  const colors = NODE_COLORS[n.type] || NODE_COLORS.user;
                  const isHighlighted = highlightedPath.includes(n.id);
                  const isSelected = selectedNode?.id === n.id;
                  return (
                    <g key={n.id} onClick={() => setSelectedNode(n)} className="cursor-pointer">
                      <circle
                        cx={n.x} cy={n.y}
                        r={isSelected ? 28 : isHighlighted ? 24 : 20}
                        fill={isHighlighted ? '#7f1d1d' : '#111827'}
                        stroke={isSelected ? '#3b82f6' : isHighlighted ? '#ef4444' : '#374151'}
                        strokeWidth={isSelected ? 3 : isHighlighted ? 2.5 : 1.5}
                      />
                      <text x={n.x} y={n.y + 4} fill="#e5e7eb" fontSize={11} textAnchor="middle" fontWeight={isSelected ? 'bold' : 'normal'}>
                        {n.type === 'user' ? '👤' : n.type === 'group' ? '👥' : n.type === 'device' ? '💻' : n.type === 'policy' ? '📋' : n.type === 'update_ring' ? '🔄' : '🔑'}
                      </text>
                      <text x={n.x} y={n.y + 36} fill="#9ca3af" fontSize={10} textAnchor="middle">
                        {n.label}
                      </text>
                      {n.riskLevel !== 'none' && n.riskLevel !== 'low' && (
                        <circle cx={n.x + 16} cy={n.y - 16} r={6}
                          fill={n.riskLevel === 'critical' ? '#ef4444' : n.riskLevel === 'high' ? '#f97316' : '#eab308'}
                        />
                      )}
                    </g>
                  );
                })}
              </svg>
            </div>

            {/* Detail panel */}
            {selectedNode && (
              <div className="w-72 border-l border-gray-800 p-4 overflow-y-auto">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="font-semibold">{selectedNode.label}</h3>
                    <span className={`text-xs px-2 py-0.5 rounded ${NODE_COLORS[selectedNode.type]?.bg} ${NODE_COLORS[selectedNode.type]?.text}`}>
                      {selectedNode.type.replace('_', ' ')}
                    </span>
                  </div>
                  <button onClick={() => setSelectedNode(null)} className="text-gray-500 hover:text-white">
                    <XMarkIcon className="w-4 h-4" />
                  </button>
                </div>
                <div className="mb-3">
                  <span className={`text-xs font-medium ${RISK_COLORS[selectedNode.riskLevel]}`}>
                    Risk: {selectedNode.riskLevel.toUpperCase()}
                  </span>
                </div>
                <h4 className="text-xs text-gray-500 uppercase mb-2">Properties</h4>
                <div className="space-y-1">
                  {Object.entries(selectedNode.properties).map(([k, v]) => (
                    <div key={k} className="flex justify-between text-sm">
                      <span className="text-gray-500">{k}</span>
                      <span className="text-gray-300">{String(v)}</span>
                    </div>
                  ))}
                </div>
                <h4 className="text-xs text-gray-500 uppercase mt-4 mb-2">Connections</h4>
                <div className="space-y-1">
                  {edges
                    .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                    .map(e => {
                      const otherId = e.source === selectedNode.id ? e.target : e.source;
                      const other = nodeMap.get(otherId);
                      return (
                        <div key={e.id} className="text-sm flex items-center gap-1 text-gray-400 cursor-pointer hover:text-white"
                          onClick={() => { const o = nodeMap.get(otherId); if (o) setSelectedNode(o); }}>
                          <ChevronRightIcon className="w-3 h-3" />
                          <span className="text-gray-500">{e.relationship}</span>
                          <span className={NODE_COLORS[other?.type || 'user']?.text}>{other?.label}</span>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Attack Paths Tab ───────────────────────────────────────────── */}
        {activeTab === 'attacks' && (
          <div className="p-6 space-y-4 overflow-y-auto max-h-[calc(100vh-200px)]">
            <p className="text-sm text-gray-500">Detected privilege escalation and lateral movement paths.</p>
            {attackPaths.map(ap => (
              <div key={ap.id} className={`p-4 rounded-lg border ${ap.severity === 'critical' ? 'border-red-800 bg-red-950/30' : ap.severity === 'high' ? 'border-orange-800 bg-orange-950/30' : 'border-yellow-800 bg-yellow-950/30'}`}>
                <div className="flex justify-between items-start mb-2">
                  <h3 className="font-semibold flex items-center gap-2">
                    <ShieldExclamationIcon className="w-5 h-5 text-red-500" />
                    {ap.name}
                  </h3>
                  <span className={`text-xs px-2 py-1 rounded font-medium ${ap.severity === 'critical' ? 'bg-red-900 text-red-300' : ap.severity === 'high' ? 'bg-orange-900 text-orange-300' : 'bg-yellow-900 text-yellow-300'}`}>
                    {ap.severity.toUpperCase()}
                  </span>
                </div>
                <p className="text-sm text-gray-400 mb-2">{ap.description}</p>
                <div className="flex items-center gap-2 mb-3 text-xs">
                  {ap.path.map((nodeId, i) => {
                    const node = nodeMap.get(nodeId);
                    return (
                      <React.Fragment key={nodeId}>
                        {i > 0 && <ChevronRightIcon className="w-3 h-3 text-gray-600" />}
                        <span className={`px-2 py-0.5 rounded ${NODE_COLORS[node?.type || 'user']?.bg} ${NODE_COLORS[node?.type || 'user']?.text}`}>
                          {node?.label || nodeId}
                        </span>
                      </React.Fragment>
                    );
                  })}
                </div>
                <div className="flex items-center justify-between">
                  <div className="text-xs text-green-400"><CheckCircleIcon className="w-4 h-4 inline mr-1" />{ap.mitigation}</div>
                  <button onClick={() => highlightAttackPath(ap)} className="text-xs px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded">
                    <EyeIcon className="w-3 h-3 inline mr-1" />Show in Graph
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Shadow Admins Tab ──────────────────────────────────────────── */}
        {activeTab === 'shadow' && (
          <div className="p-6 space-y-4 overflow-y-auto max-h-[calc(100vh-200px)]">
            <p className="text-sm text-gray-500">Accounts with admin-equivalent permissions through indirect/nested group membership.</p>
            {shadowAdmins.map(sa => (
              <div key={sa.userId} className="p-4 rounded-lg border border-gray-800 bg-gray-900/50">
                <div className="flex justify-between items-start mb-3">
                  <div className="flex items-center gap-2">
                    <UserIcon className="w-5 h-5 text-orange-400" />
                    <h3 className="font-semibold">{sa.userName}</h3>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-bold text-orange-400">{sa.riskScore}</div>
                    <div className="text-xs text-gray-500">Risk Score</div>
                  </div>
                </div>
                <h4 className="text-xs text-gray-500 uppercase mb-1">Effective Permissions</h4>
                <div className="flex flex-wrap gap-1 mb-3">
                  {sa.effectivePermissions.map(p => (
                    <span key={p} className="px-2 py-0.5 rounded bg-red-900/40 text-red-300 text-xs">{p}</span>
                  ))}
                </div>
                <h4 className="text-xs text-gray-500 uppercase mb-1">Inherited From</h4>
                <div className="flex flex-wrap gap-1">
                  {sa.inheritedFrom.map(g => (
                    <span key={g} className="px-2 py-0.5 rounded bg-purple-900/40 text-purple-300 text-xs">{g}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Stats Tab ──────────────────────────────────────────────────── */}
        {activeTab === 'stats' && stats && (
          <div className="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 overflow-y-auto max-h-[calc(100vh-200px)]">
            {/* Summary cards */}
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
              <div className="text-3xl font-bold text-blue-400">{stats.totalNodes}</div>
              <div className="text-sm text-gray-500">Total Nodes</div>
            </div>
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
              <div className="text-3xl font-bold text-purple-400">{stats.totalEdges}</div>
              <div className="text-sm text-gray-500">Total Edges</div>
            </div>
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
              <div className="text-3xl font-bold text-cyan-400">{(stats.density * 100).toFixed(1)}%</div>
              <div className="text-sm text-gray-500">Graph Density</div>
            </div>
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
              <div className="text-3xl font-bold text-green-400">{stats.avgConnections.toFixed(1)}</div>
              <div className="text-sm text-gray-500">Avg Connections</div>
            </div>
            {/* Nodes by type */}
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800 col-span-1">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Nodes by Type</h3>
              <div className="space-y-2">
                {Object.entries(stats.nodesByType).map(([type, count]) => (
                  <div key={type} className="flex justify-between items-center text-sm">
                    <span className={NODE_COLORS[type]?.text || 'text-gray-400'}>{type.replace('_', ' ')}</span>
                    <span className="text-gray-300 font-mono">{count}</span>
                  </div>
                ))}
              </div>
            </div>
            {/* Risk distribution */}
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800 col-span-1">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Risk Distribution</h3>
              <div className="space-y-2">
                {Object.entries(stats.riskDistribution).map(([level, count]) => (
                  <div key={level} className="flex justify-between items-center text-sm">
                    <span className={RISK_COLORS[level]}>{level}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-24 h-2 bg-gray-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${level === 'critical' ? 'bg-red-500' : level === 'high' ? 'bg-orange-500' : level === 'medium' ? 'bg-yellow-500' : level === 'low' ? 'bg-blue-500' : 'bg-gray-600'}`}
                          style={{ width: `${(count / stats.totalNodes) * 100}%` }}
                        />
                      </div>
                      <span className="text-gray-300 font-mono w-6 text-right">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
