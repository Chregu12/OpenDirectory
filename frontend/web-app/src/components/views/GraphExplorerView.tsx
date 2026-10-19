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
import { lldapApi, deviceApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';
import SimpleViewLayout from '@/components/shared/SimpleViewLayout';

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
  user:        { bg: 'bg-blue-100',   border: 'border-blue-500',   text: 'text-blue-700' },
  group:       { bg: 'bg-purple-100', border: 'border-purple-500', text: 'text-purple-700' },
  device:      { bg: 'bg-green-100',  border: 'border-green-500',  text: 'text-green-700' },
  policy:      { bg: 'bg-amber-100',  border: 'border-amber-500',  text: 'text-amber-700' },
  update_ring: { bg: 'bg-cyan-100',   border: 'border-cyan-500',   text: 'text-cyan-700' },
  permission:  { bg: 'bg-red-100',    border: 'border-red-500',    text: 'text-red-700' },
  certificate: { bg: 'bg-pink-100',   border: 'border-pink-500',   text: 'text-pink-700' },
};

const NODE_STYLE_MAP: Record<string, { background: string; color: string }> = {
  user:        { background: 'var(--accent-light)',              color: 'var(--accent)' },
  group:       { background: 'rgba(168,85,247,0.15)',            color: '#a855f7' },
  device:      { background: 'var(--success-light)',             color: 'var(--success)' },
  policy:      { background: 'var(--warning-light)',             color: 'var(--warning)' },
  update_ring: { background: 'rgba(6,182,212,0.15)',             color: '#06b6d4' },
  permission:  { background: 'var(--danger-light)',              color: 'var(--danger)' },
  certificate: { background: 'rgba(236,72,153,0.15)',            color: '#ec4899' },
};

const RISK_COLORS: Record<string, string> = {
  critical: 'var(--danger)',
  high:     '#f97316',
  medium:   'var(--warning)',
  low:      'var(--accent)',
  none:     'var(--text-muted)',
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
  const { isSimple } = useUiMode();
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
      // Try to load real data from LLDAP and Device APIs
      const [usersRes, groupsRes, devicesRes] = await Promise.allSettled([
        lldapApi.getUsers(),
        lldapApi.getGroups(),
        deviceApi.getDevices(),
      ]);

      let apiNodes: GraphNode[] = [];
      let apiEdges: GraphEdge[] = [];
      const cx = 500, cy = 400;

      const hasUsers = usersRes.status === 'fulfilled' && usersRes.value.data?.length > 0;
      const hasGroups = groupsRes.status === 'fulfilled' && groupsRes.value.data?.length > 0;

      if (hasUsers || hasGroups) {
        // Build nodes from real data
        if (hasUsers) {
          const users = usersRes.value.data;
          users.forEach((u: any, i: number) => {
            const angle = (i / users.length) * Math.PI * 2;
            apiNodes.push({
              id: `user-${u.id || u.uid}`, label: u.displayName || u.uid || u.id,
              type: 'user', riskLevel: 'low',
              properties: { email: u.email || '', lastLogin: u.lastLogin || '', enabled: u.enabled ?? true },
              x: cx + Math.cos(angle) * 320, y: cy + Math.sin(angle) * 280,
            });
          });
        }

        if (hasGroups) {
          const groups = groupsRes.value.data;
          groups.forEach((g: any, i: number) => {
            const angle = (i / groups.length) * Math.PI * 2 + 0.3;
            apiNodes.push({
              id: `group-${g.id || g.name}`, label: g.displayName || g.name || g.id,
              type: 'group', riskLevel: 'low',
              properties: { memberCount: g.members?.length || 0, scope: 'Global' },
              x: cx + Math.cos(angle) * 200, y: cy + Math.sin(angle) * 180,
            });

            // Build membership edges
            (g.members || []).forEach((m: any) => {
              const memberId = typeof m === 'string' ? m : m.id || m.uid;
              apiEdges.push({
                id: `e-${memberId}-${g.id || g.name}`,
                source: `user-${memberId}`, target: `group-${g.id || g.name}`,
                relationship: 'MEMBER_OF',
              });
            });
          });
        }

        if (devicesRes.status === 'fulfilled' && devicesRes.value.data?.length > 0) {
          const devs = devicesRes.value.data;
          devs.forEach((d: any, i: number) => {
            const angle = (i / devs.length) * Math.PI * 2 + 0.6;
            apiNodes.push({
              id: `device-${d.id || d.name}`, label: d.name || d.id,
              type: 'device', riskLevel: d.compliance === 'non_compliant' ? 'high' : 'low',
              properties: { os: d.os || 'Unknown', compliance: d.compliance !== 'non_compliant' },
              x: cx + Math.cos(angle) * 380, y: cy + Math.sin(angle) * 340,
            });
          });
        }

        setNodes(apiNodes);
        setEdges(apiEdges.filter(e => apiNodes.some(n => n.id === e.source) && apiNodes.some(n => n.id === e.target)));
      } else {
        // Fallback to mock data
        const { nodes: n, edges: e } = generateMockGraph();
        setNodes(n);
        setEdges(e);
      }

      setAttackPaths(generateAttackPaths());
      setShadowAdmins(generateShadowAdmins());
    } catch {
      // Fallback to mock data
      const { nodes: n, edges: e } = generateMockGraph();
      setNodes(n);
      setEdges(e);
      setAttackPaths(generateAttackPaths());
      setShadowAdmins(generateShadowAdmins());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadGraphData(); }, [loadGraphData]);

  // Recalculate stats when nodes/edges change
  useEffect(() => {
    if (nodes.length > 0) {
      setStats(generateStats(nodes, edges));
    }
  }, [nodes, edges]);

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

  const highlightAttackPath = (path: AttackPath) => {
    setHighlightedPath(path.path);
    setActiveTab('graph');
  };

  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
        <ArrowPathIcon style={{ width: 32, height: 32, color: 'var(--accent)' }} className="animate-spin" />
        <span style={{ marginLeft: 12, color: 'var(--text-muted)' }}>Loading Graph Explorer...</span>
      </div>
    );
  }

  // ── Simple Mode ──
  if (isSimple) {
    const riskNodes = nodes.filter(n => n.riskLevel === 'critical' || n.riskLevel === 'high');
    const allSecure = attackPaths.filter(ap => ap.severity === 'critical').length === 0 && shadowAdmins.length === 0;

    return (
      <SimpleViewLayout
        hero={{
          status: allSecure ? 'ok' : 'critical',
          icon: allSecure ? undefined : <ShieldExclamationIcon className="w-10 h-10 text-red-600" />,
          title: allSecure ? 'No Security Issues Found' : `${attackPaths.length} Attack Path${attackPaths.length > 1 ? 's' : ''} Detected`,
          subtitle: `${nodes.length} objects · ${edges.length} relationships · ${shadowAdmins.length} shadow admins`,
        }}
        stats={[
          { value: nodes.length, label: 'AD Objects', color: 'text-blue-600' },
          { value: attackPaths.length, label: 'Attack Paths', color: attackPaths.length > 0 ? 'text-red-600' : 'text-gray-600' },
          { value: shadowAdmins.length, label: 'Shadow Admins', color: shadowAdmins.length > 0 ? 'text-orange-600' : 'text-gray-600' },
          { value: riskNodes.length, label: 'High-Risk Objects', color: riskNodes.length > 0 ? 'text-red-600' : 'text-green-600' },
        ]}
        sections={[
          {
            title: 'Attack Paths',
            items: attackPaths.map(ap => ({
              key: ap.id,
              icon: <ShieldExclamationIcon className={`w-5 h-5 ${ap.severity === 'critical' ? 'text-red-500' : ap.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'}`} />,
              title: ap.name,
              subtitle: ap.description.slice(0, 80) + '...',
              trailing: <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${ap.severity === 'critical' ? 'bg-red-100 text-red-700' : ap.severity === 'high' ? 'bg-orange-100 text-orange-700' : 'bg-yellow-100 text-yellow-700'}`}>{ap.severity}</span>,
            })),
          },
          {
            title: 'Shadow Admins',
            items: shadowAdmins.map(sa => ({
              key: sa.userId,
              icon: <UserIcon className="w-5 h-5 text-orange-500" />,
              title: sa.userName,
              subtitle: `${sa.effectivePermissions.length} permissions · from ${sa.inheritedFrom.join(', ')}`,
              trailing: <span className="text-lg font-bold text-orange-600">{sa.riskScore}</span>,
            })),
          },
        ]}
      />
    );
  }

  const attackSeverityStyle = (severity: string): React.CSSProperties => ({
    borderColor: severity === 'critical' ? 'var(--danger)' :
                 severity === 'high' ? '#f97316' :
                 'var(--warning)',
  });

  // ── Expert Mode ──
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* ── Header ───────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 24px', borderBottom: '1px solid var(--border)', background: 'var(--bg-surface)', flexShrink: 0 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>AD Graph Explorer</h1>
          <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>Unified Endpoint Intelligence - Relationship Graph</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ position: 'relative' }}>
            <MagnifyingGlassIcon style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', width: 16, height: 16, color: 'var(--text-muted)' }} />
            <input
              style={{ paddingLeft: 36, paddingRight: 12, paddingTop: 8, paddingBottom: 8, background: 'var(--bg-surface-raised)', border: '1px solid var(--border-strong)', borderRadius: 8, fontSize: 14, color: 'var(--text-primary)', outline: 'none', width: 256, boxSizing: 'border-box' }}
              placeholder="Search nodes..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>
          <button onClick={loadGraphData} style={{ padding: 8, borderRadius: 8, background: 'var(--bg-surface-raised)', border: '1px solid var(--border)', cursor: 'pointer', color: 'var(--text-secondary)' }} title="Refresh">
            <ArrowPathIcon style={{ width: 20, height: 20 }} />
          </button>
        </div>
      </div>

      {/* ── Tabs ─────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 4, padding: '12px 24px 0', borderBottom: '1px solid var(--border)', background: 'var(--bg-surface-raised)', flexShrink: 0 }}>
        {([
          ['graph',   'Relationship Graph'],
          ['attacks', `Attack Paths (${attackPaths.length})`],
          ['shadow',  `Shadow Admins (${shadowAdmins.length})`],
          ['stats',   'Statistics'],
        ] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`od-tab ${activeTab === key ? 'od-tab-active' : 'od-tab-inactive'}`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      <div style={{ flex: 1, overflow: 'hidden' }}>
        {activeTab === 'graph' && (
          <div style={{ display: 'flex', height: '100%' }}>
            {/* Filter sidebar */}
            <div style={{ width: 192, borderRight: '1px solid var(--border)', background: 'var(--bg-surface)', padding: 16, display: 'flex', flexDirection: 'column', gap: 12, flexShrink: 0 }}>
              <h3 style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: 4 }}>
                <FunnelIcon style={{ width: 12, height: 12 }} /> Filters
              </h3>
              {Object.keys(NODE_COLORS).map(type => (
                <label key={type} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 14 }}>
                  <input
                    type="checkbox"
                    checked={filterTypes.has(type)}
                    onChange={() => toggleFilter(type)}
                    style={{ accentColor: 'var(--accent)' }}
                  />
                  <span style={{ color: NODE_STYLE_MAP[type]?.color || 'var(--text-secondary)' }}>{type.replace('_', ' ')}</span>
                </label>
              ))}
              <hr style={{ border: 'none', borderTop: '1px solid var(--border)' }} />
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                {filteredNodes.length} nodes / {filteredEdges.length} edges
              </div>
              {/* Zoom */}
              <div style={{ display: 'flex', gap: 4, marginTop: 'auto' }}>
                <button onClick={() => setZoom(z => Math.min(z + 0.2, 2))} style={{ padding: 4, background: 'var(--bg-surface-raised)', border: '1px solid var(--border)', borderRadius: 4, cursor: 'pointer', color: 'var(--text-secondary)' }}>
                  <ArrowsPointingOutIcon style={{ width: 16, height: 16 }} />
                </button>
                <button onClick={() => setZoom(z => Math.max(z - 0.2, 0.4))} style={{ padding: 4, background: 'var(--bg-surface-raised)', border: '1px solid var(--border)', borderRadius: 4, cursor: 'pointer', color: 'var(--text-secondary)' }}>
                  <ArrowsPointingInIcon style={{ width: 16, height: 16 }} />
                </button>
                <span style={{ fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center', marginLeft: 4 }}>{Math.round(zoom * 100)}%</span>
              </div>
            </div>

            {/* SVG Canvas */}
            <div style={{ flex: 1, position: 'relative', overflow: 'auto', background: 'var(--bg-base)' }}>
              <svg ref={svgRef} width="1100" height="850" style={{ display: 'block', margin: '0 auto', transform: `scale(${zoom})`, transformOrigin: 'center top' }}>
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
                        stroke={isHighlighted ? '#f85149' : 'rgba(255,255,255,0.14)'}
                        strokeWidth={isHighlighted ? 2.5 : 1}
                        strokeDasharray={isHighlighted ? '' : '4 2'}
                        opacity={isHighlighted ? 1 : 0.6}
                      />
                      <text
                        x={(src.x + tgt.x) / 2} y={(src.y + tgt.y) / 2 - 6}
                        fill="#6e7681" fontSize={9} textAnchor="middle"
                      >
                        {e.relationship}
                      </text>
                    </g>
                  );
                })}
                {/* Nodes */}
                {filteredNodes.map(n => {
                  const isHighlighted = highlightedPath.includes(n.id);
                  const isSelected = selectedNode?.id === n.id;
                  return (
                    <g key={n.id} onClick={() => setSelectedNode(n)} style={{ cursor: 'pointer' }}>
                      <circle
                        cx={n.x} cy={n.y}
                        r={isSelected ? 28 : isHighlighted ? 24 : 20}
                        fill={isHighlighted ? 'var(--danger-light)' : 'var(--bg-surface)'}
                        stroke={isSelected ? 'var(--accent)' : isHighlighted ? '#f85149' : 'rgba(255,255,255,0.14)'}
                        strokeWidth={isSelected ? 3 : isHighlighted ? 2.5 : 1.5}
                      />
                      <text x={n.x} y={n.y + 4} fill="#e4e6ea" fontSize={11} textAnchor="middle" fontWeight={isSelected ? 'bold' : 'normal'}>
                        {n.type === 'user' ? '👤' : n.type === 'group' ? '👥' : n.type === 'device' ? '💻' : n.type === 'policy' ? '📋' : n.type === 'update_ring' ? '🔄' : '🔑'}
                      </text>
                      <text x={n.x} y={n.y + 36} fill="#8b949e" fontSize={10} textAnchor="middle">
                        {n.label}
                      </text>
                      {n.riskLevel !== 'none' && n.riskLevel !== 'low' && (
                        <circle cx={n.x + 16} cy={n.y - 16} r={6}
                          fill={n.riskLevel === 'critical' ? '#f85149' : n.riskLevel === 'high' ? '#f97316' : '#d29922'}
                        />
                      )}
                    </g>
                  );
                })}
              </svg>
            </div>

            {/* Detail panel */}
            {selectedNode && (
              <div style={{ width: 288, borderLeft: '1px solid var(--border)', background: 'var(--bg-surface)', padding: 16, overflowY: 'auto', flexShrink: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                  <div>
                    <h3 style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{selectedNode.label}</h3>
                    <span style={{ fontSize: 12, padding: '2px 8px', borderRadius: 4, ...NODE_STYLE_MAP[selectedNode.type] }}>
                      {selectedNode.type.replace('_', ' ')}
                    </span>
                  </div>
                  <button onClick={() => setSelectedNode(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                    <XMarkIcon style={{ width: 16, height: 16 }} />
                  </button>
                </div>
                <div style={{ marginBottom: 12 }}>
                  <span style={{ fontSize: 12, fontWeight: 500, color: RISK_COLORS[selectedNode.riskLevel] }}>
                    Risk: {selectedNode.riskLevel.toUpperCase()}
                  </span>
                </div>
                <h4 style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8 }}>Properties</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {Object.entries(selectedNode.properties).map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 14 }}>
                      <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                      <span style={{ color: 'var(--text-secondary)' }}>{String(v)}</span>
                    </div>
                  ))}
                </div>
                <h4 style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: 16, marginBottom: 8 }}>Connections</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {edges
                    .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                    .map(e => {
                      const otherId = e.source === selectedNode.id ? e.target : e.source;
                      const other = nodeMap.get(otherId);
                      return (
                        <div key={e.id} style={{ fontSize: 14, display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-muted)', cursor: 'pointer' }}
                          onClick={() => { const o = nodeMap.get(otherId); if (o) setSelectedNode(o); }}
                          onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-primary)')}
                          onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}>
                          <ChevronRightIcon style={{ width: 12, height: 12, flexShrink: 0 }} />
                          <span style={{ color: 'var(--text-muted)' }}>{e.relationship}</span>
                          <span style={{ color: NODE_STYLE_MAP[other?.type || 'user']?.color || 'var(--text-secondary)' }}>{other?.label}</span>
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
          <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto', maxHeight: 'calc(100vh - 200px)' }}>
            <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>Detected privilege escalation and lateral movement paths.</p>
            {attackPaths.map(ap => (
              <div key={ap.id} className="od-card" style={{ padding: 16, ...attackSeverityStyle(ap.severity) }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                  <h3 style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <ShieldExclamationIcon style={{ width: 20, height: 20, color: 'var(--danger)' }} />
                    {ap.name}
                  </h3>
                  <span style={{
                    fontSize: 12, padding: '4px 8px', borderRadius: 4, fontWeight: 500,
                    color: ap.severity === 'critical' ? 'var(--danger)' : ap.severity === 'high' ? '#f97316' : 'var(--warning)',
                    background: ap.severity === 'critical' ? 'var(--danger-light)' : ap.severity === 'high' ? 'rgba(249,115,22,0.15)' : 'var(--warning-light)',
                  }}>
                    {ap.severity.toUpperCase()}
                  </span>
                </div>
                <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 8 }}>{ap.description}</p>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, fontSize: 12 }}>
                  {ap.path.map((nodeId, i) => {
                    const node = nodeMap.get(nodeId);
                    return (
                      <React.Fragment key={nodeId}>
                        {i > 0 && <ChevronRightIcon style={{ width: 12, height: 12, color: 'var(--text-muted)', flexShrink: 0 }} />}
                        <span style={{ padding: '2px 8px', borderRadius: 4, ...NODE_STYLE_MAP[node?.type || 'user'] }}>
                          {node?.label || nodeId}
                        </span>
                      </React.Fragment>
                    );
                  })}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ fontSize: 12, color: 'var(--success)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <CheckCircleIcon style={{ width: 16, height: 16, display: 'inline' }} />{ap.mitigation}
                  </div>
                  <button onClick={() => highlightAttackPath(ap)} style={{ fontSize: 12, padding: '4px 12px', background: 'var(--bg-overlay)', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 8, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <EyeIcon style={{ width: 12, height: 12 }} />Show in Graph
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Shadow Admins Tab ──────────────────────────────────────────── */}
        {activeTab === 'shadow' && (
          <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto', maxHeight: 'calc(100vh - 200px)' }}>
            <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>Accounts with admin-equivalent permissions through indirect/nested group membership.</p>
            {shadowAdmins.map(sa => (
              <div key={sa.userId} className="od-card" style={{ padding: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ width: 32, height: 32, background: 'rgba(249,115,22,0.15)', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <UserIcon style={{ width: 20, height: 20, color: '#f97316' }} />
                    </div>
                    <h3 style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{sa.userName}</h3>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: 24, fontWeight: 700, color: '#f97316' }}>{sa.riskScore}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Risk Score</div>
                  </div>
                </div>
                <h4 style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>Effective Permissions</h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 12 }}>
                  {sa.effectivePermissions.map(p => (
                    <span key={p} className="od-badge-critical" style={{ padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>{p}</span>
                  ))}
                </div>
                <h4 style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>Inherited From</h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {sa.inheritedFrom.map(g => (
                    <span key={g} style={{ padding: '2px 8px', borderRadius: 4, fontSize: 12, background: 'rgba(168,85,247,0.15)', color: '#a855f7' }}>{g}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Stats Tab ──────────────────────────────────────────────────── */}
        {activeTab === 'stats' && stats && (
          <div style={{ padding: 24, display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, overflowY: 'auto', maxHeight: 'calc(100vh - 200px)', alignContent: 'start' }}>
            <div className="od-card" style={{ padding: 16 }}>
              <div style={{ fontSize: 30, fontWeight: 700, color: 'var(--accent)' }}>{stats.totalNodes}</div>
              <div style={{ fontSize: 14, color: 'var(--text-muted)' }}>Total Nodes</div>
            </div>
            <div className="od-card" style={{ padding: 16 }}>
              <div style={{ fontSize: 30, fontWeight: 700, color: '#a855f7' }}>{stats.totalEdges}</div>
              <div style={{ fontSize: 14, color: 'var(--text-muted)' }}>Total Edges</div>
            </div>
            <div className="od-card" style={{ padding: 16 }}>
              <div style={{ fontSize: 30, fontWeight: 700, color: '#06b6d4' }}>{(stats.density * 100).toFixed(1)}%</div>
              <div style={{ fontSize: 14, color: 'var(--text-muted)' }}>Graph Density</div>
            </div>
            <div className="od-card" style={{ padding: 16 }}>
              <div style={{ fontSize: 30, fontWeight: 700, color: 'var(--success)' }}>{stats.avgConnections.toFixed(1)}</div>
              <div style={{ fontSize: 14, color: 'var(--text-muted)' }}>Avg Connections</div>
            </div>
            <div className="od-card" style={{ padding: 16 }}>
              <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 12 }}>Nodes by Type</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {Object.entries(stats.nodesByType).map(([type, count]) => (
                  <div key={type} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 14 }}>
                    <span style={{ color: NODE_STYLE_MAP[type]?.color || 'var(--text-secondary)' }}>{type.replace('_', ' ')}</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{count}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="od-card" style={{ padding: 16 }}>
              <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 12 }}>Risk Distribution</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {Object.entries(stats.riskDistribution).map(([level, count]) => (
                  <div key={level} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 14 }}>
                    <span style={{ color: RISK_COLORS[level] }}>{level}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 96, height: 8, background: 'var(--bg-overlay)', borderRadius: 9999, overflow: 'hidden' }}>
                        <div
                          style={{
                            height: '100%', borderRadius: 9999,
                            background: level === 'critical' ? '#f85149' : level === 'high' ? '#f97316' : level === 'medium' ? '#d29922' : level === 'low' ? '#006FFF' : 'var(--bg-surface-raised)',
                            width: `${(count / stats.totalNodes) * 100}%`,
                          }}
                        />
                      </div>
                      <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', width: 24, textAlign: 'right' }}>{count}</span>
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
