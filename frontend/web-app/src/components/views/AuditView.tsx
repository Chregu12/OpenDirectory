'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  DocumentMagnifyingGlassIcon,
  ArrowPathIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  XMarkIcon,
  DocumentArrowDownIcon,
  PlayIcon,
  PauseIcon,
  ClockIcon,
  UserIcon,
  ShieldCheckIcon,
  ServerIcon,
  KeyIcon,
  ComputerDesktopIcon,
  CogIcon,
  ChartBarIcon,
  LinkIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import { auditApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';
import SimpleViewLayout from '@/components/shared/SimpleViewLayout';

// ── Types ──────────────────────────────────────────────────────────────────────

interface AuditEvent {
  id: string;
  timestamp: string;
  category: 'auth' | 'device' | 'policy' | 'admin' | 'system' | 'security';
  severity: 'info' | 'warning' | 'critical';
  actor: string;
  action: string;
  target: string;
  details?: Record<string, any>;
  correlationId?: string;
  ipAddress?: string;
}

interface AuditStats {
  eventsToday: number;
  criticalEvents: number;
  topActors: { actor: string; count: number }[];
}

interface IntegrityStatus {
  status: 'ok' | 'broken';
  lastVerified: string;
  chainLength: number;
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function AuditView() {
  const { isSimple } = useUiMode();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<AuditStats>({ eventsToday: 0, criticalEvents: 0, topActors: [] });
  const [integrity, setIntegrity] = useState<IntegrityStatus>({ status: 'ok', lastVerified: new Date().toISOString(), chainLength: 0 });
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [correlatedEvents, setCorrelatedEvents] = useState<AuditEvent[]>([]);
  const [liveStream, setLiveStream] = useState(false);

  // Filters
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterSearch, setFilterSearch] = useState('');
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [eventsRes, statsRes, integrityRes] = await Promise.all([
        auditApi.getEvents({
          category: filterCategory !== 'all' ? filterCategory : undefined,
          severity: filterSeverity !== 'all' ? filterSeverity : undefined,
          search: filterSearch || undefined,
          from: filterDateFrom || undefined,
          to: filterDateTo || undefined,
          limit: 100,
        }).catch(() => null),
        auditApi.getStats().catch(() => null),
        auditApi.getIntegrity().catch(() => null),
      ]);

      if (eventsRes?.data) {
        setEvents(eventsRes.data.events || eventsRes.data || []);
      } else {
        setEvents(getDemoEvents());
      }
      if (statsRes?.data) setStats(statsRes.data);
      else setStats(getDemoStats());
      if (integrityRes?.data) setIntegrity(integrityRes.data);
    } catch {
      setEvents(getDemoEvents());
      setStats(getDemoStats());
    } finally {
      setLoading(false);
    }
  }, [filterCategory, filterSeverity, filterSearch, filterDateFrom, filterDateTo]);

  useEffect(() => { loadData(); }, [loadData]);

  // Live stream polling
  useEffect(() => {
    if (!liveStream) return;
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [liveStream, loadData]);

  const handleSelectEvent = async (event: AuditEvent) => {
    setSelectedEvent(event);
    if (event.correlationId) {
      try {
        const res = await auditApi.getCorrelations(event.correlationId);
        setCorrelatedEvents(res.data?.events || res.data || []);
      } catch {
        setCorrelatedEvents([]);
      }
    } else {
      setCorrelatedEvents([]);
    }
  };

  const handleExport = async (format: 'csv' | 'pdf') => {
    try {
      await auditApi.exportEvents({ format, category: filterCategory !== 'all' ? filterCategory : undefined, severity: filterSeverity !== 'all' ? filterSeverity : undefined });
      toast.success(`${format.toUpperCase()} export started`);
    } catch {
      toast.error('Export failed');
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'auth': return <KeyIcon className="w-4 h-4 text-purple-500" />;
      case 'device': return <ComputerDesktopIcon className="w-4 h-4 text-blue-500" />;
      case 'policy': return <ShieldCheckIcon className="w-4 h-4 text-green-500" />;
      case 'admin': return <UserIcon className="w-4 h-4 text-orange-500" />;
      case 'system': return <ServerIcon className="w-4 h-4 text-gray-500" />;
      case 'security': return <ExclamationTriangleIcon className="w-4 h-4 text-red-500" />;
      default: return <InformationCircleIcon className="w-4 h-4 text-gray-400" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical': return <span className="px-2 py-0.5 rounded-full text-xs font-semibold" style={{ color: 'var(--danger)', background: 'var(--danger-light)' }}>Critical</span>;
      case 'warning': return <span className="px-2 py-0.5 rounded-full text-xs font-semibold" style={{ color: 'var(--warning)', background: 'var(--warning-light)' }}>Warning</span>;
      default: return <span className="px-2 py-0.5 rounded-full text-xs font-semibold" style={{ color: 'var(--accent)', background: 'var(--accent-light)' }}>Info</span>;
    }
  };

  // ── Simple Mode ──
  if (isSimple) {
    const criticalEvents = events.filter(e => e.severity === 'critical');
    const warningEvents = events.filter(e => e.severity === 'warning');

    return (
      <SimpleViewLayout
        hero={{
          status: criticalEvents.length === 0 ? 'ok' : 'critical',
          title: criticalEvents.length === 0 ? 'No Critical Events' : `${criticalEvents.length} Critical Event${criticalEvents.length > 1 ? 's' : ''}`,
          subtitle: `${stats.eventsToday} events today · Integrity: ${integrity.status === 'ok' ? 'OK' : 'BROKEN'}`,
        }}
        stats={[
          { value: stats.eventsToday, label: 'Events Today', color: 'text-blue-600' },
          { value: stats.criticalEvents, label: 'Critical', color: stats.criticalEvents > 0 ? 'text-red-600' : 'text-gray-600' },
          { value: warningEvents.length, label: 'Warnings', color: 'text-yellow-600' },
          { value: integrity.status === 'ok' ? 'OK' : '!!', label: 'Integrity', color: integrity.status === 'ok' ? 'text-green-600' : 'text-red-600' },
        ]}
        sections={[{
          title: 'Recent Activity',
          items: events.slice(0, 5).map(event => ({
            key: event.id,
            icon: getCategoryIcon(event.category),
            title: event.action,
            subtitle: `${event.actor} · ${new Date(event.timestamp).toLocaleTimeString()}`,
            trailing: getSeverityBadge(event.severity),
          })),
        }]}
        actions={[
          { label: 'Refresh', icon: <ArrowPathIcon className="h-4 w-4" />, onClick: loadData },
          { label: 'Export CSV', icon: <DocumentArrowDownIcon className="h-4 w-4" />, onClick: () => handleExport('csv'), variant: 'secondary' },
        ]}
      />
    );
  }

  // ── Expert Mode ──
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Audit Log</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>Track and review all system activity</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setLiveStream(!liveStream)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium ${
              liveStream ? 'bg-green-100 text-green-700 hover:bg-green-200' : 'hover:bg-gray-200'
            }`}
            style={!liveStream ? { background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' } : undefined}
          >
            {liveStream ? <PauseIcon className="w-4 h-4" /> : <PlayIcon className="w-4 h-4" />}
            {liveStream ? 'Live' : 'Paused'}
          </button>
          <div className="flex gap-1">
            <button onClick={() => handleExport('csv')} className="flex items-center gap-1 px-3 py-2 rounded-lg hover:bg-gray-50 text-sm" style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
              <DocumentArrowDownIcon className="w-4 h-4" /> CSV
            </button>
            <button onClick={() => handleExport('pdf')} className="flex items-center gap-1 px-3 py-2 rounded-lg hover:bg-gray-50 text-sm" style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
              <DocumentArrowDownIcon className="w-4 h-4" /> PDF
            </button>
          </div>
          <button onClick={loadData} className="p-2 rounded-lg hover:bg-gray-100" style={{ color: 'var(--text-muted)' }}>
            <ArrowPathIcon className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <div className="flex items-center gap-2 mb-1">
            <ChartBarIcon className="w-5 h-5 text-blue-500" />
            <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Events Today</span>
          </div>
          <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>{stats.eventsToday}</p>
        </div>
        <div className="rounded-xl p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <div className="flex items-center gap-2 mb-1">
            <ExclamationTriangleIcon className="w-5 h-5 text-red-500" />
            <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Critical Events</span>
          </div>
          <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>{stats.criticalEvents}</p>
        </div>
        <div className="rounded-xl p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <div className="flex items-center gap-2 mb-1">
            <ShieldCheckIcon className="w-5 h-5 text-green-500" />
            <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Integrity</span>
          </div>
          <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            <span className={`inline-flex items-center gap-1 ${integrity.status === 'ok' ? 'text-green-600' : 'text-red-600'}`}>
              {integrity.status === 'ok' ? <CheckCircleIcon className="w-6 h-6" /> : <ExclamationTriangleIcon className="w-6 h-6" />}
              {integrity.status === 'ok' ? 'OK' : 'BROKEN'}
            </span>
          </p>
        </div>
      </div>

      {/* Top Actors */}
      {stats.topActors.length > 0 && (
        <div className="rounded-xl p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-secondary)' }}>Top Actors</h3>
          <div className="flex gap-3 overflow-x-auto">
            {stats.topActors.map(a => (
              <div key={a.actor} className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm flex-shrink-0" style={{ background: 'var(--bg-surface-raised)' }}>
                <UserIcon className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
                <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>{a.actor}</span>
                <span style={{ color: 'var(--text-muted)' }}>{a.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center rounded-xl p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <FunnelIcon className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
        <select value={filterCategory} onChange={e => setFilterCategory(e.target.value)} className="rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" style={{ border: '1px solid var(--border)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}>
          <option value="all">All Categories</option>
          <option value="auth">Auth</option>
          <option value="device">Device</option>
          <option value="policy">Policy</option>
          <option value="admin">Admin</option>
          <option value="system">System</option>
          <option value="security">Security</option>
        </select>
        <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} className="rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" style={{ border: '1px solid var(--border)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}>
          <option value="all">All Severities</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="critical">Critical</option>
        </select>
        <input type="date" value={filterDateFrom} onChange={e => setFilterDateFrom(e.target.value)} className="rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" style={{ border: '1px solid var(--border)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }} placeholder="From" />
        <input type="date" value={filterDateTo} onChange={e => setFilterDateTo(e.target.value)} className="rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" style={{ border: '1px solid var(--border)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }} placeholder="To" />
        <div className="relative flex-1 min-w-[200px]">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search events..."
            value={filterSearch}
            onChange={e => setFilterSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            style={{ border: '1px solid var(--border)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}
          />
        </div>
      </div>

      {/* Event Timeline */}
      {loading ? (
        <div className="flex items-center justify-center py-20"><ArrowPathIcon className="w-8 h-8 animate-spin text-blue-500" /></div>
      ) : events.length === 0 ? (
        <div className="text-center py-20" style={{ color: 'var(--text-muted)' }}>
          <DocumentMagnifyingGlassIcon className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
          <p>No audit events found</p>
        </div>
      ) : (
        <div className="rounded-xl" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          {events.map((event, idx) => (
            <div
              key={event.id}
              onClick={() => handleSelectEvent(event)}
              className="px-6 py-4 hover:bg-gray-50 cursor-pointer flex items-center gap-4"
              style={idx > 0 ? { borderTop: '1px solid var(--border)' } : undefined}
            >
              <div className="flex-shrink-0">{getCategoryIcon(event.category)}</div>
              <div className="flex-shrink-0 w-36 text-xs" style={{ color: 'var(--text-muted)' }}>
                <ClockIcon className="w-3 h-3 inline mr-1" />
                {new Date(event.timestamp).toLocaleString()}
              </div>
              <div className="flex-shrink-0">{getSeverityBadge(event.severity)}</div>
              <div className="flex-1 min-w-0">
                <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{event.action}</span>
                {event.target && <span className="text-sm ml-1" style={{ color: 'var(--text-muted)' }}>on {event.target}</span>}
              </div>
              <div className="flex-shrink-0 text-xs flex items-center gap-1" style={{ color: 'var(--text-muted)' }}>
                <UserIcon className="w-3 h-3" /> {event.actor}
              </div>
              {event.correlationId && <LinkIcon className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />}
            </div>
          ))}
        </div>
      )}

      {/* Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={() => setSelectedEvent(null)}>
          <div className="rounded-2xl max-w-lg w-full max-h-[80vh] overflow-y-auto" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} onClick={e => e.stopPropagation()}>
            <div className="p-6 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                {getCategoryIcon(selectedEvent.category)}
                <h2 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>Event Details</h2>
              </div>
              <button onClick={() => setSelectedEvent(null)} style={{ color: 'var(--text-muted)' }}><XMarkIcon className="w-6 h-6" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Timestamp</h4>
                  <p className="text-sm" style={{ color: 'var(--text-primary)' }}>{new Date(selectedEvent.timestamp).toLocaleString()}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Severity</h4>
                  {getSeverityBadge(selectedEvent.severity)}
                </div>
                <div>
                  <h4 className="text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Category</h4>
                  <p className="text-sm capitalize" style={{ color: 'var(--text-primary)' }}>{selectedEvent.category}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Actor</h4>
                  <p className="text-sm" style={{ color: 'var(--text-primary)' }}>{selectedEvent.actor}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Action</h4>
                  <p className="text-sm" style={{ color: 'var(--text-primary)' }}>{selectedEvent.action}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Target</h4>
                  <p className="text-sm" style={{ color: 'var(--text-primary)' }}>{selectedEvent.target}</p>
                </div>
              </div>
              {selectedEvent.ipAddress && (
                <div>
                  <h4 className="text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>IP Address</h4>
                  <p className="text-sm" style={{ color: 'var(--text-primary)' }}>{selectedEvent.ipAddress}</p>
                </div>
              )}
              {selectedEvent.details && Object.keys(selectedEvent.details).length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold uppercase mb-1" style={{ color: 'var(--text-muted)' }}>Details</h4>
                  <pre className="text-xs rounded-lg p-3 overflow-x-auto" style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' }}>{JSON.stringify(selectedEvent.details, null, 2)}</pre>
                </div>
              )}
              {correlatedEvents.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold uppercase mb-2" style={{ color: 'var(--text-muted)' }}>Correlated Events</h4>
                  <div className="space-y-2">
                    {correlatedEvents.map(ce => (
                      <div key={ce.id} className="flex items-center gap-2 rounded-lg p-2 text-sm" style={{ background: 'var(--bg-surface-raised)' }}>
                        {getCategoryIcon(ce.category)}
                        <span style={{ color: 'var(--text-secondary)' }}>{ce.action}</span>
                        <span className="text-xs ml-auto" style={{ color: 'var(--text-muted)' }}>{new Date(ce.timestamp).toLocaleTimeString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Demo Data ──────────────────────────────────────────────────────────────────

function getDemoEvents(): AuditEvent[] {
  const now = Date.now();
  return [
    { id: 'e1', timestamp: new Date(now - 60000).toISOString(), category: 'auth', severity: 'info', actor: 'admin@corp.local', action: 'User login', target: 'Web Console', ipAddress: '192.168.1.10', correlationId: 'corr-1' },
    { id: 'e2', timestamp: new Date(now - 180000).toISOString(), category: 'policy', severity: 'info', actor: 'admin@corp.local', action: 'Policy deployed', target: 'CIS-Win11-L1', correlationId: 'corr-1' },
    { id: 'e3', timestamp: new Date(now - 300000).toISOString(), category: 'device', severity: 'warning', actor: 'system', action: 'Device compliance check failed', target: 'DESKTOP-A1B2C3' },
    { id: 'e4', timestamp: new Date(now - 600000).toISOString(), category: 'security', severity: 'critical', actor: 'system', action: 'Multiple failed login attempts', target: 'jdoe@corp.local', ipAddress: '10.0.0.55' },
    { id: 'e5', timestamp: new Date(now - 900000).toISOString(), category: 'admin', severity: 'info', actor: 'admin@corp.local', action: 'User created', target: 'newuser@corp.local' },
    { id: 'e6', timestamp: new Date(now - 1200000).toISOString(), category: 'system', severity: 'info', actor: 'system', action: 'Backup completed', target: 'Full backup #247' },
    { id: 'e7', timestamp: new Date(now - 1800000).toISOString(), category: 'auth', severity: 'warning', actor: 'jsmith@corp.local', action: 'MFA challenge failed', target: 'VPN Gateway', ipAddress: '203.0.113.42' },
    { id: 'e8', timestamp: new Date(now - 3600000).toISOString(), category: 'device', severity: 'info', actor: 'system', action: 'Device enrolled', target: 'MacBook-Pro-Jane' },
    { id: 'e9', timestamp: new Date(now - 5400000).toISOString(), category: 'policy', severity: 'warning', actor: 'admin@corp.local', action: 'Policy rollback', target: 'USB-Restrict-v2', details: { reason: 'Caused peripheral issues' } },
    { id: 'e10', timestamp: new Date(now - 7200000).toISOString(), category: 'security', severity: 'critical', actor: 'system', action: 'Malware detected', target: 'LAPTOP-XYZ789', details: { threatName: 'Trojan.GenericKD', filePath: 'C:\\Users\\jdoe\\Downloads\\setup.exe' } },
  ];
}

function getDemoStats(): AuditStats {
  return {
    eventsToday: 247,
    criticalEvents: 3,
    topActors: [
      { actor: 'admin@corp.local', count: 89 },
      { actor: 'system', count: 134 },
      { actor: 'jsmith@corp.local', count: 12 },
      { actor: 'jdoe@corp.local', count: 8 },
    ],
  };
}
