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
      case 'critical': return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700">Critical</span>;
      case 'warning': return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-yellow-100 text-yellow-700">Warning</span>;
      default: return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-700">Info</span>;
    }
  };

  // ── Simple Mode ──
  if (isSimple) {
    const criticalEvents = events.filter(e => e.severity === 'critical');
    const warningEvents = events.filter(e => e.severity === 'warning');
    const recentEvents = events.slice(0, 5);
    const allClear = criticalEvents.length === 0;

    return (
      <div className="p-6 space-y-6">
        {/* Status Hero */}
        <div className={`rounded-2xl p-8 text-center ${
          allClear
            ? 'bg-gradient-to-br from-green-50 to-emerald-100 border border-green-200'
            : 'bg-gradient-to-br from-red-50 to-red-100 border border-red-200'
        }`}>
          <div className={`w-20 h-20 mx-auto rounded-full flex items-center justify-center mb-4 ${
            allClear ? 'bg-green-200' : 'bg-red-200'
          }`}>
            {allClear ? (
              <CheckCircleIcon className="w-10 h-10 text-green-600" />
            ) : (
              <ExclamationTriangleIcon className="w-10 h-10 text-red-600" />
            )}
          </div>
          <h1 className={`text-2xl font-bold mb-1 ${allClear ? 'text-green-900' : 'text-red-900'}`}>
            {allClear ? 'No Critical Events' : `${criticalEvents.length} Critical Event${criticalEvents.length > 1 ? 's' : ''}`}
          </h1>
          <p className="text-sm text-gray-600">
            {stats.eventsToday} events today · Integrity: {integrity.status === 'ok' ? 'OK' : 'BROKEN'}
          </p>
        </div>

        {/* Compact Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white rounded-xl p-4 border border-gray-100 shadow-sm text-center">
            <p className="text-2xl font-bold text-blue-600">{stats.eventsToday}</p>
            <p className="text-xs text-gray-500 mt-1">Events Today</p>
          </div>
          <div className="bg-white rounded-xl p-4 border border-gray-100 shadow-sm text-center">
            <p className={`text-2xl font-bold ${stats.criticalEvents > 0 ? 'text-red-600' : 'text-gray-600'}`}>{stats.criticalEvents}</p>
            <p className="text-xs text-gray-500 mt-1">Critical</p>
          </div>
          <div className="bg-white rounded-xl p-4 border border-gray-100 shadow-sm text-center">
            <p className="text-2xl font-bold text-yellow-600">{warningEvents.length}</p>
            <p className="text-xs text-gray-500 mt-1">Warnings</p>
          </div>
          <div className="bg-white rounded-xl p-4 border border-gray-100 shadow-sm text-center">
            <p className={`text-2xl font-bold ${integrity.status === 'ok' ? 'text-green-600' : 'text-red-600'}`}>
              {integrity.status === 'ok' ? 'OK' : '!!'}
            </p>
            <p className="text-xs text-gray-500 mt-1">Integrity</p>
          </div>
        </div>

        {/* Recent events */}
        {recentEvents.length > 0 && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
            <h3 className="text-sm font-semibold text-gray-900 mb-3">Recent Activity</h3>
            <div className="space-y-2">
              {recentEvents.map(event => (
                <div key={event.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    {getCategoryIcon(event.category)}
                    <div>
                      <p className="text-sm font-medium text-gray-900">{event.action}</p>
                      <p className="text-xs text-gray-500">{event.actor} · {new Date(event.timestamp).toLocaleTimeString()}</p>
                    </div>
                  </div>
                  {getSeverityBadge(event.severity)}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="flex justify-center gap-3">
          <button
            onClick={loadData}
            className="flex items-center gap-2 px-6 py-3 text-sm font-medium text-white bg-blue-600 rounded-xl hover:bg-blue-700 transition-colors shadow-sm"
          >
            <ArrowPathIcon className="h-4 w-4" />
            Refresh
          </button>
          <button
            onClick={() => handleExport('csv')}
            className="flex items-center gap-2 px-6 py-3 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors"
          >
            <DocumentArrowDownIcon className="h-4 w-4" />
            Export CSV
          </button>
        </div>
      </div>
    );
  }

  // ── Expert Mode ──
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Audit Log</h1>
          <p className="text-sm text-gray-500 mt-1">Track and review all system activity</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setLiveStream(!liveStream)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium ${
              liveStream ? 'bg-green-100 text-green-700 hover:bg-green-200' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            {liveStream ? <PauseIcon className="w-4 h-4" /> : <PlayIcon className="w-4 h-4" />}
            {liveStream ? 'Live' : 'Paused'}
          </button>
          <div className="flex gap-1">
            <button onClick={() => handleExport('csv')} className="flex items-center gap-1 px-3 py-2 text-gray-600 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 text-sm">
              <DocumentArrowDownIcon className="w-4 h-4" /> CSV
            </button>
            <button onClick={() => handleExport('pdf')} className="flex items-center gap-1 px-3 py-2 text-gray-600 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 text-sm">
              <DocumentArrowDownIcon className="w-4 h-4" /> PDF
            </button>
          </div>
          <button onClick={loadData} className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100">
            <ArrowPathIcon className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2 mb-1">
            <ChartBarIcon className="w-5 h-5 text-blue-500" />
            <span className="text-sm font-medium text-gray-600">Events Today</span>
          </div>
          <p className="text-2xl font-bold text-gray-900">{stats.eventsToday}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2 mb-1">
            <ExclamationTriangleIcon className="w-5 h-5 text-red-500" />
            <span className="text-sm font-medium text-gray-600">Critical Events</span>
          </div>
          <p className="text-2xl font-bold text-gray-900">{stats.criticalEvents}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2 mb-1">
            <ShieldCheckIcon className="w-5 h-5 text-green-500" />
            <span className="text-sm font-medium text-gray-600">Integrity</span>
          </div>
          <p className="text-2xl font-bold text-gray-900">
            <span className={`inline-flex items-center gap-1 ${integrity.status === 'ok' ? 'text-green-600' : 'text-red-600'}`}>
              {integrity.status === 'ok' ? <CheckCircleIcon className="w-6 h-6" /> : <ExclamationTriangleIcon className="w-6 h-6" />}
              {integrity.status === 'ok' ? 'OK' : 'BROKEN'}
            </span>
          </p>
        </div>
      </div>

      {/* Top Actors */}
      {stats.topActors.length > 0 && (
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Top Actors</h3>
          <div className="flex gap-3 overflow-x-auto">
            {stats.topActors.map(a => (
              <div key={a.actor} className="flex items-center gap-2 bg-gray-50 rounded-lg px-3 py-2 text-sm flex-shrink-0">
                <UserIcon className="w-4 h-4 text-gray-400" />
                <span className="font-medium text-gray-700">{a.actor}</span>
                <span className="text-gray-400">{a.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center bg-white rounded-xl border border-gray-200 p-4">
        <FunnelIcon className="w-5 h-5 text-gray-400" />
        <select value={filterCategory} onChange={e => setFilterCategory(e.target.value)} className="border border-gray-300 rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
          <option value="all">All Categories</option>
          <option value="auth">Auth</option>
          <option value="device">Device</option>
          <option value="policy">Policy</option>
          <option value="admin">Admin</option>
          <option value="system">System</option>
          <option value="security">Security</option>
        </select>
        <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} className="border border-gray-300 rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
          <option value="all">All Severities</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="critical">Critical</option>
        </select>
        <input type="date" value={filterDateFrom} onChange={e => setFilterDateFrom(e.target.value)} className="border border-gray-300 rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" placeholder="From" />
        <input type="date" value={filterDateTo} onChange={e => setFilterDateTo(e.target.value)} className="border border-gray-300 rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" placeholder="To" />
        <div className="relative flex-1 min-w-[200px]">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search events..."
            value={filterSearch}
            onChange={e => setFilterSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>
      </div>

      {/* Event Timeline */}
      {loading ? (
        <div className="flex items-center justify-center py-20"><ArrowPathIcon className="w-8 h-8 animate-spin text-blue-500" /></div>
      ) : events.length === 0 ? (
        <div className="text-center py-20 text-gray-500">
          <DocumentMagnifyingGlassIcon className="w-12 h-12 mx-auto mb-3 text-gray-300" />
          <p>No audit events found</p>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-100">
          {events.map(event => (
            <div
              key={event.id}
              onClick={() => handleSelectEvent(event)}
              className="px-6 py-4 hover:bg-gray-50 cursor-pointer flex items-center gap-4"
            >
              <div className="flex-shrink-0">{getCategoryIcon(event.category)}</div>
              <div className="flex-shrink-0 w-36 text-xs text-gray-500">
                <ClockIcon className="w-3 h-3 inline mr-1" />
                {new Date(event.timestamp).toLocaleString()}
              </div>
              <div className="flex-shrink-0">{getSeverityBadge(event.severity)}</div>
              <div className="flex-1 min-w-0">
                <span className="text-sm text-gray-900 font-medium">{event.action}</span>
                {event.target && <span className="text-sm text-gray-500 ml-1">on {event.target}</span>}
              </div>
              <div className="flex-shrink-0 text-xs text-gray-500 flex items-center gap-1">
                <UserIcon className="w-3 h-3" /> {event.actor}
              </div>
              {event.correlationId && <LinkIcon className="w-4 h-4 text-gray-300 flex-shrink-0" />}
            </div>
          ))}
        </div>
      )}

      {/* Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={() => setSelectedEvent(null)}>
          <div className="bg-white rounded-2xl max-w-lg w-full max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="p-6 border-b border-gray-200 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {getCategoryIcon(selectedEvent.category)}
                <h2 className="text-lg font-bold text-gray-900">Event Details</h2>
              </div>
              <button onClick={() => setSelectedEvent(null)} className="text-gray-400 hover:text-gray-600"><XMarkIcon className="w-6 h-6" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="text-xs font-semibold text-gray-500 uppercase">Timestamp</h4>
                  <p className="text-sm text-gray-900">{new Date(selectedEvent.timestamp).toLocaleString()}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-gray-500 uppercase">Severity</h4>
                  {getSeverityBadge(selectedEvent.severity)}
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-gray-500 uppercase">Category</h4>
                  <p className="text-sm text-gray-900 capitalize">{selectedEvent.category}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-gray-500 uppercase">Actor</h4>
                  <p className="text-sm text-gray-900">{selectedEvent.actor}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-gray-500 uppercase">Action</h4>
                  <p className="text-sm text-gray-900">{selectedEvent.action}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-gray-500 uppercase">Target</h4>
                  <p className="text-sm text-gray-900">{selectedEvent.target}</p>
                </div>
              </div>
              {selectedEvent.ipAddress && (
                <div>
                  <h4 className="text-xs font-semibold text-gray-500 uppercase">IP Address</h4>
                  <p className="text-sm text-gray-900">{selectedEvent.ipAddress}</p>
                </div>
              )}
              {selectedEvent.details && Object.keys(selectedEvent.details).length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Details</h4>
                  <pre className="text-xs bg-gray-50 rounded-lg p-3 overflow-x-auto">{JSON.stringify(selectedEvent.details, null, 2)}</pre>
                </div>
              )}
              {correlatedEvents.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-gray-500 uppercase mb-2">Correlated Events</h4>
                  <div className="space-y-2">
                    {correlatedEvents.map(ce => (
                      <div key={ce.id} className="flex items-center gap-2 bg-gray-50 rounded-lg p-2 text-sm">
                        {getCategoryIcon(ce.category)}
                        <span className="text-gray-700">{ce.action}</span>
                        <span className="text-gray-400 text-xs ml-auto">{new Date(ce.timestamp).toLocaleTimeString()}</span>
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
