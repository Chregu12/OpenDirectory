'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  BellIcon,
  BellAlertIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  CheckCircleIcon,
  XMarkIcon,
  PlusIcon,
  ArrowPathIcon,
  FunnelIcon,
  CogIcon,
  EnvelopeIcon,
  ChatBubbleLeftRightIcon,
  LinkIcon,
  ShieldExclamationIcon,
  ClockIcon,
  CheckIcon,
  TrashIcon,
  PaperAirplaneIcon,
  XCircleIcon,
  AdjustmentsHorizontalIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import { api } from '@/lib/api';

// ── Types ─────────────────────────────────────────────────────────────────────

type AlertSeverity = 'critical' | 'warning' | 'info';
type AlertStatus   = 'active' | 'acknowledged' | 'resolved';

interface Alert {
  id: string;
  name: string;
  service: string;
  severity: AlertSeverity;
  status: AlertStatus;
  message: string;
  createdAt: number;
  acknowledgedAt?: number | null;
  acknowledgedBy?: string | null;
}

interface AlertRule {
  id: string;
  name: string;
  service: string;
  metric: string;
  operator: string;
  threshold: number;
  severity: AlertSeverity;
  notificationChannels: string[];
  enabled: boolean;
}

type ChannelType = 'email' | 'slack' | 'webhook' | 'pagerduty';

interface NotificationChannel {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  config: Record<string, string>;
}

interface NotificationHistoryEntry {
  channelId: string;
  channelName: string;
  channelType: ChannelType;
  alertName: string;
  subject: string;
  status: 'delivered' | 'failed' | 'skipped';
  error?: string | null;
  sentAt: number;
}

// ── Mock seed data ─────────────────────────────────────────────────────────────

const MOCK_ALERTS: Alert[] = [
  { id: 'a1', name: 'High CPU Usage', service: 'node-3', severity: 'critical', status: 'active', message: 'CPU usage at 91% (threshold: > 90%)', createdAt: Date.now() - 420000 },
  { id: 'a2', name: 'Memory Pressure', service: 'auth-service', severity: 'warning', status: 'active', message: 'Memory usage at 87% (threshold: > 85%)', createdAt: Date.now() - 900000 },
  { id: 'a3', name: 'Slow Response Time', service: 'api-gateway', severity: 'warning', status: 'acknowledged', message: 'P95 latency at 2340 ms (threshold: > 2000 ms)', createdAt: Date.now() - 3600000, acknowledgedAt: Date.now() - 1800000, acknowledgedBy: 'admin' },
  { id: 'a4', name: 'Disk Usage Critical', service: 'storage-node-1', severity: 'critical', status: 'active', message: 'Disk usage at 96% (threshold: > 95%)', createdAt: Date.now() - 180000 },
  { id: 'a5', name: 'High Error Rate', service: 'user-service', severity: 'info', status: 'active', message: 'Error rate at 1.2% in the last 5 minutes', createdAt: Date.now() - 60000 },
  { id: 'a6', name: 'SSL Certificate Expiry', service: 'api-gateway', severity: 'warning', status: 'active', message: 'SSL certificate expires in 14 days', createdAt: Date.now() - 7200000 },
];

const MOCK_RULES: AlertRule[] = [
  { id: 'r1', name: 'High CPU Usage', service: 'all', metric: 'CPU', operator: '>', threshold: 90, severity: 'critical', notificationChannels: ['email', 'slack'], enabled: true },
  { id: 'r2', name: 'Memory Pressure', service: 'all', metric: 'Memory', operator: '>', threshold: 85, severity: 'warning', notificationChannels: ['email', 'slack'], enabled: true },
  { id: 'r3', name: 'Disk Usage Critical', service: 'all', metric: 'Disk', operator: '>', threshold: 95, severity: 'critical', notificationChannels: ['email', 'slack', 'webhook'], enabled: true },
  { id: 'r4', name: 'Slow Response Time', service: 'api-gateway', metric: 'Response Time', operator: '>', threshold: 2000, severity: 'warning', notificationChannels: ['slack'], enabled: false },
  { id: 'r5', name: 'High Error Rate', service: 'api', metric: 'Error Rate', operator: '>', threshold: 5, severity: 'warning', notificationChannels: ['slack'], enabled: true },
];

const MOCK_CHANNELS: NotificationChannel[] = [
  { id: 'c1', name: 'Admin Email', type: 'email', enabled: true, config: { to: 'admin@opendirectory.local' } },
  { id: 'c2', name: 'Ops Slack', type: 'slack', enabled: true, config: { webhookUrl: 'https://hooks.slack.com/...' } },
  { id: 'c3', name: 'Monitoring Webhook', type: 'webhook', enabled: false, config: { url: '', method: 'POST' } },
  { id: 'c4', name: 'PagerDuty On-Call', type: 'pagerduty', enabled: false, config: { routingKey: '' } },
];

const MOCK_HISTORY: NotificationHistoryEntry[] = [
  { channelId: 'c1', channelName: 'Admin Email', channelType: 'email', alertName: 'Disk Usage Critical', subject: '[ALERT] CRITICAL — Disk Usage Critical', status: 'delivered', sentAt: Date.now() - 180000 },
  { channelId: 'c2', channelName: 'Ops Slack', channelType: 'slack', alertName: 'Disk Usage Critical', subject: '[ALERT] CRITICAL — Disk Usage Critical', status: 'delivered', sentAt: Date.now() - 179000 },
  { channelId: 'c1', channelName: 'Admin Email', channelType: 'email', alertName: 'High CPU Usage', subject: '[ALERT] CRITICAL — High CPU Usage', status: 'delivered', sentAt: Date.now() - 420000 },
  { channelId: 'c2', channelName: 'Ops Slack', channelType: 'slack', alertName: 'Memory Pressure', subject: '[ALERT] WARNING — Memory Pressure', status: 'delivered', sentAt: Date.now() - 900000 },
  { channelId: 'c3', channelName: 'Monitoring Webhook', channelType: 'webhook', alertName: 'Slow Response Time', subject: '[ALERT] WARNING — Slow Response Time', status: 'failed', error: 'Connection refused', sentAt: Date.now() - 3600000 },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function severityBadge(severity: AlertSeverity) {
  switch (severity) {
    case 'critical': return 'bg-red-100 text-red-700 border border-red-200';
    case 'warning':  return 'bg-orange-100 text-orange-700 border border-orange-200';
    case 'info':     return 'bg-blue-100 text-blue-700 border border-blue-200';
  }
}

function severityLabel(severity: AlertSeverity) {
  switch (severity) {
    case 'critical': return 'Kritisch';
    case 'warning':  return 'Warnung';
    case 'info':     return 'Info';
  }
}

function statusBadge(status: AlertStatus) {
  switch (status) {
    case 'active':       return 'bg-red-50 text-red-600';
    case 'acknowledged': return 'bg-yellow-50 text-yellow-700';
    case 'resolved':     return 'bg-green-50 text-green-700';
  }
}

function statusLabel(status: AlertStatus) {
  switch (status) {
    case 'active':       return 'Aktiv';
    case 'acknowledged': return 'Bestätigt';
    case 'resolved':     return 'Gelöst';
  }
}

function channelIcon(type: ChannelType) {
  switch (type) {
    case 'email':     return <EnvelopeIcon className="w-5 h-5" />;
    case 'slack':     return <ChatBubbleLeftRightIcon className="w-5 h-5" />;
    case 'webhook':   return <LinkIcon className="w-5 h-5" />;
    case 'pagerduty': return <ShieldExclamationIcon className="w-5 h-5" />;
  }
}

function channelTypeName(type: ChannelType) {
  switch (type) {
    case 'email':     return 'E-Mail';
    case 'slack':     return 'Slack';
    case 'webhook':   return 'Webhook';
    case 'pagerduty': return 'PagerDuty';
  }
}

function relativeTime(ms: number): string {
  const diff = Date.now() - ms;
  if (diff < 60000)  return 'Gerade eben';
  if (diff < 3600000) return `vor ${Math.floor(diff / 60000)} Min.`;
  if (diff < 86400000) return `vor ${Math.floor(diff / 3600000)} Std.`;
  return `vor ${Math.floor(diff / 86400000)} Tag(en)`;
}

type TabKey = 'active' | 'rules' | 'channels' | 'history';

// ── Main Component ────────────────────────────────────────────────────────────

export default function AlertingView() {
  const [activeTab, setActiveTab] = useState<TabKey>('active');
  const [loading, setLoading] = useState(false);

  // Alerts state
  const [alerts, setAlerts] = useState<Alert[]>(MOCK_ALERTS);
  const [severityFilter, setSeverityFilter] = useState<AlertSeverity | 'alle'>('alle');
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set());

  // Rules state
  const [rules, setRules] = useState<AlertRule[]>(MOCK_RULES);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [editingRule, setEditingRule] = useState<Partial<AlertRule>>({});

  // Channels state
  const [channels, setChannels] = useState<NotificationChannel[]>(MOCK_CHANNELS);
  const [showChannelModal, setShowChannelModal] = useState(false);
  const [editingChannel, setEditingChannel] = useState<Partial<NotificationChannel>>({});

  // History state
  const [history, setHistory] = useState<NotificationHistoryEntry[]>(MOCK_HISTORY);

  // ── Stats ────────────────────────────────────────────────────────────────

  const activeAlerts       = alerts.filter((a) => a.status === 'active');
  const criticalCount      = activeAlerts.filter((a) => a.severity === 'critical').length;
  const warningCount       = activeAlerts.filter((a) => a.severity === 'warning').length;
  const infoCount          = activeAlerts.filter((a) => a.severity === 'info').length;

  // ── API calls ─────────────────────────────────────────────────────────────

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await api.get('/api/monitoring/alerts');
      if (res.data?.data) setAlerts(res.data.data);
    } catch {
      // Use mock data when service unavailable
    }
  }, []);

  const fetchChannels = useCallback(async () => {
    try {
      const res = await api.get('/api/monitoring/notifications/channels');
      if (res.data?.data) setChannels(res.data.data);
    } catch {
      // Use mock data
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    fetchChannels();
  }, [fetchAlerts, fetchChannels]);

  // ── Alert actions ─────────────────────────────────────────────────────────

  const acknowledgeAlert = async (id: string) => {
    try {
      await api.post(`/api/monitoring/alerts/${id}/acknowledge`, { acknowledgedBy: 'admin' });
      setAlerts((prev) =>
        prev.map((a) => a.id === id ? { ...a, status: 'acknowledged', acknowledgedAt: Date.now(), acknowledgedBy: 'admin' } : a)
      );
      toast.success('Alert bestätigt');
    } catch {
      setAlerts((prev) =>
        prev.map((a) => a.id === id ? { ...a, status: 'acknowledged', acknowledgedAt: Date.now(), acknowledgedBy: 'admin' } : a)
      );
      toast.success('Alert bestätigt');
    }
  };

  const closeAlert = async (id: string) => {
    try {
      await api.put(`/api/monitoring/alerts/${id}`, { status: 'resolved' });
    } catch { /* ignore */ }
    setAlerts((prev) => prev.filter((a) => a.id !== id));
    toast.success('Alert geschlossen');
  };

  const bulkAcknowledge = async () => {
    const ids = Array.from(selectedAlerts);
    if (ids.length === 0) return;
    try {
      await api.post('/api/monitoring/alerts/bulk-acknowledge', { alertIds: ids, acknowledgedBy: 'admin' });
    } catch { /* ignore */ }
    setAlerts((prev) =>
      prev.map((a) => ids.includes(a.id) ? { ...a, status: 'acknowledged', acknowledgedAt: Date.now() } : a)
    );
    setSelectedAlerts(new Set());
    toast.success(`${ids.length} Alert(s) bestätigt`);
  };

  const toggleSelectAlert = (id: string) => {
    setSelectedAlerts((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  // ── Rule actions ──────────────────────────────────────────────────────────

  const toggleRule = (id: string) => {
    setRules((prev) => prev.map((r) => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const saveRule = () => {
    if (!editingRule.name || !editingRule.metric) {
      toast.error('Name und Metrik sind Pflichtfelder');
      return;
    }
    if (editingRule.id) {
      setRules((prev) => prev.map((r) => r.id === editingRule.id ? { ...r, ...editingRule } as AlertRule : r));
      toast.success('Regel aktualisiert');
    } else {
      const newRule: AlertRule = {
        id: `r${Date.now()}`,
        name: editingRule.name!,
        service: editingRule.service || 'all',
        metric: editingRule.metric!,
        operator: editingRule.operator || '>',
        threshold: editingRule.threshold ?? 80,
        severity: editingRule.severity || 'warning',
        notificationChannels: editingRule.notificationChannels || [],
        enabled: true,
      };
      setRules((prev) => [...prev, newRule]);
      toast.success('Neue Regel erstellt');
    }
    setShowRuleModal(false);
    setEditingRule({});
  };

  // ── Channel actions ───────────────────────────────────────────────────────

  const testChannel = async (id: string) => {
    const ch = channels.find((c) => c.id === id);
    try {
      await api.post('/api/monitoring/notifications/test', { channelId: id });
      toast.success(`Test an "${ch?.name}" gesendet`);
    } catch {
      toast.success(`Test an "${ch?.name}" gesendet (simuliert)`);
    }
  };

  const saveChannel = () => {
    if (!editingChannel.name || !editingChannel.type) {
      toast.error('Name und Typ sind Pflichtfelder');
      return;
    }
    if (editingChannel.id) {
      setChannels((prev) => prev.map((c) => c.id === editingChannel.id ? { ...c, ...editingChannel } as NotificationChannel : c));
      toast.success('Kanal aktualisiert');
    } else {
      const newCh: NotificationChannel = {
        id: `c${Date.now()}`,
        name: editingChannel.name!,
        type: editingChannel.type as ChannelType,
        enabled: true,
        config: editingChannel.config || {},
      };
      setChannels((prev) => [...prev, newCh]);
      toast.success('Kanal hinzugefügt');
    }
    setShowChannelModal(false);
    setEditingChannel({});
  };

  // ── Filtered alerts ───────────────────────────────────────────────────────

  const filteredAlerts = severityFilter === 'alle'
    ? activeAlerts
    : activeAlerts.filter((a) => a.severity === severityFilter);

  // ── Render ────────────────────────────────────────────────────────────────

  const tabs: { key: TabKey; label: string }[] = [
    { key: 'active',   label: 'Aktive Alerts' },
    { key: 'rules',    label: 'Alert-Regeln' },
    { key: 'channels', label: 'Benachrichtigungskanäle' },
    { key: 'history',  label: 'Verlauf' },
  ];

  return (
    <div className="min-h-screen bg-[#F2F2F7] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-white rounded-xl shadow-sm">
            <BellAlertIcon className="w-6 h-6 text-[#0071E3]" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-gray-900">Benachrichtigungen &amp; Alerts</h1>
            <p className="text-sm text-gray-500">Verwalte Alarme, Regeln und Benachrichtigungskanäle</p>
          </div>
        </div>
        <button
          onClick={() => { fetchAlerts(); fetchChannels(); toast.success('Aktualisiert'); }}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 text-gray-700 rounded-xl text-sm font-medium hover:bg-gray-50 transition-colors shadow-sm"
        >
          <ArrowPathIcon className="w-4 h-4" />
          Aktualisieren
        </button>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Aktive Alerts', value: activeAlerts.length, icon: BellIcon, color: 'text-[#0071E3]', bg: 'bg-blue-50' },
          { label: 'Kritisch',      value: criticalCount,       icon: XCircleIcon,              color: 'text-red-600',   bg: 'bg-red-50'  },
          { label: 'Warnung',       value: warningCount,        icon: ExclamationTriangleIcon,  color: 'text-orange-600', bg: 'bg-orange-50' },
          { label: 'Info',          value: infoCount,           icon: InformationCircleIcon,    color: 'text-blue-500',  bg: 'bg-sky-50'  },
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="bg-white rounded-2xl p-4 shadow-sm flex items-center gap-3">
            <div className={`p-2.5 rounded-xl ${bg}`}>
              <Icon className={`w-5 h-5 ${color}`} />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{value}</p>
              <p className="text-xs text-gray-500">{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tab bar */}
      <div className="bg-white rounded-2xl shadow-sm mb-6 overflow-hidden">
        <div className="flex border-b border-gray-100">
          {tabs.map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`flex-1 px-4 py-3.5 text-sm font-medium transition-colors ${
                activeTab === key
                  ? 'text-[#0071E3] border-b-2 border-[#0071E3] bg-blue-50/40'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* ── Tab 1: Aktive Alerts ─────────────────────────────────────────────── */}
        {activeTab === 'active' && (
          <div className="p-6">
            {/* Filter bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
              <div className="flex items-center gap-2">
                <FunnelIcon className="w-4 h-4 text-gray-400" />
                <span className="text-sm text-gray-500">Filter:</span>
                {(['alle', 'critical', 'warning', 'info'] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setSeverityFilter(f)}
                    className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                      severityFilter === f
                        ? 'bg-[#0071E3] text-white'
                        : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                    }`}
                  >
                    {f === 'alle' ? 'Alle' : severityLabel(f)}
                  </button>
                ))}
              </div>
              {selectedAlerts.size > 0 && (
                <button
                  onClick={bulkAcknowledge}
                  className="flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white rounded-xl text-sm font-medium hover:bg-[#0071E3]/90 transition-colors"
                >
                  <CheckIcon className="w-4 h-4" />
                  {selectedAlerts.size} bestätigen
                </button>
              )}
            </div>

            {filteredAlerts.length === 0 ? (
              <div className="text-center py-16 text-gray-400">
                <CheckCircleIcon className="w-12 h-12 mx-auto mb-3 opacity-40" />
                <p className="font-medium">Keine aktiven Alerts</p>
                <p className="text-sm mt-1">Alle Systeme laufen normal</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-gray-400 border-b border-gray-100">
                      <th className="pb-3 pr-4 font-medium w-8">
                        <input
                          type="checkbox"
                          checked={selectedAlerts.size === filteredAlerts.length && filteredAlerts.length > 0}
                          onChange={(e) => {
                            if (e.target.checked) setSelectedAlerts(new Set(filteredAlerts.map((a) => a.id)));
                            else setSelectedAlerts(new Set());
                          }}
                          className="rounded"
                        />
                      </th>
                      <th className="pb-3 pr-4 font-medium">Name</th>
                      <th className="pb-3 pr-4 font-medium">Service</th>
                      <th className="pb-3 pr-4 font-medium">Schwere</th>
                      <th className="pb-3 pr-4 font-medium">Meldung</th>
                      <th className="pb-3 pr-4 font-medium">Zeit</th>
                      <th className="pb-3 pr-4 font-medium">Status</th>
                      <th className="pb-3 font-medium">Aktionen</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-50">
                    {filteredAlerts.map((alert) => (
                      <tr key={alert.id} className="hover:bg-gray-50/60 transition-colors">
                        <td className="py-3 pr-4">
                          <input
                            type="checkbox"
                            checked={selectedAlerts.has(alert.id)}
                            onChange={() => toggleSelectAlert(alert.id)}
                            className="rounded"
                          />
                        </td>
                        <td className="py-3 pr-4 font-medium text-gray-900">{alert.name}</td>
                        <td className="py-3 pr-4">
                          <span className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded-md text-xs font-mono">
                            {alert.service}
                          </span>
                        </td>
                        <td className="py-3 pr-4">
                          <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${severityBadge(alert.severity)}`}>
                            {severityLabel(alert.severity)}
                          </span>
                        </td>
                        <td className="py-3 pr-4 text-gray-500 max-w-xs truncate">{alert.message}</td>
                        <td className="py-3 pr-4 text-gray-400 whitespace-nowrap">
                          <span className="flex items-center gap-1">
                            <ClockIcon className="w-3.5 h-3.5" />
                            {relativeTime(alert.createdAt)}
                          </span>
                        </td>
                        <td className="py-3 pr-4">
                          <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${statusBadge(alert.status)}`}>
                            {statusLabel(alert.status)}
                          </span>
                        </td>
                        <td className="py-3">
                          <div className="flex items-center gap-2">
                            {alert.status === 'active' && (
                              <button
                                onClick={() => acknowledgeAlert(alert.id)}
                                title="Bestätigen"
                                className="p-1.5 text-gray-400 hover:text-[#0071E3] hover:bg-blue-50 rounded-lg transition-colors"
                              >
                                <CheckIcon className="w-4 h-4" />
                              </button>
                            )}
                            <button
                              onClick={() => closeAlert(alert.id)}
                              title="Schliessen"
                              className="p-1.5 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                            >
                              <XMarkIcon className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── Tab 2: Alert-Regeln ──────────────────────────────────────────────── */}
        {activeTab === 'rules' && (
          <div className="p-6">
            <div className="flex items-center justify-between mb-5">
              <p className="text-sm text-gray-500">{rules.length} Regeln konfiguriert</p>
              <button
                onClick={() => { setEditingRule({}); setShowRuleModal(true); }}
                className="flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white rounded-xl text-sm font-medium hover:bg-[#0071E3]/90 transition-colors"
              >
                <PlusIcon className="w-4 h-4" />
                Neue Regel
              </button>
            </div>

            <div className="space-y-3">
              {rules.map((rule) => (
                <div key={rule.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-xl hover:bg-gray-100/70 transition-colors">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <AdjustmentsHorizontalIcon className="w-5 h-5 text-gray-400 flex-shrink-0" />
                    <div className="min-w-0">
                      <p className="font-medium text-gray-900 truncate">{rule.name}</p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        {rule.service} · {rule.metric} {rule.operator} {rule.threshold} ·{' '}
                        <span className={`font-medium ${rule.severity === 'critical' ? 'text-red-600' : rule.severity === 'warning' ? 'text-orange-500' : 'text-blue-500'}`}>
                          {severityLabel(rule.severity)}
                        </span>
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 ml-4">
                    <div className="flex gap-1.5 flex-wrap justify-end">
                      {rule.notificationChannels.map((ch) => (
                        <span key={ch} className="px-2 py-0.5 bg-white border border-gray-200 rounded-full text-xs text-gray-500">
                          {ch}
                        </span>
                      ))}
                    </div>
                    <button
                      onClick={() => toggleRule(rule.id)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors flex-shrink-0 ${
                        rule.enabled ? 'bg-[#0071E3]' : 'bg-gray-200'
                      }`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform shadow-sm ${rule.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                    <button
                      onClick={() => { setEditingRule({ ...rule }); setShowRuleModal(true); }}
                      className="p-1.5 text-gray-400 hover:text-[#0071E3] hover:bg-blue-50 rounded-lg transition-colors"
                    >
                      <CogIcon className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Tab 3: Benachrichtigungskanäle ──────────────────────────────────── */}
        {activeTab === 'channels' && (
          <div className="p-6">
            <div className="flex items-center justify-between mb-5">
              <p className="text-sm text-gray-500">{channels.length} Kanäle konfiguriert</p>
              <button
                onClick={() => { setEditingChannel({ type: 'email' }); setShowChannelModal(true); }}
                className="flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white rounded-xl text-sm font-medium hover:bg-[#0071E3]/90 transition-colors"
              >
                <PlusIcon className="w-4 h-4" />
                Kanal hinzufügen
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {channels.map((ch) => (
                <div key={ch.id} className="bg-gray-50 rounded-2xl p-5 flex flex-col gap-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`p-2.5 rounded-xl ${ch.enabled ? 'bg-[#0071E3]/10 text-[#0071E3]' : 'bg-gray-200 text-gray-400'}`}>
                        {channelIcon(ch.type)}
                      </div>
                      <div>
                        <p className="font-semibold text-gray-900">{ch.name}</p>
                        <p className="text-xs text-gray-500">{channelTypeName(ch.type)}</p>
                      </div>
                    </div>
                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${ch.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                      {ch.enabled ? 'Aktiv' : 'Inaktiv'}
                    </span>
                  </div>

                  {ch.type === 'email' && ch.config.to && (
                    <p className="text-xs text-gray-500 font-mono truncate">{ch.config.to}</p>
                  )}
                  {ch.type === 'slack' && ch.config.webhookUrl && (
                    <p className="text-xs text-gray-500 font-mono truncate">{ch.config.webhookUrl.substring(0, 40)}…</p>
                  )}
                  {ch.type === 'webhook' && ch.config.url && (
                    <p className="text-xs text-gray-500 font-mono truncate">{ch.config.url}</p>
                  )}

                  <div className="flex gap-2 mt-auto">
                    <button
                      onClick={() => { setEditingChannel({ ...ch }); setShowChannelModal(true); }}
                      className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-white border border-gray-200 text-gray-700 rounded-xl text-xs font-medium hover:bg-gray-50 transition-colors"
                    >
                      <CogIcon className="w-3.5 h-3.5" />
                      Konfigurieren
                    </button>
                    <button
                      onClick={() => testChannel(ch.id)}
                      className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-[#0071E3]/10 text-[#0071E3] rounded-xl text-xs font-medium hover:bg-[#0071E3]/20 transition-colors"
                    >
                      <PaperAirplaneIcon className="w-3.5 h-3.5" />
                      Test senden
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Tab 4: Verlauf ───────────────────────────────────────────────────── */}
        {activeTab === 'history' && (
          <div className="p-6">
            <p className="text-sm text-gray-500 mb-5">{history.length} gesendete Benachrichtigungen</p>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-gray-400 border-b border-gray-100">
                    <th className="pb-3 pr-4 font-medium">Zeit</th>
                    <th className="pb-3 pr-4 font-medium">Kanal</th>
                    <th className="pb-3 pr-4 font-medium">Alert</th>
                    <th className="pb-3 pr-4 font-medium">Betreff</th>
                    <th className="pb-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {history.map((entry, i) => (
                    <tr key={i} className="hover:bg-gray-50/60 transition-colors">
                      <td className="py-3 pr-4 text-gray-400 whitespace-nowrap">
                        <span className="flex items-center gap-1">
                          <ClockIcon className="w-3.5 h-3.5" />
                          {relativeTime(entry.sentAt)}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className="flex items-center gap-1.5 text-gray-600">
                          {channelIcon(entry.channelType)}
                          {entry.channelName}
                        </span>
                      </td>
                      <td className="py-3 pr-4 font-medium text-gray-900">{entry.alertName}</td>
                      <td className="py-3 pr-4 text-gray-500 max-w-xs truncate">{entry.subject}</td>
                      <td className="py-3">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          entry.status === 'delivered'
                            ? 'bg-green-100 text-green-700'
                            : entry.status === 'failed'
                            ? 'bg-red-100 text-red-700'
                            : 'bg-gray-100 text-gray-500'
                        }`}>
                          {entry.status === 'delivered' && <CheckCircleIcon className="w-3 h-3" />}
                          {entry.status === 'failed'    && <XCircleIcon      className="w-3 h-3" />}
                          {entry.status === 'delivered' ? 'Zugestellt' : entry.status === 'failed' ? 'Fehlgeschlagen' : 'Übersprungen'}
                        </span>
                        {entry.error && (
                          <p className="text-xs text-red-500 mt-0.5">{entry.error}</p>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ── Modal: Alert-Regel ─────────────────────────────────────────────────── */}
      {showRuleModal && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
              <h2 className="text-lg font-semibold text-gray-900">
                {editingRule.id ? 'Regel bearbeiten' : 'Neue Alert-Regel'}
              </h2>
              <button onClick={() => { setShowRuleModal(false); setEditingRule({}); }} className="p-2 text-gray-400 hover:text-gray-600 rounded-xl hover:bg-gray-100">
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
                <input
                  type="text"
                  value={editingRule.name || ''}
                  onChange={(e) => setEditingRule((p) => ({ ...p, name: e.target.value }))}
                  placeholder="z.B. Hohe CPU-Auslastung"
                  className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Service</label>
                  <select
                    value={editingRule.service || 'all'}
                    onChange={(e) => setEditingRule((p) => ({ ...p, service: e.target.value }))}
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  >
                    <option value="all">Alle</option>
                    <option value="api-gateway">API Gateway</option>
                    <option value="auth-service">Auth Service</option>
                    <option value="user-service">User Service</option>
                    <option value="device-service">Device Service</option>
                    <option value="policy-service">Policy Service</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Metrik *</label>
                  <select
                    value={editingRule.metric || ''}
                    onChange={(e) => setEditingRule((p) => ({ ...p, metric: e.target.value }))}
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  >
                    <option value="">Auswählen…</option>
                    <option value="CPU">CPU (%)</option>
                    <option value="Memory">Memory (%)</option>
                    <option value="Disk">Disk (%)</option>
                    <option value="Response Time">Response Time (ms)</option>
                    <option value="Error Rate">Error Rate (%)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Operator</label>
                  <select
                    value={editingRule.operator || '>'}
                    onChange={(e) => setEditingRule((p) => ({ ...p, operator: e.target.value }))}
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  >
                    <option value=">">{'>'}</option>
                    <option value="<">{'<'}</option>
                    <option value=">=">{'>='}</option>
                    <option value="<=">{'<='}</option>
                    <option value="==">{'=='}</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Schwellenwert</label>
                  <input
                    type="number"
                    value={editingRule.threshold ?? ''}
                    onChange={(e) => setEditingRule((p) => ({ ...p, threshold: Number(e.target.value) }))}
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Schwere</label>
                  <select
                    value={editingRule.severity || 'warning'}
                    onChange={(e) => setEditingRule((p) => ({ ...p, severity: e.target.value as AlertSeverity }))}
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  >
                    <option value="critical">Kritisch</option>
                    <option value="warning">Warnung</option>
                    <option value="info">Info</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Benachrichtigungskanäle</label>
                <div className="flex flex-wrap gap-2">
                  {(['email', 'slack', 'webhook', 'pagerduty'] as const).map((ch) => {
                    const selected = (editingRule.notificationChannels || []).includes(ch);
                    return (
                      <button
                        key={ch}
                        type="button"
                        onClick={() => {
                          const current = editingRule.notificationChannels || [];
                          setEditingRule((p) => ({
                            ...p,
                            notificationChannels: selected ? current.filter((c) => c !== ch) : [...current, ch],
                          }));
                        }}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-colors ${
                          selected ? 'bg-[#0071E3] text-white border-[#0071E3]' : 'bg-white text-gray-600 border-gray-200 hover:border-[#0071E3]'
                        }`}
                      >
                        {channelIcon(ch)}
                        {channelTypeName(ch)}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3 px-6 py-4 border-t border-gray-100">
              <button
                onClick={() => { setShowRuleModal(false); setEditingRule({}); }}
                className="px-4 py-2 border border-gray-200 text-gray-700 rounded-xl text-sm font-medium hover:bg-gray-50"
              >
                Abbrechen
              </button>
              <button
                onClick={saveRule}
                className="px-4 py-2 bg-[#0071E3] text-white rounded-xl text-sm font-medium hover:bg-[#0071E3]/90"
              >
                {editingRule.id ? 'Speichern' : 'Erstellen'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Modal: Benachrichtigungskanal ──────────────────────────────────────── */}
      {showChannelModal && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
              <h2 className="text-lg font-semibold text-gray-900">
                {editingChannel.id ? 'Kanal konfigurieren' : 'Kanal hinzufügen'}
              </h2>
              <button onClick={() => { setShowChannelModal(false); setEditingChannel({}); }} className="p-2 text-gray-400 hover:text-gray-600 rounded-xl hover:bg-gray-100">
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
                  <input
                    type="text"
                    value={editingChannel.name || ''}
                    onChange={(e) => setEditingChannel((p) => ({ ...p, name: e.target.value }))}
                    placeholder="z.B. Ops Slack"
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Typ *</label>
                  <select
                    value={editingChannel.type || 'email'}
                    onChange={(e) => setEditingChannel((p) => ({ ...p, type: e.target.value as ChannelType, config: {} }))}
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  >
                    <option value="email">E-Mail</option>
                    <option value="slack">Slack</option>
                    <option value="webhook">Webhook</option>
                    <option value="pagerduty">PagerDuty</option>
                  </select>
                </div>
              </div>

              {/* Type-specific config */}
              {editingChannel.type === 'email' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Empfänger-E-Mail</label>
                  <input
                    type="email"
                    value={editingChannel.config?.to || ''}
                    onChange={(e) => setEditingChannel((p) => ({ ...p, config: { ...p.config, to: e.target.value } }))}
                    placeholder="admin@example.com"
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  />
                </div>
              )}
              {editingChannel.type === 'slack' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Slack Webhook URL</label>
                  <input
                    type="url"
                    value={editingChannel.config?.webhookUrl || ''}
                    onChange={(e) => setEditingChannel((p) => ({ ...p, config: { ...p.config, webhookUrl: e.target.value } }))}
                    placeholder="https://hooks.slack.com/services/..."
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  />
                </div>
              )}
              {editingChannel.type === 'webhook' && (
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">URL</label>
                    <input
                      type="url"
                      value={editingChannel.config?.url || ''}
                      onChange={(e) => setEditingChannel((p) => ({ ...p, config: { ...p.config, url: e.target.value } }))}
                      placeholder="https://your-service.example.com/webhook"
                      className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Methode</label>
                    <select
                      value={editingChannel.config?.method || 'POST'}
                      onChange={(e) => setEditingChannel((p) => ({ ...p, config: { ...p.config, method: e.target.value } }))}
                      className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                    >
                      <option value="POST">POST</option>
                      <option value="PUT">PUT</option>
                    </select>
                  </div>
                </div>
              )}
              {editingChannel.type === 'pagerduty' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Routing Key</label>
                  <input
                    type="text"
                    value={editingChannel.config?.routingKey || ''}
                    onChange={(e) => setEditingChannel((p) => ({ ...p, config: { ...p.config, routingKey: e.target.value } }))}
                    placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                    className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3] font-mono"
                  />
                </div>
              )}

              <div className="flex items-center justify-between pt-2">
                <span className="text-sm font-medium text-gray-700">Aktiv</span>
                <button
                  type="button"
                  onClick={() => setEditingChannel((p) => ({ ...p, enabled: !p.enabled }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    editingChannel.enabled !== false ? 'bg-[#0071E3]' : 'bg-gray-200'
                  }`}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform shadow-sm ${editingChannel.enabled !== false ? 'translate-x-6' : 'translate-x-1'}`} />
                </button>
              </div>
            </div>
            <div className="flex justify-end gap-3 px-6 py-4 border-t border-gray-100">
              <button
                onClick={() => { setShowChannelModal(false); setEditingChannel({}); }}
                className="px-4 py-2 border border-gray-200 text-gray-700 rounded-xl text-sm font-medium hover:bg-gray-50"
              >
                Abbrechen
              </button>
              <button
                onClick={saveChannel}
                className="px-4 py-2 bg-[#0071E3] text-white rounded-xl text-sm font-medium hover:bg-[#0071E3]/90"
              >
                {editingChannel.id ? 'Speichern' : 'Hinzufügen'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
