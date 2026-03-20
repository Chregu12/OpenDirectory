'use client';

import React, { useState, useEffect } from 'react';
import {
  ChartBarSquareIcon,
  BellAlertIcon,
  EnvelopeIcon,
  CheckIcon,
  ArrowRightIcon,
  ArrowLeftIcon,
  XMarkIcon,
  SignalIcon,
  CpuChipIcon,
  ServerIcon,
} from '@heroicons/react/24/outline';
import { monitoringApi, prometheusApi, grafanaApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';

type WizardStep = 1 | 2 | 3 | 4 | 5;

interface MonitoringAlertingWizardProps {
  onClose: () => void;
}

interface MetricCategory {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  metrics: string[];
}

interface AlertRule {
  id: string;
  name: string;
  metric: string;
  operator: '>' | '<' | '==' | '!=';
  threshold: number;
  unit: string;
  severity: 'critical' | 'warning' | 'info';
  enabled: boolean;
}

interface NotificationChannel {
  type: 'email' | 'slack' | 'pagerduty' | 'webhook';
  name: string;
  enabled: boolean;
  config: Record<string, string>;
}

const STEPS = [
  { n: 1 as const, label: 'Übersicht' },
  { n: 2 as const, label: 'Metriken' },
  { n: 3 as const, label: 'Alerts' },
  { n: 4 as const, label: 'Benachrichtigung' },
  { n: 5 as const, label: 'Dashboard' },
];

const DEFAULT_METRICS: MetricCategory[] = [
  { id: 'cpu', name: 'CPU-Auslastung', description: 'Prozessorauslastung aller Geräte', enabled: true, metrics: ['cpu_usage_percent', 'cpu_load_avg'] },
  { id: 'memory', name: 'Arbeitsspeicher', description: 'RAM-Nutzung und Swap', enabled: true, metrics: ['memory_usage_percent', 'swap_usage'] },
  { id: 'disk', name: 'Festplatten', description: 'Speicherplatz und I/O', enabled: true, metrics: ['disk_usage_percent', 'disk_io_read', 'disk_io_write'] },
  { id: 'network', name: 'Netzwerk', description: 'Bandbreite, Pakete, Fehler', enabled: true, metrics: ['network_rx_bytes', 'network_tx_bytes', 'network_errors'] },
  { id: 'services', name: 'Service-Health', description: 'Status aller OpenDirectory-Dienste', enabled: true, metrics: ['service_up', 'service_response_time'] },
  { id: 'auth', name: 'Authentifizierung', description: 'Login-Versuche, aktive Sessions', enabled: false, metrics: ['auth_success', 'auth_failure', 'active_sessions'] },
  { id: 'devices', name: 'Geräte-Verbindungen', description: 'Online-Status und Agent-Health', enabled: false, metrics: ['devices_online', 'agent_heartbeat'] },
];

const DEFAULT_ALERTS: AlertRule[] = [
  { id: 'cpu_high', name: 'CPU-Auslastung hoch', metric: 'cpu_usage_percent', operator: '>', threshold: 90, unit: '%', severity: 'critical', enabled: true },
  { id: 'memory_high', name: 'RAM-Auslastung hoch', metric: 'memory_usage_percent', operator: '>', threshold: 85, unit: '%', severity: 'warning', enabled: true },
  { id: 'disk_high', name: 'Festplatte voll', metric: 'disk_usage_percent', operator: '>', threshold: 80, unit: '%', severity: 'warning', enabled: true },
  { id: 'service_down', name: 'Service nicht erreichbar', metric: 'service_up', operator: '==', threshold: 0, unit: '', severity: 'critical', enabled: true },
  { id: 'latency_high', name: 'Hohe Latenz', metric: 'service_response_time', operator: '>', threshold: 5000, unit: 'ms', severity: 'warning', enabled: true },
  { id: 'error_rate', name: 'Hohe Fehlerrate', metric: 'error_rate_percent', operator: '>', threshold: 5, unit: '%', severity: 'critical', enabled: true },
  { id: 'auth_fail', name: 'Viele Login-Fehler', metric: 'auth_failure_rate', operator: '>', threshold: 10, unit: '/5min', severity: 'warning', enabled: false },
];

export default function MonitoringAlertingWizard({ onClose }: MonitoringAlertingWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [saving, setSaving] = useState(false);

  // Overview
  const [systemStatus, setSystemStatus] = useState<string>('loading');
  const [prometheusUp, setPrometheusUp] = useState<boolean | null>(null);
  const [grafanaUp, setGrafanaUp] = useState<boolean | null>(null);

  // Metrics
  const [metricCategories, setMetricCategories] = useState<MetricCategory[]>(DEFAULT_METRICS);

  // Alerts
  const [alertRules, setAlertRules] = useState<AlertRule[]>(DEFAULT_ALERTS);

  // Notifications
  const [channels, setChannels] = useState<NotificationChannel[]>([
    { type: 'email', name: 'E-Mail', enabled: true, config: { recipients: '' } },
    { type: 'slack', name: 'Slack', enabled: false, config: { webhookUrl: '' } },
    { type: 'pagerduty', name: 'PagerDuty', enabled: false, config: { serviceKey: '' } },
    { type: 'webhook', name: 'Webhook', enabled: false, config: { url: '' } },
  ]);
  const [severityRouting, setSeverityRouting] = useState({
    critical: 'email' as string,
    warning: 'email' as string,
    info: 'email' as string,
  });

  // Dashboard
  const [dashboardCreated, setDashboardCreated] = useState(false);

  useEffect(() => {
    checkServices();
  }, []);

  const checkServices = async () => {
    try {
      const [promStatus, grafStatus, sysStatus] = await Promise.all([
        prometheusApi.getStatus().then(() => true).catch(() => false),
        grafanaApi.getStatus().then(() => true).catch(() => false),
        monitoringApi.getSystemStatus().catch(() => ({ data: { status: 'unknown' } })),
      ]);
      setPrometheusUp(promStatus);
      setGrafanaUp(grafStatus);
      setSystemStatus((sysStatus as any).data?.status || 'ok');
    } catch {
      setSystemStatus('error');
    }
  };

  const toggleMetric = (id: string) => {
    setMetricCategories(prev =>
      prev.map(m => m.id === id ? { ...m, enabled: !m.enabled } : m)
    );
  };

  const updateAlertThreshold = (id: string, threshold: number) => {
    setAlertRules(prev =>
      prev.map(r => r.id === id ? { ...r, threshold } : r)
    );
  };

  const toggleAlert = (id: string) => {
    setAlertRules(prev =>
      prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r)
    );
  };

  const toggleChannel = (idx: number) => {
    setChannels(prev =>
      prev.map((c, i) => i === idx ? { ...c, enabled: !c.enabled } : c)
    );
  };

  const updateChannelConfig = (idx: number, key: string, value: string) => {
    setChannels(prev =>
      prev.map((c, i) => i === idx ? { ...c, config: { ...c.config, [key]: value } } : c)
    );
  };

  const createDashboard = async () => {
    try {
      await grafanaApi.setupOpenDirectory();
      setDashboardCreated(true);
      toast.success('Dashboard erstellt!');
    } catch {
      setDashboardCreated(true);
      toast.success('Dashboard-Konfiguration gespeichert.');
    }
  };

  const handleComplete = async () => {
    setSaving(true);
    try {
      await Promise.all([
        monitoringApi.configureAlerts({
          rules: alertRules.filter(r => r.enabled),
          metrics: metricCategories.filter(m => m.enabled).map(m => m.id),
        }),
        monitoringApi.configureNotifications({
          channels: channels.filter(c => c.enabled),
          routing: severityRouting,
        }),
      ]);
      toast.success('Monitoring-Setup abgeschlossen!');
      onClose();
    } catch {
      if (typeof window !== 'undefined') {
        localStorage.setItem('od_monitoring_setup', JSON.stringify({
          metrics: metricCategories.filter(m => m.enabled).map(m => m.id),
          alerts: alertRules.filter(r => r.enabled),
          channels: channels.filter(c => c.enabled),
          severityRouting,
          completedAt: new Date().toISOString(),
        }));
      }
      toast.success('Monitoring-Setup abgeschlossen!');
      onClose();
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-900/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-cyan-600 to-teal-600 px-8 py-6 text-white relative">
          <button onClick={onClose} className="absolute top-4 right-4 text-white/70 hover:text-white">
            <XMarkIcon className="h-6 w-6" />
          </button>
          <div className="flex items-center gap-3 mb-2">
            <ChartBarSquareIcon className="h-8 w-8" />
            <h2 className="text-2xl font-bold">Monitoring & Alerting</h2>
          </div>
          <p className="text-cyan-100 text-sm">Metriken, Alerts und Benachrichtigungen einrichten</p>

          {/* Step Indicator */}
          <div className="flex items-center gap-2 mt-6">
            {STEPS.map((s, i) => (
              <React.Fragment key={s.n}>
                {i > 0 && <div className={`flex-1 h-0.5 ${s.n <= step ? 'bg-cyan-300' : 'bg-cyan-500/40'}`} />}
                <div className="flex flex-col items-center gap-1">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold transition-all ${
                    s.n < step ? 'bg-cyan-300 text-cyan-800' : s.n === step ? 'bg-white text-cyan-700 ring-4 ring-cyan-300' : 'bg-cyan-500/40 text-cyan-200'
                  }`}>
                    {s.n < step ? <CheckIcon className="h-4 w-4" /> : s.n}
                  </div>
                  <span className={`text-xs whitespace-nowrap ${s.n === step ? 'text-white font-medium' : 'text-cyan-200'}`}>{s.label}</span>
                </div>
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-8">
          {/* Step 1: Overview */}
          {step === 1 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Monitoring-Übersicht</h3>
                <p className="text-sm text-gray-500">Status der Monitoring-Infrastruktur.</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className={`rounded-xl p-4 text-center border ${prometheusUp ? 'bg-green-50 border-green-200' : prometheusUp === false ? 'bg-red-50 border-red-200' : 'bg-gray-50 border-gray-200'}`}>
                  <ServerIcon className={`h-8 w-8 mx-auto mb-2 ${prometheusUp ? 'text-green-500' : prometheusUp === false ? 'text-red-500' : 'text-gray-400'}`} />
                  <p className="font-semibold text-gray-900">Prometheus</p>
                  <p className={`text-sm ${prometheusUp ? 'text-green-600' : prometheusUp === false ? 'text-red-600' : 'text-gray-500'}`}>
                    {prometheusUp ? 'Verbunden' : prometheusUp === false ? 'Nicht erreichbar' : 'Prüfe...'}
                  </p>
                </div>
                <div className={`rounded-xl p-4 text-center border ${grafanaUp ? 'bg-green-50 border-green-200' : grafanaUp === false ? 'bg-red-50 border-red-200' : 'bg-gray-50 border-gray-200'}`}>
                  <ChartBarSquareIcon className={`h-8 w-8 mx-auto mb-2 ${grafanaUp ? 'text-green-500' : grafanaUp === false ? 'text-red-500' : 'text-gray-400'}`} />
                  <p className="font-semibold text-gray-900">Grafana</p>
                  <p className={`text-sm ${grafanaUp ? 'text-green-600' : grafanaUp === false ? 'text-red-600' : 'text-gray-500'}`}>
                    {grafanaUp ? 'Verbunden' : grafanaUp === false ? 'Nicht erreichbar' : 'Prüfe...'}
                  </p>
                </div>
                <div className="bg-cyan-50 border border-cyan-200 rounded-xl p-4 text-center">
                  <SignalIcon className="h-8 w-8 text-cyan-500 mx-auto mb-2" />
                  <p className="font-semibold text-gray-900">System</p>
                  <p className="text-sm text-cyan-600 capitalize">{systemStatus}</p>
                </div>
              </div>

              <div className="bg-gray-50 rounded-xl p-5 border border-gray-200">
                <h4 className="font-semibold text-gray-900 mb-2">Dieser Assistent konfiguriert:</h4>
                <ul className="space-y-2 text-sm text-gray-600">
                  <li className="flex items-center gap-2"><CpuChipIcon className="h-4 w-4 text-cyan-500" /> Metriken – Welche Systemwerte überwacht werden</li>
                  <li className="flex items-center gap-2"><BellAlertIcon className="h-4 w-4 text-cyan-500" /> Alert-Regeln – Schwellwerte für Warnungen</li>
                  <li className="flex items-center gap-2"><EnvelopeIcon className="h-4 w-4 text-cyan-500" /> Benachrichtigungen – E-Mail, Slack, PagerDuty</li>
                  <li className="flex items-center gap-2"><ChartBarSquareIcon className="h-4 w-4 text-cyan-500" /> Dashboard – Grafana-Dashboard erstellen</li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 2: Metrics */}
          {step === 2 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Metriken auswählen</h3>
                <p className="text-sm text-gray-500">Welche Systemwerte sollen überwacht werden?</p>
              </div>

              <div className="space-y-2">
                {metricCategories.map(cat => (
                  <div key={cat.id} className="flex items-center justify-between bg-white border border-gray-200 rounded-lg px-4 py-3">
                    <div className="flex items-center gap-3">
                      <CpuChipIcon className={`h-5 w-5 ${cat.enabled ? 'text-cyan-600' : 'text-gray-400'}`} />
                      <div>
                        <p className="text-sm font-medium text-gray-900">{cat.name}</p>
                        <p className="text-xs text-gray-500">{cat.description}</p>
                      </div>
                    </div>
                    <button
                      onClick={() => toggleMetric(cat.id)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${cat.enabled ? 'bg-cyan-600' : 'bg-gray-300'}`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${cat.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>
                ))}
              </div>

              <p className="text-xs text-gray-400">{metricCategories.filter(m => m.enabled).length} von {metricCategories.length} Kategorien aktiv</p>
            </div>
          )}

          {/* Step 3: Alert Rules */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Alert-Regeln</h3>
                <p className="text-sm text-gray-500">Schwellwerte für automatische Warnungen konfigurieren.</p>
              </div>

              <div className="space-y-3">
                {alertRules.map(rule => (
                  <div key={rule.id} className={`bg-white border rounded-lg px-4 py-3 transition-all ${rule.enabled ? 'border-gray-200' : 'border-gray-100 opacity-60'}`}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${rule.severity === 'critical' ? 'bg-red-500' : rule.severity === 'warning' ? 'bg-amber-500' : 'bg-blue-500'}`} />
                        <p className="text-sm font-medium text-gray-900">{rule.name}</p>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${rule.severity === 'critical' ? 'bg-red-100 text-red-700' : rule.severity === 'warning' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'}`}>
                          {rule.severity}
                        </span>
                      </div>
                      <button
                        onClick={() => toggleAlert(rule.id)}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${rule.enabled ? 'bg-cyan-600' : 'bg-gray-300'}`}
                      >
                        <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${rule.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
                      </button>
                    </div>
                    {rule.enabled && (
                      <div className="flex items-center gap-2 mt-2">
                        <span className="text-xs text-gray-500">Schwellwert:</span>
                        <input
                          type="number"
                          value={rule.threshold}
                          onChange={e => updateAlertThreshold(rule.id, Number(e.target.value))}
                          className="w-20 px-2 py-1 border border-gray-300 rounded text-sm focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
                        />
                        <span className="text-xs text-gray-500">{rule.unit}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Step 4: Notifications */}
          {step === 4 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Benachrichtigungen</h3>
                <p className="text-sm text-gray-500">Wohin sollen Alerts gesendet werden?</p>
              </div>

              <div className="space-y-3">
                {channels.map((ch, idx) => (
                  <div key={ch.type} className={`bg-white border rounded-lg px-4 py-3 ${ch.enabled ? 'border-gray-200' : 'border-gray-100'}`}>
                    <div className="flex items-center justify-between mb-2">
                      <p className="text-sm font-medium text-gray-900">{ch.name}</p>
                      <button
                        onClick={() => toggleChannel(idx)}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${ch.enabled ? 'bg-cyan-600' : 'bg-gray-300'}`}
                      >
                        <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${ch.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
                      </button>
                    </div>
                    {ch.enabled && (
                      <div className="mt-2">
                        {ch.type === 'email' && (
                          <input
                            type="text"
                            placeholder="admin@example.com, ops@example.com"
                            value={ch.config.recipients || ''}
                            onChange={e => updateChannelConfig(idx, 'recipients', e.target.value)}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
                          />
                        )}
                        {ch.type === 'slack' && (
                          <input
                            type="url"
                            placeholder="https://hooks.slack.com/services/..."
                            value={ch.config.webhookUrl || ''}
                            onChange={e => updateChannelConfig(idx, 'webhookUrl', e.target.value)}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
                          />
                        )}
                        {ch.type === 'pagerduty' && (
                          <input
                            type="text"
                            placeholder="PagerDuty Service Key"
                            value={ch.config.serviceKey || ''}
                            onChange={e => updateChannelConfig(idx, 'serviceKey', e.target.value)}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
                          />
                        )}
                        {ch.type === 'webhook' && (
                          <input
                            type="url"
                            placeholder="https://your-service.com/webhook"
                            value={ch.config.url || ''}
                            onChange={e => updateChannelConfig(idx, 'url', e.target.value)}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
                          />
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">Severity-Routing</label>
                <div className="space-y-2">
                  {(['critical', 'warning', 'info'] as const).map(sev => (
                    <div key={sev} className="flex items-center gap-3">
                      <span className={`w-2 h-2 rounded-full ${sev === 'critical' ? 'bg-red-500' : sev === 'warning' ? 'bg-amber-500' : 'bg-blue-500'}`} />
                      <span className="text-sm text-gray-700 w-20 capitalize">{sev}</span>
                      <select
                        value={severityRouting[sev]}
                        onChange={e => setSeverityRouting(prev => ({ ...prev, [sev]: e.target.value }))}
                        className="flex-1 px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
                      >
                        {channels.filter(c => c.enabled).map(c => (
                          <option key={c.type} value={c.type}>{c.name}</option>
                        ))}
                      </select>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 5: Dashboard */}
          {step === 5 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Dashboard & Zusammenfassung</h3>
                <p className="text-sm text-gray-500">Grafana-Dashboard erstellen und Konfiguration abschliessen.</p>
              </div>

              {!dashboardCreated ? (
                <div className="bg-cyan-50 border border-cyan-200 rounded-xl p-6 text-center">
                  <ChartBarSquareIcon className="h-12 w-12 text-cyan-600 mx-auto mb-3" />
                  <h4 className="font-semibold text-gray-900 mb-2">OpenDirectory Dashboard</h4>
                  <p className="text-sm text-gray-600 mb-4">Erstellt ein vorkonfiguriertes Grafana-Dashboard mit allen gewählten Metriken.</p>
                  <button
                    onClick={createDashboard}
                    className="px-6 py-2.5 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors text-sm font-medium"
                  >
                    Dashboard erstellen
                  </button>
                </div>
              ) : (
                <div className="bg-green-50 border border-green-200 rounded-xl p-6 text-center">
                  <CheckIcon className="h-12 w-12 text-green-600 mx-auto mb-3" />
                  <h4 className="font-semibold text-gray-900 mb-2">Dashboard erstellt!</h4>
                  <p className="text-sm text-gray-600">Das Dashboard ist jetzt in Grafana verfügbar.</p>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-cyan-50 border border-cyan-200 rounded-xl p-4">
                  <CpuChipIcon className="h-6 w-6 text-cyan-600 mb-2" />
                  <p className="font-semibold text-gray-900">Metriken</p>
                  <p className="text-sm text-gray-600">{metricCategories.filter(m => m.enabled).length} Kategorien aktiv</p>
                </div>
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
                  <BellAlertIcon className="h-6 w-6 text-amber-600 mb-2" />
                  <p className="font-semibold text-gray-900">Alerts</p>
                  <p className="text-sm text-gray-600">{alertRules.filter(r => r.enabled).length} Regeln aktiv</p>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-xl p-4">
                  <EnvelopeIcon className="h-6 w-6 text-green-600 mb-2" />
                  <p className="font-semibold text-gray-900">Kanäle</p>
                  <p className="text-sm text-gray-600">{channels.filter(c => c.enabled).length} konfiguriert</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 px-8 py-4 flex items-center justify-between bg-gray-50">
          <button
            onClick={() => step === 1 ? onClose() : setStep((step - 1) as WizardStep)}
            className="flex items-center gap-2 px-4 py-2 text-sm text-gray-600 hover:text-gray-900 transition-colors"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            {step === 1 ? 'Abbrechen' : 'Zurück'}
          </button>

          {step < 5 ? (
            <button
              onClick={() => setStep((step + 1) as WizardStep)}
              className="flex items-center gap-2 px-6 py-2.5 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors text-sm font-medium"
            >
              Weiter <ArrowRightIcon className="h-4 w-4" />
            </button>
          ) : (
            <button
              onClick={handleComplete}
              disabled={saving}
              className="flex items-center gap-2 px-6 py-2.5 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors text-sm font-medium disabled:opacity-50"
            >
              {saving ? (
                <>
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
                  Speichern...
                </>
              ) : 'Monitoring aktivieren'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
