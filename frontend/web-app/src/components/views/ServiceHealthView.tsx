'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  ArrowPathIcon,
  ShieldCheckIcon,
  ServerIcon,
  ComputerDesktopIcon,
  CpuChipIcon,
  CircleStackIcon,
  KeyIcon,
  DocumentCheckIcon,
  CloudIcon,
  LockClosedIcon,
  ChartBarIcon,
  ClipboardDocumentListIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  WrenchScrewdriverIcon,
  SignalIcon,
  BriefcaseIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

type ServiceStatus = 'operational' | 'degraded' | 'outage';

interface ServiceInfo {
  id: string;
  name: string;
  icon: React.ComponentType<{ className?: string }>;
  status: ServiceStatus;
  uptime: number; // percentage over 30 days
  responseTime: number; // ms
  lastIncident: string | null; // null = no incident
}

interface Incident {
  id: string;
  title: string;
  status: 'resolved' | 'investigating' | 'monitoring';
  severity: 'critical' | 'major' | 'minor';
  affectedServices: string[];
  startTime: string;
  endTime: string | null;
  resolution: string;
}

interface MetricPoint {
  label: string;
  value: number;
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_SERVICES: ServiceInfo[] = [
  { id: 'auth',       name: 'Authentifizierung',      icon: LockClosedIcon,         status: 'operational', uptime: 99.97, responseTime: 12,  lastIncident: null },
  { id: 'api-gw',     name: 'API Gateway',             icon: SignalIcon,             status: 'operational', uptime: 99.92, responseTime: 8,   lastIncident: null },
  { id: 'device-mgmt',name: 'Geräte-Management',       icon: ComputerDesktopIcon,    status: 'operational', uptime: 99.85, responseTime: 24,  lastIncident: 'vor 5 Tagen' },
  { id: 'policy',     name: 'Richtlinien-Engine',      icon: DocumentCheckIcon,      status: 'operational', uptime: 99.99, responseTime: 5,   lastIncident: null },
  { id: 'monitoring', name: 'Monitoring',              icon: ChartBarIcon,           status: 'degraded',    uptime: 98.50, responseTime: 145, lastIncident: 'heute' },
  { id: 'certs',      name: 'Zertifikatsverwaltung',   icon: ShieldCheckIcon,        status: 'operational', uptime: 100.0, responseTime: 18,  lastIncident: null },
  { id: 'ldap',       name: 'LDAP / Verzeichnis',      icon: CircleStackIcon,        status: 'operational', uptime: 99.95, responseTime: 3,   lastIncident: 'vor 12 Tagen' },
  { id: 'mdm',        name: 'MDM Server',              icon: CpuChipIcon,            status: 'operational', uptime: 99.78, responseTime: 31,  lastIncident: 'vor 3 Tagen' },
  { id: 'backup',     name: 'Backup-Dienst',           icon: CloudIcon,              status: 'operational', uptime: 99.60, responseTime: 56,  lastIncident: 'vor 8 Tagen' },
  { id: 'cond-access',name: 'Conditional Access',      icon: KeyIcon,                status: 'operational', uptime: 99.98, responseTime: 10,  lastIncident: null },
  { id: 'licenses',   name: 'Lizenzverwaltung',        icon: BriefcaseIcon,          status: 'operational', uptime: 99.70, responseTime: 44,  lastIncident: 'vor 14 Tagen' },
  { id: 'audit',      name: 'Audit-Dienst',            icon: ClipboardDocumentListIcon, status: 'outage',  uptime: 97.20, responseTime: 0,   lastIncident: 'heute' },
];

const MOCK_INCIDENTS: Incident[] = [
  {
    id: '1',
    title: 'Audit-Dienst nicht erreichbar',
    status: 'investigating',
    severity: 'critical',
    affectedServices: ['Audit-Dienst'],
    startTime: new Date(Date.now() - 2 * 3600000).toISOString(),
    endTime: null,
    resolution: 'Ursache wird untersucht. Daten werden gepuffert.',
  },
  {
    id: '2',
    title: 'Monitoring – erhöhte Antwortzeiten',
    status: 'monitoring',
    severity: 'minor',
    affectedServices: ['Monitoring'],
    startTime: new Date(Date.now() - 5 * 3600000).toISOString(),
    endTime: null,
    resolution: 'Ressourcen wurden erhöht, Situation wird beobachtet.',
  },
  {
    id: '3',
    title: 'MDM Server – kurzzeitige Unterbrechung',
    status: 'resolved',
    severity: 'major',
    affectedServices: ['MDM Server', 'Geräte-Management'],
    startTime: new Date(Date.now() - 3 * 86400000).toISOString(),
    endTime: new Date(Date.now() - 3 * 86400000 + 2700000).toISOString(),
    resolution: 'Datenbankverbindung wurde wiederhergestellt. Kein Datenverlust.',
  },
  {
    id: '4',
    title: 'Backup-Dienst – verzögerte Ausführung',
    status: 'resolved',
    severity: 'minor',
    affectedServices: ['Backup-Dienst'],
    startTime: new Date(Date.now() - 8 * 86400000).toISOString(),
    endTime: new Date(Date.now() - 8 * 86400000 + 7200000).toISOString(),
    resolution: 'Speicherengpass behoben. Alle Backups erfolgreich abgeschlossen.',
  },
];

// 24h response time data (hourly averages in ms)
const MOCK_RESPONSE_TIME: MetricPoint[] = Array.from({ length: 24 }, (_, i) => ({
  label: `${String(i).padStart(2, '0')}:00`,
  value: Math.round(15 + Math.random() * 40 + (i >= 8 && i <= 18 ? 20 : 0)),
}));

// 24h error rate (%)
const MOCK_ERROR_RATE: MetricPoint[] = Array.from({ length: 24 }, (_, i) => ({
  label: `${String(i).padStart(2, '0')}:00`,
  value: parseFloat((Math.random() * 0.8 + (i === 14 ? 1.5 : 0)).toFixed(2)),
}));

// 30-day availability (%)
const MOCK_AVAILABILITY: MetricPoint[] = Array.from({ length: 30 }, (_, i) => ({
  label: `Tag ${i + 1}`,
  value: parseFloat((98.5 + Math.random() * 1.5).toFixed(2)),
}));

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString('de-CH', { dateStyle: 'short', timeStyle: 'short' });
}

function fmtRelative(ts: string) {
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'gerade eben';
  if (m < 60) return `vor ${m} Min.`;
  const h = Math.floor(m / 60);
  if (h < 24) return `vor ${h} Std.`;
  return `vor ${Math.floor(h / 24)} Tagen`;
}

const STATUS_CONFIG: Record<ServiceStatus, { label: string; badge: string; dot: string; icon: React.ComponentType<{ className?: string }>; glow: string }> = {
  operational: {
    label: 'Betriebsbereit',
    badge: 'bg-green-50 text-green-700 border-green-200',
    dot: 'bg-green-500',
    icon: CheckCircleIcon,
    glow: 'shadow-green-100',
  },
  degraded: {
    label: 'Degradiert',
    badge: 'bg-orange-50 text-orange-700 border-orange-200',
    dot: 'bg-orange-400',
    icon: ExclamationTriangleIcon,
    glow: 'shadow-orange-100',
  },
  outage: {
    label: 'Ausgefallen',
    badge: 'bg-red-50 text-red-700 border-red-200',
    dot: 'bg-red-500',
    icon: XCircleIcon,
    glow: 'shadow-red-100',
  },
};

const INCIDENT_SEVERITY: Record<Incident['severity'], string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  major:    'bg-orange-100 text-orange-800 border-orange-200',
  minor:    'bg-yellow-100 text-yellow-800 border-yellow-200',
};

const INCIDENT_STATUS_LABELS: Record<Incident['status'], string> = {
  resolved:      'Behoben',
  investigating: 'Wird untersucht',
  monitoring:    'Wird überwacht',
};

const INCIDENT_STATUS_STYLES: Record<Incident['status'], string> = {
  resolved:      'bg-green-50 text-green-700 border-green-200',
  investigating: 'bg-red-50 text-red-700 border-red-200',
  monitoring:    'bg-yellow-50 text-yellow-700 border-yellow-200',
};

// ─── Sparkline Bar Chart ──────────────────────────────────────────────────────

function SparklineChart({
  data,
  color,
  height = 40,
  showLabels = false,
}: {
  data: MetricPoint[];
  color: string;
  height?: number;
  showLabels?: boolean;
}) {
  const max = Math.max(...data.map(d => d.value), 0.001);
  const subset = data.length > 24 ? data.filter((_, i) => i % 3 === 0) : data;

  return (
    <div className="flex items-end gap-px" style={{ height }}>
      {subset.map((point, i) => {
        const pct = (point.value / max) * 100;
        return (
          <div
            key={i}
            className="relative flex-1 group"
            style={{ height: `${Math.max(pct, 3)}%`, backgroundColor: color, borderRadius: 2, opacity: 0.75 + (pct / 100) * 0.25 }}
            title={`${point.label}: ${point.value}`}
          >
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 bg-gray-800 text-white text-xs px-1.5 py-0.5 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none z-10">
              {point.label}: {point.value}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Service Card ─────────────────────────────────────────────────────────────

function ServiceCard({ service }: { service: ServiceInfo }) {
  const cfg = STATUS_CONFIG[service.status];
  const StatusIcon = cfg.icon;

  return (
    <div className={`bg-white rounded-xl shadow-sm p-4 border border-gray-100 hover:shadow-md transition-shadow`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <div className={`rounded-lg p-2 ${service.status === 'operational' ? 'bg-blue-50' : service.status === 'degraded' ? 'bg-orange-50' : 'bg-red-50'}`}>
            <service.icon className={`w-5 h-5 ${service.status === 'operational' ? 'text-[#0071E3]' : service.status === 'degraded' ? 'text-orange-500' : 'text-red-500'}`} />
          </div>
          <div>
            <p className="text-sm font-semibold text-gray-900 leading-tight">{service.name}</p>
          </div>
        </div>
        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border ${cfg.badge}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot} ${service.status !== 'operational' ? 'animate-pulse' : ''}`} />
          {cfg.label}
        </span>
      </div>

      <div className="grid grid-cols-3 gap-2 text-center">
        <div className="bg-gray-50 rounded-lg p-2">
          <p className="text-xs text-gray-500 mb-0.5">Uptime</p>
          <p className={`text-sm font-bold ${service.uptime >= 99.9 ? 'text-green-600' : service.uptime >= 99 ? 'text-orange-500' : 'text-red-500'}`}>
            {service.uptime.toFixed(2)}%
          </p>
          <p className="text-xs text-gray-400">30 Tage</p>
        </div>
        <div className="bg-gray-50 rounded-lg p-2">
          <p className="text-xs text-gray-500 mb-0.5">Antwortzeit</p>
          <p className={`text-sm font-bold ${service.responseTime === 0 ? 'text-red-500' : service.responseTime < 50 ? 'text-green-600' : service.responseTime < 100 ? 'text-orange-500' : 'text-red-500'}`}>
            {service.responseTime === 0 ? '—' : `${service.responseTime}ms`}
          </p>
        </div>
        <div className="bg-gray-50 rounded-lg p-2">
          <p className="text-xs text-gray-500 mb-0.5">Letzter Vorfall</p>
          <p className="text-xs font-medium text-gray-700 truncate">
            {service.lastIncident ?? 'Kein Vorfall'}
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ServiceHealthView() {
  const [services, setServices] = useState<ServiceInfo[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [incidentsOpen, setIncidentsOpen] = useState(true);
  const [expandedIncident, setExpandedIncident] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [routesRes, servicesRes] = await Promise.allSettled([
        api.get('/api/gateway/routes'),
        api.get('/api/services'),
      ]);

      // Try to map real services if available, otherwise fall back to mock
      if (servicesRes.status === 'fulfilled' && Array.isArray(servicesRes.value.data) && servicesRes.value.data.length > 0) {
        const real = servicesRes.value.data;
        // Map real service data onto mock structure for any that match
        const merged = MOCK_SERVICES.map(mock => {
          const match = real.find((r: any) =>
            r.name?.toLowerCase().includes(mock.id) ||
            r.id?.toLowerCase().includes(mock.id)
          );
          if (match) {
            return {
              ...mock,
              status: match.status === 'healthy' || match.status === 'up' ? 'operational' as ServiceStatus
                    : match.status === 'degraded' ? 'degraded' as ServiceStatus
                    : 'outage' as ServiceStatus,
              responseTime: match.responseTime ?? match.latency ?? mock.responseTime,
            };
          }
          return mock;
        });
        setServices(merged);
      } else {
        setServices(MOCK_SERVICES);
      }

      setIncidents(MOCK_INCIDENTS);
      setLastUpdated(new Date());
    } catch {
      setServices(MOCK_SERVICES);
      setIncidents(MOCK_INCIDENTS);
      setLastUpdated(new Date());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Overall status
  const hasOutage = services.some(s => s.status === 'outage');
  const hasDegraded = services.some(s => s.status === 'degraded');
  const outageCount = services.filter(s => s.status === 'outage').length;
  const degradedCount = services.filter(s => s.status === 'degraded').length;

  const overallStatus = hasOutage ? 'outage' : hasDegraded ? 'degraded' : 'operational';

  const activeIncidents = incidents.filter(i => i.status !== 'resolved');
  const resolvedIncidents = incidents.filter(i => i.status === 'resolved');

  return (
    <div className="min-h-screen bg-[#F2F2F7] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Service Health</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Zuletzt aktualisiert: {lastUpdated.toLocaleTimeString('de-CH')} · Automatische Aktualisierung alle 30s
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white border border-gray-200 hover:bg-gray-50 transition-colors shadow-sm text-sm text-gray-600"
        >
          <ArrowPathIcon className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Aktualisieren
        </button>
      </div>

      {/* Overall Status Banner */}
      <div className={`rounded-xl p-4 mb-6 flex items-center gap-3 ${
        overallStatus === 'operational' ? 'bg-green-50 border border-green-200' :
        overallStatus === 'degraded'    ? 'bg-orange-50 border border-orange-200' :
                                          'bg-red-50 border border-red-200'
      }`}>
        {overallStatus === 'operational' ? (
          <CheckCircleIcon className="w-6 h-6 text-green-600 shrink-0" />
        ) : overallStatus === 'degraded' ? (
          <ExclamationTriangleIcon className="w-6 h-6 text-orange-500 shrink-0" />
        ) : (
          <XCircleIcon className="w-6 h-6 text-red-500 shrink-0" />
        )}
        <div>
          <p className={`font-semibold ${
            overallStatus === 'operational' ? 'text-green-800' :
            overallStatus === 'degraded'    ? 'text-orange-800' :
                                              'text-red-800'
          }`}>
            {overallStatus === 'operational'
              ? 'Alle Systeme betriebsbereit'
              : `${outageCount + degradedCount} Störung${outageCount + degradedCount !== 1 ? 'en' : ''} erkannt`}
          </p>
          {overallStatus !== 'operational' && (
            <p className={`text-sm mt-0.5 ${overallStatus === 'degraded' ? 'text-orange-700' : 'text-red-700'}`}>
              {outageCount > 0 && `${outageCount} Dienst${outageCount !== 1 ? 'e' : ''} ausgefallen`}
              {outageCount > 0 && degradedCount > 0 && ', '}
              {degradedCount > 0 && `${degradedCount} Dienst${degradedCount !== 1 ? 'e' : ''} degradiert`}
            </p>
          )}
        </div>
      </div>

      {/* Service Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        {services.map(service => (
          <ServiceCard key={service.id} service={service} />
        ))}
        {loading && services.length === 0 && Array.from({ length: 12 }).map((_, i) => (
          <div key={i} className="bg-white rounded-xl shadow-sm p-4 border border-gray-100 animate-pulse">
            <div className="flex items-center gap-2.5 mb-3">
              <div className="w-9 h-9 bg-gray-200 rounded-lg" />
              <div className="h-4 bg-gray-200 rounded w-32" />
            </div>
            <div className="grid grid-cols-3 gap-2">
              {[0, 1, 2].map(j => <div key={j} className="h-12 bg-gray-100 rounded-lg" />)}
            </div>
          </div>
        ))}
      </div>

      {/* Active Incidents */}
      {activeIncidents.length > 0 && (
        <div className="bg-white rounded-xl shadow-sm border border-red-100 mb-4 overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-red-100 bg-red-50">
            <div className="flex items-center gap-2">
              <ExclamationTriangleIcon className="w-5 h-5 text-red-500" />
              <h2 className="font-semibold text-red-800 text-sm">Aktive Störungen ({activeIncidents.length})</h2>
            </div>
          </div>
          <div className="divide-y divide-gray-50">
            {activeIncidents.map(incident => (
              <div key={incident.id} className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${INCIDENT_STATUS_STYLES[incident.status]}`}>
                        {INCIDENT_STATUS_LABELS[incident.status]}
                      </span>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${INCIDENT_SEVERITY[incident.severity]}`}>
                        {incident.severity === 'critical' ? 'Kritisch' : incident.severity === 'major' ? 'Schwerwiegend' : 'Geringfügig'}
                      </span>
                    </div>
                    <p className="font-medium text-gray-900 text-sm">{incident.title}</p>
                    <p className="text-xs text-gray-500 mt-0.5">{incident.resolution}</p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {incident.affectedServices.map((s, i) => (
                        <span key={i} className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full">{s}</span>
                      ))}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-xs text-gray-500">Seit {fmtRelative(incident.startTime)}</p>
                    <p className="text-xs text-gray-400">{fmtTime(incident.startTime)}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Incident History */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 mb-6 overflow-hidden">
        <button
          onClick={() => setIncidentsOpen(o => !o)}
          className="w-full flex items-center justify-between px-5 py-3.5 border-b border-gray-100 hover:bg-gray-50 transition-colors"
        >
          <div className="flex items-center gap-2">
            <ClipboardDocumentListIcon className="w-5 h-5 text-gray-500" />
            <h2 className="font-semibold text-gray-800 text-sm">Vorfallshistorie</h2>
            <span className="bg-gray-100 text-gray-600 text-xs px-2 py-0.5 rounded-full">{resolvedIncidents.length} behoben</span>
          </div>
          {incidentsOpen ? (
            <ChevronDownIcon className="w-4 h-4 text-gray-400" />
          ) : (
            <ChevronRightIcon className="w-4 h-4 text-gray-400" />
          )}
        </button>

        {incidentsOpen && (
          <div className="divide-y divide-gray-50">
            {resolvedIncidents.length === 0 ? (
              <p className="text-center py-8 text-sm text-gray-400">Keine behobenen Vorfälle</p>
            ) : (
              resolvedIncidents.map(incident => (
                <div key={incident.id} className="p-4">
                  <button
                    onClick={() => setExpandedIncident(expandedIncident === incident.id ? null : incident.id)}
                    className="w-full text-left"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3 flex-1 min-w-0">
                        <CheckCircleIcon className="w-4 h-4 text-green-500 mt-0.5 shrink-0" />
                        <div>
                          <p className="text-sm font-medium text-gray-800">{incident.title}</p>
                          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                            <span className={`inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium border ${INCIDENT_SEVERITY[incident.severity]}`}>
                              {incident.severity === 'critical' ? 'Kritisch' : incident.severity === 'major' ? 'Schwerwiegend' : 'Geringfügig'}
                            </span>
                            <span className="text-xs text-gray-400">
                              {fmtTime(incident.startTime)}
                              {incident.endTime && ` – ${fmtTime(incident.endTime)}`}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`text-xs px-2 py-0.5 rounded-full border ${INCIDENT_STATUS_STYLES['resolved']}`}>
                          {INCIDENT_STATUS_LABELS['resolved']}
                        </span>
                        {expandedIncident === incident.id ? (
                          <ChevronDownIcon className="w-4 h-4 text-gray-400" />
                        ) : (
                          <ChevronRightIcon className="w-4 h-4 text-gray-400" />
                        )}
                      </div>
                    </div>
                  </button>

                  {expandedIncident === incident.id && (
                    <div className="mt-3 ml-7 pl-3 border-l-2 border-gray-100">
                      <p className="text-xs text-gray-600 mb-2">{incident.resolution}</p>
                      <div className="flex flex-wrap gap-1">
                        <span className="text-xs text-gray-400">Betroffene Dienste:</span>
                        {incident.affectedServices.map((s, i) => (
                          <span key={i} className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full">{s}</span>
                        ))}
                      </div>
                      {incident.endTime && (
                        <p className="text-xs text-gray-400 mt-1">
                          Dauer: {Math.round((new Date(incident.endTime).getTime() - new Date(incident.startTime).getTime()) / 60000)} Min.
                        </p>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* Metrics Section */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Avg Response Time */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-gray-800">Ø Antwortzeit</h3>
              <p className="text-xs text-gray-400">Letzte 24 Stunden</p>
            </div>
            <div className="text-right">
              <p className="text-lg font-bold text-gray-900">
                {Math.round(MOCK_RESPONSE_TIME.reduce((a, b) => a + b.value, 0) / MOCK_RESPONSE_TIME.length)}ms
              </p>
              <p className="text-xs text-green-600">Normal</p>
            </div>
          </div>
          <SparklineChart data={MOCK_RESPONSE_TIME} color="#0071E3" height={48} />
          <div className="flex justify-between text-xs text-gray-400 mt-1">
            <span>00:00</span>
            <span>12:00</span>
            <span>23:00</span>
          </div>
        </div>

        {/* Error Rate */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-gray-800">Fehlerrate</h3>
              <p className="text-xs text-gray-400">Letzte 24 Stunden</p>
            </div>
            <div className="text-right">
              <p className="text-lg font-bold text-gray-900">
                {(MOCK_ERROR_RATE.reduce((a, b) => a + b.value, 0) / MOCK_ERROR_RATE.length).toFixed(2)}%
              </p>
              <p className="text-xs text-green-600">Normal</p>
            </div>
          </div>
          <SparklineChart data={MOCK_ERROR_RATE} color="#ef4444" height={48} />
          <div className="flex justify-between text-xs text-gray-400 mt-1">
            <span>00:00</span>
            <span>12:00</span>
            <span>23:00</span>
          </div>
        </div>

        {/* 30-day Availability */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-gray-800">Verfügbarkeit</h3>
              <p className="text-xs text-gray-400">Letzte 30 Tage</p>
            </div>
            <div className="text-right">
              <p className="text-lg font-bold text-gray-900">
                {(MOCK_AVAILABILITY.reduce((a, b) => a + b.value, 0) / MOCK_AVAILABILITY.length).toFixed(2)}%
              </p>
              <p className="text-xs text-green-600">Sehr gut</p>
            </div>
          </div>
          <SparklineChart data={MOCK_AVAILABILITY} color="#10b981" height={48} />
          <div className="flex justify-between text-xs text-gray-400 mt-1">
            <span>Tag 1</span>
            <span>Tag 15</span>
            <span>Tag 30</span>
          </div>
        </div>
      </div>
    </div>
  );
}
