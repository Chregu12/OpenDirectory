'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldExclamationIcon,
  ArrowPathIcon,
  PlayIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  WrenchScrewdriverIcon,
  ComputerDesktopIcon,
  KeyIcon,
  DocumentTextIcon,
  ChevronDownIcon,
  ChevronUpIcon
} from '@heroicons/react/24/outline';
import { securityApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';
import SimpleViewLayout from '@/components/shared/SimpleViewLayout';

// ── Types ──────────────────────────────────────────────────────────────────────

interface Finding {
  id: string;
  title: string;
  category: 'gpo' | 'privilege' | 'device' | 'network' | 'identity';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  affectedEntities: string[];
  benchmark: string;
  remediation: string;
  remediationScript?: string;
}

interface ScanResult {
  scanId: string;
  timestamp: string;
  duration: string;
  status: 'completed' | 'running' | 'failed';
  totalFindings: number;
  bySeverity: Record<string, number>;
  overallRiskScore: number;
  findings: Finding[];
}

const emptyScanResult: ScanResult = {
  scanId: '',
  timestamp: new Date().toISOString(),
  duration: '—',
  status: 'completed',
  totalFindings: 0,
  bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
  overallRiskScore: 0,
  findings: [],
};

// ── Helpers ────────────────────────────────────────────────────────────────────

const sevBadge = (s: string) =>
  s === 'critical' ? 'od-badge-critical' :
  s === 'high' ? 'od-badge-high' :
  s === 'medium' ? 'od-badge-medium' :
  'od-badge-low';

const sevDot = (s: string) =>
  s === 'critical' ? 'bg-red-500' :
  s === 'high' ? 'bg-orange-500' :
  s === 'medium' ? 'bg-yellow-500' :
  'bg-blue-500';

const sevText = (s: string) =>
  s === 'critical' ? 'text-red-600' :
  s === 'high' ? 'text-orange-600' :
  s === 'medium' ? 'text-yellow-600' :
  'text-blue-600';

// ── Component ──────────────────────────────────────────────────────────────────

interface SecurityScannerViewProps {
  onOpenWizard?: () => void;
}

export default function SecurityScannerView({ onOpenWizard }: SecurityScannerViewProps) {
  const { isSimple } = useUiMode();
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'trends'>('overview');
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [usingDemoData, setUsingDemoData] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [scanResult, setScanResult] = useState<ScanResult>(emptyScanResult);
  const [trends, setTrends] = useState<{ date: string; score: number }[]>([]);

  useEffect(() => { loadSecurityData(); }, []);

  const loadSecurityData = async () => {
    setLoading(true);
    try {
      const [complianceRes, alertsRes] = await Promise.allSettled([
        securityApi.getComplianceStatus(),
        securityApi.getSecurityAlerts(),
      ]);

      let apiDataFound = false;

      if (complianceRes.status === 'fulfilled' && complianceRes.value.data) {
        const data = complianceRes.value.data;
        if (data.findings?.length > 0) {
          setScanResult({
            ...emptyScanResult,
            findings: data.findings,
            totalFindings: data.findings.length,
            overallRiskScore: data.riskScore ?? 0,
            bySeverity: data.bySeverity ?? emptyScanResult.bySeverity,
          });
          apiDataFound = true;
        }
      }

      if (alertsRes.status === 'fulfilled' && alertsRes.value.data?.trends) {
        setTrends(alertsRes.value.data.trends);
        apiDataFound = true;
      }

      setUsingDemoData(!apiDataFound);
    } catch {
      setUsingDemoData(true);
    } finally {
      setLoading(false);
    }
  };

  const startScan = async () => {
    setScanning(true);
    try {
      await securityApi.getComplianceStatus();
      await loadSecurityData();
    } catch {
      // Scan simulation fallback
      await new Promise(r => setTimeout(r, 2000));
    } finally {
      setScanning(false);
    }
  };

  const filteredFindings = severityFilter === 'all'
    ? scanResult.findings
    : scanResult.findings.filter(f => f.severity === severityFilter);

  const categoryIcons: Record<string, React.ComponentType<any>> = {
    gpo: DocumentTextIcon,
    privilege: KeyIcon,
    device: ComputerDesktopIcon,
    network: ShieldExclamationIcon,
    identity: KeyIcon,
  };

  if (isSimple) {
    const criticalFindings = scanResult.findings.filter(f => f.severity === 'critical');

    return (
      <SimpleViewLayout
        hero={{
          status: scanResult.overallRiskScore > 70 ? 'critical' : scanResult.overallRiskScore > 50 ? 'warning' : 'ok',
          icon: <ShieldExclamationIcon className="w-10 h-10 text-red-600" />,
          title: `Risk Score: ${scanResult.overallRiskScore}`,
          subtitle: `${scanResult.totalFindings} findings from last scan (${new Date(scanResult.timestamp).toLocaleDateString()})`,
        }}
        stats={Object.entries(scanResult.bySeverity).map(([sev, count]) => ({
          value: count as number,
          label: sev.charAt(0).toUpperCase() + sev.slice(1),
          color: sevText(sev),
        }))}
        sections={criticalFindings.length > 0 ? [{
          title: 'Critical Findings Requiring Immediate Action',
          items: criticalFindings.map(f => ({
            key: f.id,
            icon: <XCircleIcon className="w-5 h-5 text-red-500" />,
            title: f.title,
            subtitle: f.description,
          })),
        }] : []}
        actions={[
          { label: scanning ? 'Scanning...' : 'Run Scan', icon: scanning ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <PlayIcon className="w-4 h-4" />, onClick: startScan, disabled: scanning },
          ...(onOpenWizard ? [{ label: 'Security-Assistent', onClick: onOpenWizard, variant: 'secondary' as const }] : []),
        ]}
      />
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Demo data banner */}
      {usingDemoData && (
        <div className="mx-6 mt-4 p-3 bg-yellow-50 border border-yellow-300 rounded-lg flex items-center gap-2 text-yellow-800 text-sm">
          <ExclamationTriangleIcon className="w-4 h-4 text-yellow-500 shrink-0" />
          <span>Demo-Modus: API nicht erreichbar. Gezeigte Daten sind Beispieldaten.</span>
        </div>
      )}
      {/* Loading skeleton */}
      {loading && (
        <div className="flex-1 p-6 space-y-4 animate-pulse">
          <div className="grid grid-cols-5 gap-4">
            {[...Array(5)].map((_, i) => <div key={i} className="h-24 bg-gray-200 rounded-xl" />)}
          </div>
          <div className="h-32 bg-gray-200 rounded-xl" />
          <div className="h-24 bg-gray-200 rounded-xl" />
        </div>
      )}
      {/* Header */}
      {!loading && <>
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
        <div>
          <h1 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
            <ShieldExclamationIcon className="w-6 h-6 text-red-600" /> Security Exposure Scanner
          </h1>
          <p className="text-sm text-gray-500">CIS, NIST, DISA STIG compliance benchmarking</p>
        </div>
        <div className="flex items-center gap-3">
          {onOpenWizard && (
            <button onClick={onOpenWizard} className="px-3 py-1.5 rounded-lg bg-red-50 hover:bg-red-100 text-red-700 text-sm font-medium transition-colors">
              Security-Assistent
            </button>
          )}
          <button onClick={startScan} disabled={scanning}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg text-sm text-white flex items-center gap-2 shadow-sm">
            {scanning ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <PlayIcon className="w-4 h-4" />}
            {scanning ? 'Scanning...' : 'Run Scan'}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-6 pt-3 border-b border-gray-200 bg-gray-50">
        {([['overview', 'Overview'], ['findings', `Findings (${scanResult.totalFindings})`], ['trends', 'Risk Trends']] as const).map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)}
            className={`od-tab ${activeTab === key ? 'od-tab-active' : 'od-tab-inactive'}`}>
            {label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {/* ── Overview ───────────────────────────────────────────────────── */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Risk score + severity cards */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
              <div className="od-card p-5 col-span-1 text-center">
                <div className={`text-5xl font-bold ${scanResult.overallRiskScore > 70 ? 'text-red-600' : scanResult.overallRiskScore > 50 ? 'text-orange-600' : 'text-green-600'}`}>
                  {scanResult.overallRiskScore}
                </div>
                <div className="text-sm text-gray-500 mt-1">Risk Score</div>
                <div className="text-xs text-gray-400 mt-1">Last scan: {new Date(scanResult.timestamp).toLocaleDateString()}</div>
              </div>
              {Object.entries(scanResult.bySeverity).map(([sev, count]) => (
                <div key={sev} className="od-card p-4">
                  <div className={`text-3xl font-bold ${sevText(sev)}`}>
                    {count}
                  </div>
                  <div className="text-sm text-gray-500 capitalize">{sev}</div>
                </div>
              ))}
            </div>

            {/* Category breakdown */}
            <div className="od-card p-4">
              <h3 className="text-sm font-semibold text-gray-600 mb-3">Findings by Category</h3>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                {['gpo', 'privilege', 'device', 'network', 'identity'].map(cat => {
                  const count = scanResult.findings.filter(f => f.category === cat).length;
                  const Icon = categoryIcons[cat];
                  return (
                    <div key={cat} className="flex items-center gap-2 p-2 rounded-lg bg-gray-50">
                      <Icon className="w-5 h-5 text-gray-400" />
                      <div>
                        <div className="text-lg font-bold text-gray-900">{count}</div>
                        <div className="text-xs text-gray-500 capitalize">{cat === 'gpo' ? 'GPO' : cat}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Top critical findings */}
            <div className="od-card p-4 border-red-200">
              <h3 className="text-sm font-semibold text-red-600 mb-3">Critical Findings Requiring Immediate Action</h3>
              {scanResult.findings.filter(f => f.severity === 'critical').length === 0 && (
                <p className="text-sm text-gray-400 text-center py-2">Keine kritischen Findings</p>
              )}
              {scanResult.findings.filter(f => f.severity === 'critical').map(f => (
                <div key={f.id} className="flex items-start gap-3 mb-3 last:mb-0">
                  <XCircleIcon className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-medium text-sm text-gray-900">{f.title}</div>
                    <div className="text-xs text-gray-500">{f.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Findings ───────────────────────────────────────────────────── */}
        {activeTab === 'findings' && (
          <div className="space-y-4">
            {/* Filter */}
            <div className="flex gap-2">
              {['all', 'critical', 'high', 'medium', 'low'].map(s => (
                <button key={s} onClick={() => setSeverityFilter(s)}
                  className={`px-3 py-1 text-xs rounded-lg ${severityFilter === s ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-600 hover:text-gray-900 hover:bg-gray-200'}`}>
                  {s === 'all' ? `All (${scanResult.totalFindings})` : `${s} (${scanResult.bySeverity[s] || 0})`}
                </button>
              ))}
            </div>

            {filteredFindings.length === 0 && (
              <div className="od-card p-8 text-center text-sm text-gray-400">Keine Findings gefunden</div>
            )}
            {filteredFindings.map(f => {
              const expanded = expandedFinding === f.id;
              const Icon = categoryIcons[f.category];
              return (
                <div key={f.id} className="od-card overflow-hidden">
                  <button onClick={() => setExpandedFinding(expanded ? null : f.id)}
                    className="w-full p-4 flex items-start gap-3 text-left hover:bg-gray-50">
                    <span className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${sevDot(f.severity)}`} />
                    <Icon className="w-5 h-5 text-gray-400 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm text-gray-900">{f.title}</div>
                      <div className="text-xs text-gray-500 mt-0.5">{f.benchmark}</div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-xs shrink-0 ${sevBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                    {expanded ? <ChevronUpIcon className="w-4 h-4 text-gray-400 shrink-0" /> : <ChevronDownIcon className="w-4 h-4 text-gray-400 shrink-0" />}
                  </button>
                  {expanded && (
                    <div className="px-4 pb-4 border-t border-gray-100 pt-3 space-y-3">
                      <p className="text-sm text-gray-600">{f.description}</p>
                      <div>
                        <h4 className="text-xs text-gray-500 uppercase mb-1">Affected Entities</h4>
                        <div className="flex flex-wrap gap-1">
                          {f.affectedEntities.map(e => (
                            <span key={e} className="text-xs px-2 py-0.5 bg-gray-100 rounded text-gray-700">{e}</span>
                          ))}
                        </div>
                      </div>
                      <div className="flex items-start gap-2 text-sm text-green-700">
                        <WrenchScrewdriverIcon className="w-4 h-4 mt-0.5 shrink-0" />
                        <span>{f.remediation}</span>
                      </div>
                      {f.remediationScript && (
                        <div>
                          <h4 className="text-xs text-gray-500 uppercase mb-1">Remediation Script</h4>
                          <pre className="p-3 bg-gray-900 rounded-lg text-xs text-green-400 overflow-x-auto font-mono">{f.remediationScript}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* ── Risk Trends ────────────────────────────────────────────────── */}
        {activeTab === 'trends' && (
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-gray-600">Risk Score Over Time</h3>
            <div className="od-card p-4">
              {trends.length === 0 && (
                <div className="h-48 flex items-center justify-center text-sm text-gray-400">Keine Verlaufsdaten verfügbar</div>
              )}
              <div className="flex items-end gap-4 h-48">
                {trends.map((t) => (
                  <div key={t.date} className="flex-1 flex flex-col items-center gap-2">
                    <span className="text-xs text-gray-600">{t.score}</span>
                    <div className="w-full relative" style={{ height: `${t.score * 1.8}px` }}>
                      <div className={`absolute bottom-0 w-full rounded-t ${t.score > 70 ? 'bg-red-500' : t.score > 50 ? 'bg-orange-500' : 'bg-green-500'}`}
                        style={{ height: '100%' }} />
                    </div>
                    <span className="text-xs text-gray-500">{new Date(t.date).toLocaleDateString('de-DE', { month: 'short', day: 'numeric' })}</span>
                  </div>
                ))}
              </div>
              <div className="mt-4 text-sm text-gray-500 text-center">
                Trend: <span className="text-green-600 font-medium">Improving</span> (-6 points in 30 days)
              </div>
            </div>
          </div>
        )}
      </div>
      </>}
    </div>
  );
}
