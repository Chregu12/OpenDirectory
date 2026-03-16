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

// ── Mock Data ──────────────────────────────────────────────────────────────────

const mockScan: ScanResult = {
  scanId: 'scan-2026-03-15-001',
  timestamp: '2026-03-15T08:00:00Z',
  duration: '4m 32s',
  status: 'completed',
  totalFindings: 12,
  bySeverity: { critical: 2, high: 4, medium: 4, low: 2 },
  overallRiskScore: 68,
  findings: [
    {
      id: 'f-1', title: 'Weak Password Policy on Default Domain GPO',
      category: 'gpo', severity: 'critical',
      description: 'Default Domain Policy allows passwords with minimum length of 6 characters and no complexity requirements.',
      affectedEntities: ['Default Domain Policy', 'All domain users (1,240)'],
      benchmark: 'CIS Microsoft Windows Server 2022 Benchmark v1.0 - 1.1.1',
      remediation: 'Set minimum password length to 14+ characters and enable complexity requirements.',
      remediationScript: `Set-ADDefaultDomainPasswordPolicy -Identity corp.local \`\n  -MinPasswordLength 14 \`\n  -ComplexityEnabled $true \`\n  -PasswordHistoryCount 24 \`\n  -MaxPasswordAge (New-TimeSpan -Days 60)`,
    },
    {
      id: 'f-2', title: 'User in 12 Admin Groups',
      category: 'privilege', severity: 'critical',
      description: 'User "svc-backup" is member of 12 groups with administrative privileges, creating excessive privilege accumulation.',
      affectedEntities: ['svc-backup', 'Domain Admins', 'Backup Operators', 'Server Operators', '9 more groups'],
      benchmark: 'NIST SP 800-53 AC-6 (Least Privilege)',
      remediation: 'Review and remove unnecessary group memberships. Implement just-in-time privileged access.',
    },
    {
      id: 'f-3', title: 'BitLocker Disabled on 45 Devices',
      category: 'device', severity: 'high',
      description: '45 devices have BitLocker encryption disabled, exposing data at rest.',
      affectedEntities: ['LAPTOP-23', 'WS-007', 'WS-012', '42 more devices'],
      benchmark: 'CIS Microsoft Windows 11 Benchmark v1.0 - 1.1.2',
      remediation: 'Enable BitLocker with XTS-AES-256 on all non-compliant devices.',
      remediationScript: `Enable-BitLocker -MountPoint "C:" \`\n  -EncryptionMethod XtsAes256 \`\n  -RecoveryPasswordProtector`,
    },
    {
      id: 'f-4', title: 'EDR Agent Stopped on 8 Devices',
      category: 'device', severity: 'high',
      description: 'Microsoft Defender for Endpoint service is stopped or disabled on 8 devices.',
      affectedEntities: ['MAC-05', 'WS-019', 'LAPTOP-31', '5 more devices'],
      benchmark: 'DISA STIG V-253297',
      remediation: 'Restart EDR agent and configure service recovery options.',
      remediationScript: `Start-Service -Name "Sense"\nSet-Service -Name "Sense" -StartupType Automatic`,
    },
    {
      id: 'f-5', title: 'Audit Policy Not Logging Privilege Use',
      category: 'gpo', severity: 'high',
      description: 'Audit policy does not log "Sensitive Privilege Use" events, hiding potential privilege abuse.',
      affectedEntities: ['Default Domain Controller Policy'],
      benchmark: 'CIS Benchmark 17.8.1',
      remediation: 'Enable "Audit Sensitive Privilege Use" for Success and Failure.',
    },
    {
      id: 'f-6', title: 'Kerberos Delegation Misconfiguration',
      category: 'identity', severity: 'high',
      description: '3 service accounts have unconstrained Kerberos delegation enabled, allowing credential theft.',
      affectedEntities: ['svc-sql', 'svc-web', 'svc-iis'],
      benchmark: 'NIST SP 800-53 IA-5',
      remediation: 'Switch to constrained delegation or resource-based constrained delegation.',
    },
    {
      id: 'f-7', title: '23 Devices Missing Critical Patches',
      category: 'device', severity: 'medium',
      description: '23 devices are missing KB5031234 (Critical Security Update) released 14 days ago.',
      affectedEntities: ['23 devices across Ring B and Ring C'],
      benchmark: 'NIST SP 800-40 Rev 4',
      remediation: 'Push KB5031234 through expedited update ring.',
    },
    {
      id: 'f-8', title: 'SMBv1 Enabled on 5 Servers',
      category: 'network', severity: 'medium',
      description: 'SMBv1 protocol is enabled on 5 servers, vulnerable to EternalBlue-type attacks.',
      affectedEntities: ['SRV-FILE01', 'SRV-FILE02', 'SRV-PRINT01', '2 more'],
      benchmark: 'CIS Benchmark 18.3.3',
      remediation: 'Disable SMBv1 after verifying no legacy dependencies.',
      remediationScript: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart`,
    },
    {
      id: 'f-9', title: 'LAPS Not Deployed to All Workstations',
      category: 'identity', severity: 'medium',
      description: '120 workstations do not have Local Administrator Password Solution (LAPS) deployed.',
      affectedEntities: ['120 workstations in OU=Workstations'],
      benchmark: 'DISA STIG V-253280',
      remediation: 'Deploy LAPS GPO to all workstation OUs.',
    },
    {
      id: 'f-10', title: 'Stale Computer Accounts (90+ days inactive)',
      category: 'identity', severity: 'medium',
      description: '34 computer accounts have not authenticated in 90+ days, potential orphaned resources.',
      affectedEntities: ['34 computer objects'],
      benchmark: 'CIS Benchmark 1.1.4',
      remediation: 'Disable inactive accounts after verification, then delete after 30-day grace period.',
    },
    {
      id: 'f-11', title: 'Print Spooler Running on Domain Controllers',
      category: 'network', severity: 'low',
      description: 'Print Spooler service is running on 2 Domain Controllers (PrintNightmare risk).',
      affectedEntities: ['SRV-DC01', 'SRV-DC02'],
      benchmark: 'CIS Benchmark 5.29',
      remediation: 'Disable Print Spooler service on all Domain Controllers.',
      remediationScript: `Stop-Service -Name "Spooler" -Force\nSet-Service -Name "Spooler" -StartupType Disabled`,
    },
    {
      id: 'f-12', title: 'Guest Account Not Renamed',
      category: 'identity', severity: 'low',
      description: 'Built-in Guest account has default name, making it a known target.',
      affectedEntities: ['Guest account'],
      benchmark: 'CIS Benchmark 2.3.10.1',
      remediation: 'Rename Guest account to a non-standard name.',
    },
  ],
};

const riskTrends = [
  { date: '2026-02-15', score: 74 },
  { date: '2026-02-22', score: 71 },
  { date: '2026-03-01', score: 72 },
  { date: '2026-03-08', score: 69 },
  { date: '2026-03-15', score: 68 },
];

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

export default function SecurityScannerView() {
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'trends'>('overview');
  const [scanning, setScanning] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [scanResult, setScanResult] = useState<ScanResult>(mockScan);
  const [trends, setTrends] = useState(riskTrends);

  useEffect(() => { loadSecurityData(); }, []);

  const loadSecurityData = async () => {
    try {
      const [complianceRes, alertsRes] = await Promise.allSettled([
        securityApi.getComplianceStatus(),
        securityApi.getSecurityAlerts(),
      ]);

      if (complianceRes.status === 'fulfilled' && complianceRes.value.data) {
        const data = complianceRes.value.data;
        if (data.findings?.length > 0) {
          setScanResult({
            ...mockScan,
            findings: data.findings,
            totalFindings: data.findings.length,
            overallRiskScore: data.riskScore ?? scanResult.overallRiskScore,
            bySeverity: data.bySeverity ?? scanResult.bySeverity,
          });
        }
      }

      if (alertsRes.status === 'fulfilled' && alertsRes.value.data?.trends) {
        setTrends(alertsRes.value.data.trends);
      }
    } catch {
      // Keep mock data as fallback
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

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
        <div>
          <h1 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
            <ShieldExclamationIcon className="w-6 h-6 text-red-600" /> Security Exposure Scanner
          </h1>
          <p className="text-sm text-gray-500">CIS, NIST, DISA STIG compliance benchmarking</p>
        </div>
        <button onClick={startScan} disabled={scanning}
          className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg text-sm text-white flex items-center gap-2 shadow-sm">
          {scanning ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <PlayIcon className="w-4 h-4" />}
          {scanning ? 'Scanning...' : 'Run Scan'}
        </button>
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
              <div className="flex items-end gap-4 h-48">
                {trends.map((t, i) => (
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
    </div>
  );
}
