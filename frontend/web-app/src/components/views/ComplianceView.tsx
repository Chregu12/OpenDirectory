'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ClipboardDocumentCheckIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  ComputerDesktopIcon,
  ChartBarIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  MinusIcon,
  FunnelIcon,
  DocumentArrowDownIcon,
  XMarkIcon,
  ClockIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import { complianceApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';
import SimpleViewLayout from '@/components/shared/SimpleViewLayout';

// ── Types ──────────────────────────────────────────────────────────────────────

interface BaselineStatus {
  id: string;
  name: string;
  devicesCovered: number;
  passRate: number;
  trend: 'up' | 'down' | 'stable';
}

interface DeviceCompliance {
  deviceId: string;
  deviceName: string;
  platform: string;
  score: number;
  lastScan: string;
  status: 'compliant' | 'non_compliant' | 'pending';
}

interface ViolationGroup {
  severity: 'critical' | 'high' | 'medium' | 'low';
  count: number;
  items: { checkId: string; title: string; affectedDevices: number }[];
}

interface Waiver {
  id: string;
  checkId: string;
  checkTitle: string;
  deviceId?: string;
  reason: string;
  approvedBy?: string;
  expiresAt: string;
  status: 'active' | 'expired' | 'revoked';
}

interface TrendPoint {
  date: string;
  score: number;
}

// ── Component ──────────────────────────────────────────────────────────────────

interface ComplianceViewProps {
  onOpenWizard?: () => void;
}

export default function ComplianceView({ onOpenWizard }: ComplianceViewProps) {
  const { isSimple } = useUiMode();
  const [loading, setLoading] = useState(true);
  const [fleetScore, setFleetScore] = useState(0);
  const [baselines, setBaselines] = useState<BaselineStatus[]>([]);
  const [devices, setDevices] = useState<DeviceCompliance[]>([]);
  const [violations, setViolations] = useState<ViolationGroup[]>([]);
  const [waivers, setWaivers] = useState<Waiver[]>([]);
  const [trendData, setTrendData] = useState<TrendPoint[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'devices' | 'violations' | 'waivers'>('overview');

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [statusRes, baselinesRes, waiversRes] = await Promise.all([
        complianceApi.getStatus().catch(() => null),
        complianceApi.getBaselines().catch(() => null),
        complianceApi.getWaivers().catch(() => null),
      ]);

      if (statusRes?.data) {
        setFleetScore(statusRes.data.fleetScore || 0);
        setDevices(statusRes.data.devices || []);
        setViolations(statusRes.data.violations || []);
        setTrendData(statusRes.data.trend || []);
      } else {
        loadDemoData();
      }
      if (baselinesRes?.data) setBaselines(baselinesRes.data.baselines || baselinesRes.data || []);
      if (waiversRes?.data) setWaivers(waiversRes.data.waivers || waiversRes.data || []);
    } catch {
      loadDemoData();
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDemoData = () => {
    setFleetScore(87.3);
    setBaselines([
      { id: '1', name: 'CIS Windows 11 L1', devicesCovered: 45, passRate: 91.2, trend: 'up' },
      { id: '2', name: 'CIS macOS Ventura L1', devicesCovered: 28, passRate: 88.5, trend: 'stable' },
      { id: '3', name: 'CIS Ubuntu 22.04 L1', devicesCovered: 12, passRate: 79.1, trend: 'down' },
      { id: '4', name: 'Company Security Baseline', devicesCovered: 85, passRate: 93.4, trend: 'up' },
    ]);
    setDevices([
      { deviceId: 'd1', deviceName: 'DESKTOP-A1B2C3', platform: 'windows', score: 95, lastScan: new Date(Date.now() - 3600000).toISOString(), status: 'compliant' },
      { deviceId: 'd2', deviceName: 'MacBook-Pro-Jane', platform: 'macos', score: 88, lastScan: new Date(Date.now() - 7200000).toISOString(), status: 'compliant' },
      { deviceId: 'd3', deviceName: 'ubuntu-dev-01', platform: 'linux', score: 62, lastScan: new Date(Date.now() - 14400000).toISOString(), status: 'non_compliant' },
      { deviceId: 'd4', deviceName: 'LAPTOP-XYZ789', platform: 'windows', score: 78, lastScan: new Date(Date.now() - 10800000).toISOString(), status: 'non_compliant' },
      { deviceId: 'd5', deviceName: 'MacBook-Air-Bob', platform: 'macos', score: 91, lastScan: new Date(Date.now() - 1800000).toISOString(), status: 'compliant' },
    ]);
    setViolations([
      { severity: 'critical', count: 3, items: [{ checkId: 'c1', title: 'BitLocker not enabled', affectedDevices: 2 }, { checkId: 'c2', title: 'Firewall disabled', affectedDevices: 1 }] },
      { severity: 'high', count: 8, items: [{ checkId: 'h1', title: 'Screen lock timeout > 5 min', affectedDevices: 5 }, { checkId: 'h2', title: 'Antivirus definitions outdated', affectedDevices: 3 }] },
      { severity: 'medium', count: 15, items: [{ checkId: 'm1', title: 'Auto-update disabled', affectedDevices: 8 }, { checkId: 'm2', title: 'USB storage not restricted', affectedDevices: 7 }] },
      { severity: 'low', count: 22, items: [{ checkId: 'l1', title: 'Telemetry not configured', affectedDevices: 12 }, { checkId: 'l2', title: 'Power settings non-standard', affectedDevices: 10 }] },
    ]);
    setWaivers([
      { id: 'w1', checkId: 'c1', checkTitle: 'BitLocker not enabled', deviceId: 'd3', reason: 'Linux device - uses LUKS instead', approvedBy: 'admin', expiresAt: new Date(Date.now() + 86400000 * 90).toISOString(), status: 'active' },
    ]);
    const trend: TrendPoint[] = [];
    for (let i = 29; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000);
      trend.push({ date: d.toISOString().split('T')[0], score: 80 + Math.random() * 15 });
    }
    setTrendData(trend);
  };

  useEffect(() => { loadData(); }, [loadData]);

  const handleTriggerScan = async (deviceId: string) => {
    try {
      await complianceApi.triggerScan(deviceId);
      toast.success('Compliance scan triggered');
    } catch {
      toast.error('Failed to trigger scan');
    }
  };

  const handleRevokeWaiver = async (waiverId: string) => {
    try {
      await complianceApi.deleteWaiver(waiverId);
      setWaivers(prev => prev.filter(w => w.id !== waiverId));
      toast.success('Waiver revoked');
    } catch {
      toast.error('Failed to revoke waiver');
    }
  };

  const handleExportReport = async () => {
    try {
      await complianceApi.generateReport({ format: 'csv' });
      toast.success('Report generation started');
    } catch {
      toast.error('Failed to generate report');
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-600';
    if (score >= 70) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getScoreBg = (score: number) => {
    if (score >= 90) return 'bg-green-500';
    if (score >= 70) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800';
      case 'high': return 'bg-orange-100 text-orange-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      case 'low': return 'bg-blue-100 text-blue-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return <ArrowTrendingUpIcon className="w-4 h-4 text-green-500" />;
      case 'down': return <ArrowTrendingDownIcon className="w-4 h-4 text-red-500" />;
      default: return <MinusIcon className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'compliant': return <span className="inline-flex items-center gap-1 text-xs font-medium text-green-700 bg-green-100 px-2 py-0.5 rounded-full"><CheckCircleIcon className="w-3 h-3" />Compliant</span>;
      case 'non_compliant': return <span className="inline-flex items-center gap-1 text-xs font-medium text-red-700 bg-red-100 px-2 py-0.5 rounded-full"><XCircleIcon className="w-3 h-3" />Non-Compliant</span>;
      default: return <span className="inline-flex items-center gap-1 text-xs font-medium text-gray-700 bg-gray-100 px-2 py-0.5 rounded-full"><ClockIcon className="w-3 h-3" />Pending</span>;
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-96"><ArrowPathIcon className="w-8 h-8 animate-spin text-blue-500" /></div>;
  }

  // ── Simple Mode ──
  if (isSimple) {
    const totalViolations = violations.reduce((s, v) => s + v.count, 0);
    const criticalCount = violations.find(v => v.severity === 'critical')?.count || 0;
    const compliantDevices = devices.filter(d => d.status === 'compliant').length;
    const scoreOk = fleetScore >= 80;

    return (
      <SimpleViewLayout
        hero={{
          status: scoreOk ? 'ok' : criticalCount > 0 ? 'critical' : 'warning',
          icon: (
            <div className="relative w-10 h-10">
              <svg className="w-10 h-10 transform -rotate-90" viewBox="0 0 36 36">
                <path className="text-gray-200" stroke="currentColor" strokeWidth="3" fill="none" d="M18 2.0845a 15.9155 15.9155 0 0 1 0 31.831a 15.9155 15.9155 0 0 1 0 -31.831" />
                <path className={scoreOk ? 'text-green-500' : 'text-red-500'} stroke="currentColor" strokeWidth="3" strokeDasharray={`${fleetScore}, 100`} strokeLinecap="round" fill="none" d="M18 2.0845a 15.9155 15.9155 0 0 1 0 31.831a 15.9155 15.9155 0 0 1 0 -31.831" />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className={`text-xs font-bold ${scoreOk ? 'text-green-700' : 'text-red-700'}`}>{fleetScore.toFixed(0)}%</span>
              </div>
            </div>
          ),
          title: scoreOk ? 'Fleet Compliant' : 'Attention Required',
          subtitle: `${compliantDevices} of ${devices.length} devices compliant`,
        }}
        stats={[
          { value: devices.length, label: 'Devices', color: 'text-blue-600' },
          { value: baselines.length, label: 'Baselines', color: 'text-green-600' },
          { value: totalViolations, label: 'Violations', color: criticalCount > 0 ? 'text-red-600' : 'text-gray-600' },
          { value: waivers.filter(w => w.status === 'active').length, label: 'Waivers', color: 'text-amber-600' },
        ]}
        sections={criticalCount > 0 ? [{
          title: 'Critical Violations',
          items: violations
            .filter(v => v.severity === 'critical')
            .flatMap(v => v.items)
            .map(item => ({
              key: item.checkId,
              icon: <XCircleIcon className="w-5 h-5 text-red-500" />,
              title: item.title,
              trailing: (
                <span className="text-xs text-red-600">{item.affectedDevices} device{item.affectedDevices !== 1 ? 's' : ''}</span>
              ),
            })),
        }] : []}
      >
        {/* Trend */}
        {trendData.length > 0 && (
          <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
            <h3 className="text-sm font-semibold text-gray-700 mb-3">30-Day Trend</h3>
            <div className="flex items-end gap-0.5 h-16">
              {trendData.map((point, i) => (
                <div key={i} className="flex-1 group relative">
                  <div className={`w-full rounded-t ${getScoreBg(point.score)} opacity-70`} style={{ height: `${(point.score / 100) * 64}px` }} />
                </div>
              ))}
            </div>
          </div>
        )}
      </SimpleViewLayout>
    );
  }

  // ── Expert Mode ──
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Compliance</h1>
          <p className="text-sm text-gray-500 mt-1">Monitor device compliance across your fleet</p>
        </div>
        <div className="flex items-center gap-3">
          {onOpenWizard && (
            <button onClick={onOpenWizard} className="px-3 py-1.5 rounded-lg bg-red-50 hover:bg-red-100 text-red-700 text-sm font-medium transition-colors">
              Security-Assistent
            </button>
          )}
          <button onClick={handleExportReport} className="flex items-center gap-2 px-3 py-2 text-gray-600 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 text-sm">
            <DocumentArrowDownIcon className="w-4 h-4" /> Export
          </button>
          <button onClick={loadData} className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100">
            <ArrowPathIcon className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Fleet Score + Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-1 bg-white rounded-xl border border-gray-200 p-6 flex flex-col items-center justify-center">
          <p className="text-xs font-semibold text-gray-500 uppercase mb-2">Fleet Score</p>
          <div className="relative w-32 h-32">
            <svg className="w-32 h-32 transform -rotate-90" viewBox="0 0 36 36">
              <path className="text-gray-200" stroke="currentColor" strokeWidth="3" fill="none" d="M18 2.0845a 15.9155 15.9155 0 0 1 0 31.831a 15.9155 15.9155 0 0 1 0 -31.831" />
              <path className={getScoreBg(fleetScore).replace('bg-', 'text-')} stroke="currentColor" strokeWidth="3" strokeDasharray={`${fleetScore}, 100`} strokeLinecap="round" fill="none" d="M18 2.0845a 15.9155 15.9155 0 0 1 0 31.831a 15.9155 15.9155 0 0 1 0 -31.831" />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className={`text-3xl font-bold ${getScoreColor(fleetScore)}`}>{fleetScore.toFixed(0)}%</span>
            </div>
          </div>
        </div>
        <div className="lg:col-span-3 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-white rounded-xl border border-gray-200 p-4">
            <div className="flex items-center gap-2 mb-1">
              <ComputerDesktopIcon className="w-5 h-5 text-blue-500" />
              <span className="text-sm font-medium text-gray-600">Total Devices</span>
            </div>
            <p className="text-2xl font-bold text-gray-900">{devices.length}</p>
            <p className="text-xs text-green-600 mt-1">{devices.filter(d => d.status === 'compliant').length} compliant</p>
          </div>
          <div className="bg-white rounded-xl border border-gray-200 p-4">
            <div className="flex items-center gap-2 mb-1">
              <ExclamationTriangleIcon className="w-5 h-5 text-red-500" />
              <span className="text-sm font-medium text-gray-600">Violations</span>
            </div>
            <p className="text-2xl font-bold text-gray-900">{violations.reduce((s, v) => s + v.count, 0)}</p>
            <p className="text-xs text-red-600 mt-1">{violations.find(v => v.severity === 'critical')?.count || 0} critical</p>
          </div>
          <div className="bg-white rounded-xl border border-gray-200 p-4">
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheckIcon className="w-5 h-5 text-green-500" />
              <span className="text-sm font-medium text-gray-600">Baselines</span>
            </div>
            <p className="text-2xl font-bold text-gray-900">{baselines.length}</p>
            <p className="text-xs text-gray-500 mt-1">{waivers.filter(w => w.status === 'active').length} active waivers</p>
          </div>
        </div>
      </div>

      {/* Trend Chart (simple ASCII-style bar chart) */}
      {trendData.length > 0 && (
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">Compliance Trend (30 days)</h3>
          <div className="flex items-end gap-1 h-24">
            {trendData.map((point, i) => (
              <div key={i} className="flex-1 flex flex-col items-center group relative">
                <div className="absolute -top-6 hidden group-hover:block bg-gray-800 text-white text-xs px-2 py-1 rounded whitespace-nowrap z-10">
                  {point.date}: {point.score.toFixed(1)}%
                </div>
                <div className={`w-full rounded-t ${getScoreBg(point.score)} opacity-80`} style={{ height: `${(point.score / 100) * 96}px` }} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-4 border-b border-gray-200">
        {(['overview', 'devices', 'violations', 'waivers'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`pb-3 text-sm font-medium border-b-2 transition-colors capitalize ${
              activeTab === tab ? 'border-blue-600 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Baseline</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Devices</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Pass Rate</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Trend</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {baselines.map(b => (
                <tr key={b.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-sm font-medium text-gray-900">{b.name}</td>
                  <td className="px-6 py-4 text-sm text-gray-600">{b.devicesCovered}</td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-24 bg-gray-200 rounded-full h-2">
                        <div className={`h-2 rounded-full ${getScoreBg(b.passRate)}`} style={{ width: `${b.passRate}%` }} />
                      </div>
                      <span className={`text-sm font-medium ${getScoreColor(b.passRate)}`}>{b.passRate}%</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">{getTrendIcon(b.trend)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'devices' && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Device</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Platform</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Score</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Scan</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {devices.map(d => (
                <tr key={d.deviceId} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-sm font-medium text-gray-900">{d.deviceName}</td>
                  <td className="px-6 py-4 text-sm text-gray-600 capitalize">{d.platform}</td>
                  <td className="px-6 py-4">
                    <span className={`text-sm font-bold ${getScoreColor(d.score)}`}>{d.score}%</span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500">{new Date(d.lastScan).toLocaleString()}</td>
                  <td className="px-6 py-4">{getStatusBadge(d.status)}</td>
                  <td className="px-6 py-4">
                    <button onClick={() => handleTriggerScan(d.deviceId)} className="text-blue-600 hover:text-blue-800 text-sm font-medium">Scan</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'violations' && (
        <div className="space-y-4">
          {violations.map(group => (
            <div key={group.severity} className="bg-white rounded-xl border border-gray-200 overflow-hidden">
              <div className="px-6 py-3 bg-gray-50 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${getSeverityColor(group.severity)} capitalize`}>{group.severity}</span>
                  <span className="text-sm text-gray-600">{group.count} violation{group.count !== 1 ? 's' : ''}</span>
                </div>
              </div>
              <div className="divide-y divide-gray-100">
                {group.items.map(item => (
                  <div key={item.checkId} className="px-6 py-3 flex items-center justify-between">
                    <span className="text-sm text-gray-900">{item.title}</span>
                    <span className="text-xs text-gray-500">{item.affectedDevices} device{item.affectedDevices !== 1 ? 's' : ''}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'waivers' && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          {waivers.length === 0 ? (
            <div className="p-8 text-center text-gray-500">No active waivers</div>
          ) : (
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Check</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reason</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Approved By</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Expires</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {waivers.map(w => (
                  <tr key={w.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm font-medium text-gray-900">{w.checkTitle}</td>
                    <td className="px-6 py-4 text-sm text-gray-600">{w.reason}</td>
                    <td className="px-6 py-4 text-sm text-gray-600">{w.approvedBy || '-'}</td>
                    <td className="px-6 py-4 text-sm text-gray-500">{new Date(w.expiresAt).toLocaleDateString()}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${w.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'}`}>{w.status}</span>
                    </td>
                    <td className="px-6 py-4">
                      {w.status === 'active' && (
                        <button onClick={() => handleRevokeWaiver(w.id)} className="text-red-600 hover:text-red-800 text-sm font-medium">Revoke</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
