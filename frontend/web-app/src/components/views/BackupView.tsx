'use client';

import React, { useState, useEffect } from 'react';
import {
  CloudArrowUpIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  CircleStackIcon,
  ServerIcon,
  ShieldCheckIcon,
  FolderIcon,
  PlayIcon,
  WrenchScrewdriverIcon,
} from '@heroicons/react/24/outline';
import { backupApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';
import SimpleViewLayout from '@/components/shared/SimpleViewLayout';
import toast from 'react-hot-toast';

// ── Types ──────────────────────────────────────────────────────────────────────

interface BackupEntry {
  id: string;
  type: 'full' | 'incremental' | 'differential';
  status: 'completed' | 'running' | 'failed' | 'scheduled';
  startedAt: string;
  completedAt?: string;
  size: string;
  sources: string[];
}

interface BackupStatus {
  lastBackup: string | null;
  nextScheduled: string | null;
  totalBackups: number;
  storageUsed: string;
  encryption: boolean;
  storageType: string;
}

// ── Component ──────────────────────────────────────────────────────────────────

interface BackupViewProps {
  onOpenWizard?: () => void;
}

export default function BackupView({ onOpenWizard }: BackupViewProps) {
  const { isSimple } = useUiMode();
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<BackupStatus>({
    lastBackup: null,
    nextScheduled: null,
    totalBackups: 0,
    storageUsed: '–',
    encryption: true,
    storageType: 'local',
  });
  const [backups, setBackups] = useState<BackupEntry[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'history' | 'recovery'>('overview');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [statusRes, backupsRes] = await Promise.all([
        backupApi.getBackupStatus().catch(() => ({ data: {} })),
        backupApi.getBackups().catch(() => ({ data: { backups: [] } })),
      ]);

      setStatus({
        lastBackup: statusRes.data?.lastBackup || null,
        nextScheduled: statusRes.data?.nextScheduled || null,
        totalBackups: statusRes.data?.totalBackups || 0,
        storageUsed: statusRes.data?.storageUsed || '–',
        encryption: statusRes.data?.encryption ?? true,
        storageType: statusRes.data?.storageType || 'local',
      });

      setBackups(backupsRes.data?.backups || backupsRes.data?.data?.backups || []);
    } catch {
      // keep defaults
    } finally {
      setLoading(false);
    }
  };

  const startBackup = async () => {
    try {
      await backupApi.createBackup({ type: 'full', sources: ['config', 'ldap', 'policies', 'certificates'] });
      toast.success('Backup gestartet!');
      loadData();
    } catch {
      toast.error('Backup konnte nicht gestartet werden.');
    }
  };

  const statusIcon = (s: string) => {
    switch (s) {
      case 'completed': return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'running': return <ArrowPathIcon className="h-5 w-5 text-blue-500 animate-spin" />;
      case 'failed': return <XCircleIcon className="h-5 w-5 text-red-500" />;
      default: return <ClockIcon className="h-5 w-5 text-gray-400" />;
    }
  };

  const typeLabel = (t: string) => {
    switch (t) {
      case 'full': return 'Full';
      case 'incremental': return 'Inkrementell';
      case 'differential': return 'Differentiell';
      default: return t;
    }
  };

  // ── Simple Mode ──
  if (isSimple) {
    const lastBackupOk = backups.length > 0 && backups[0]?.status === 'completed';
    const hasRunning = backups.some(b => b.status === 'running');

    return (
      <SimpleViewLayout
        hero={{
          status: hasRunning ? 'warning' : lastBackupOk ? 'ok' : 'warning',
          icon: hasRunning
            ? <ArrowPathIcon className="w-10 h-10 text-blue-600 animate-spin" />
            : lastBackupOk
            ? <CheckCircleIcon className="w-10 h-10 text-green-600" />
            : <ExclamationTriangleIcon className="w-10 h-10 text-yellow-600" />,
          title: hasRunning ? 'Backup Running...' : lastBackupOk ? 'Backups Up to Date' : 'No Recent Backup',
          subtitle: status.lastBackup
            ? `Last backup: ${new Date(status.lastBackup).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })}`
            : 'No backups yet',
        }}
        stats={[
          { value: status.totalBackups, label: 'Total Backups', color: 'text-blue-600' },
          { value: status.storageUsed, label: 'Storage', color: 'text-purple-600' },
          { value: status.encryption ? 'AES-256' : 'Off', label: 'Encryption', color: 'text-amber-600' },
          { value: status.storageType, label: 'Storage Type', color: 'text-gray-600' },
        ]}
        sections={backups.length > 0 ? [{
          title: 'Recent Backups',
          maxItems: 3,
          items: backups.slice(0, 3).map((b, i) => ({
            key: b.id || `backup-${i}`,
            icon: statusIcon(b.status),
            title: `${typeLabel(b.type)} Backup`,
            subtitle: new Date(b.startedAt).toLocaleString('de-DE'),
            trailing: (
              <span className={`text-xs font-medium ${b.status === 'completed' ? 'text-green-600' : b.status === 'failed' ? 'text-red-600' : 'text-blue-600'}`}>
                {b.size}
              </span>
            ),
          })),
        }] : []}
        actions={[
          { label: 'Backup starten', icon: <PlayIcon className="h-4 w-4" />, onClick: startBackup },
          ...(onOpenWizard ? [{ label: 'Setup', icon: <WrenchScrewdriverIcon className="h-4 w-4" />, onClick: onOpenWizard, variant: 'secondary' as const }] : []),
        ]}
      />
    );
  }

  // ── Expert Mode ──
  return (
    <div className="p-6 space-y-6" style={{ background: 'var(--bg-base)', minHeight: '100vh' }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Backup &amp; Recovery</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>Datensicherung und Wiederherstellung verwalten</p>
        </div>
        <div className="flex items-center gap-3">
          {onOpenWizard && (
            <button
              onClick={onOpenWizard}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors"
              style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface)', border: '1px solid var(--border)' }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-surface-raised)')}
              onMouseLeave={(e) => ((e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-surface)')}
            >
              <WrenchScrewdriverIcon className="h-4 w-4" />
              Setup-Assistent
            </button>
          )}
          <button
            onClick={startBackup}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-emerald-600 rounded-lg hover:bg-emerald-700 transition-colors"
          >
            <PlayIcon className="h-4 w-4" />
            Backup starten
          </button>
          <button onClick={loadData} className="p-2 transition-colors" style={{ color: 'var(--text-muted)' }}
            onMouseEnter={(e) => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--text-secondary)')}
            onMouseLeave={(e) => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--text-muted)')}
          >
            <ArrowPathIcon className={`h-5 w-5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'rgba(16,185,129,0.15)' }}>
              <ClockIcon className="h-5 w-5 text-emerald-500" />
            </div>
            <span className="text-sm" style={{ color: 'var(--text-muted)' }}>Letztes Backup</span>
          </div>
          <p className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            {status.lastBackup ? new Date(status.lastBackup).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : 'Noch keins'}
          </p>
        </div>

        <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'rgba(59,130,246,0.15)' }}>
              <CircleStackIcon className="h-5 w-5 text-blue-500" />
            </div>
            <span className="text-sm" style={{ color: 'var(--text-muted)' }}>Backups gesamt</span>
          </div>
          <p className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>{status.totalBackups}</p>
        </div>

        <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'rgba(168,85,247,0.15)' }}>
              <ServerIcon className="h-5 w-5 text-purple-500" />
            </div>
            <span className="text-sm" style={{ color: 'var(--text-muted)' }}>Speicher</span>
          </div>
          <p className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>{status.storageUsed}</p>
          <p className="text-xs mt-1 capitalize" style={{ color: 'var(--text-muted)' }}>{status.storageType}</p>
        </div>

        <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'rgba(245,158,11,0.15)' }}>
              <ShieldCheckIcon className="h-5 w-5 text-amber-500" />
            </div>
            <span className="text-sm" style={{ color: 'var(--text-muted)' }}>Verschlüsselung</span>
          </div>
          <p className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>{status.encryption ? 'AES-256' : 'Aus'}</p>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="flex gap-6">
          {(['overview', 'history', 'recovery'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="pb-3 text-sm font-medium border-b-2 transition-colors"
              style={
                activeTab === tab
                  ? { borderColor: '#10b981', color: '#10b981' }
                  : { borderColor: 'transparent', color: 'var(--text-muted)' }
              }
              onMouseEnter={(e) => { if (activeTab !== tab) (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-secondary)'; }}
              onMouseLeave={(e) => { if (activeTab !== tab) (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-muted)'; }}
            >
              {tab === 'overview' ? 'Übersicht' : tab === 'history' ? 'Verlauf' : 'Wiederherstellung'}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-4">
          {/* Schedule Info */}
          <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
            <h3 className="font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Backup-Zeitplan</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm">
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Nächstes Backup</span>
                <p className="font-medium mt-1" style={{ color: 'var(--text-primary)' }}>
                  {status.nextScheduled ? new Date(status.nextScheduled).toLocaleString('de-DE') : 'Nicht geplant'}
                </p>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Speicherort</span>
                <p className="font-medium mt-1 capitalize" style={{ color: 'var(--text-primary)' }}>{status.storageType}</p>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Verschlüsselung</span>
                <p className="font-medium mt-1" style={{ color: 'var(--text-primary)' }}>{status.encryption ? 'Aktiviert (AES-256)' : 'Deaktiviert'}</p>
              </div>
            </div>
          </div>

          {/* Recent Backups */}
          <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
            <h3 className="font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Letzte Backups</h3>
            {backups.length > 0 ? (
              <div className="space-y-2">
                {backups.slice(0, 5).map((b, i) => (
                  <div key={b.id || i} className="flex items-center justify-between py-2 last:border-0" style={{ borderBottom: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-3">
                      {statusIcon(b.status)}
                      <div>
                        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{typeLabel(b.type)} Backup</p>
                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{new Date(b.startedAt).toLocaleString('de-DE')}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{b.size}</p>
                      <p className={`text-xs ${b.status === 'completed' ? 'text-green-500' : b.status === 'failed' ? 'text-red-500' : 'text-blue-500'}`}>
                        {b.status === 'completed' ? 'Abgeschlossen' : b.status === 'running' ? 'Läuft...' : b.status === 'failed' ? 'Fehlgeschlagen' : 'Geplant'}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <CloudArrowUpIcon className="h-12 w-12 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Noch keine Backups vorhanden.</p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Starten Sie den Setup-Assistenten um Backups zu konfigurieren.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'history' && (
        <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <h3 className="font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Backup-Verlauf</h3>
          {backups.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left" style={{ color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}>
                    <th className="pb-2 font-medium">Status</th>
                    <th className="pb-2 font-medium">Typ</th>
                    <th className="pb-2 font-medium">Gestartet</th>
                    <th className="pb-2 font-medium">Abgeschlossen</th>
                    <th className="pb-2 font-medium">Grösse</th>
                    <th className="pb-2 font-medium">Quellen</th>
                  </tr>
                </thead>
                <tbody>
                  {backups.map((b, i) => (
                    <tr key={b.id || i} className="last:border-0" style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="py-2.5">{statusIcon(b.status)}</td>
                      <td className="py-2.5" style={{ color: 'var(--text-primary)' }}>{typeLabel(b.type)}</td>
                      <td className="py-2.5" style={{ color: 'var(--text-secondary)' }}>{new Date(b.startedAt).toLocaleString('de-DE')}</td>
                      <td className="py-2.5" style={{ color: 'var(--text-secondary)' }}>{b.completedAt ? new Date(b.completedAt).toLocaleString('de-DE') : '–'}</td>
                      <td className="py-2.5" style={{ color: 'var(--text-secondary)' }}>{b.size}</td>
                      <td className="py-2.5" style={{ color: 'var(--text-secondary)' }}>{b.sources?.join(', ') || '–'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-center py-8" style={{ color: 'var(--text-muted)' }}>Keine Einträge vorhanden.</p>
          )}
        </div>
      )}

      {activeTab === 'recovery' && (
        <div className="space-y-4">
          <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
            <h3 className="font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Wiederherstellung</h3>
            <p className="text-sm mb-4" style={{ color: 'var(--text-muted)' }}>Wählen Sie ein Backup zur Wiederherstellung.</p>
            {backups.filter(b => b.status === 'completed').length > 0 ? (
              <div className="space-y-2">
                {backups.filter(b => b.status === 'completed').map((b, i) => (
                  <div key={b.id || i} className="flex items-center justify-between rounded-lg px-4 py-3" style={{ background: 'var(--bg-surface-raised)' }}>
                    <div className="flex items-center gap-3">
                      <FolderIcon className="h-5 w-5 text-emerald-500" />
                      <div>
                        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{typeLabel(b.type)} – {new Date(b.startedAt).toLocaleString('de-DE')}</p>
                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{b.size} · {b.sources?.join(', ')}</p>
                      </div>
                    </div>
                    <button
                      onClick={async () => {
                        try {
                          await backupApi.restoreBackup(b.id);
                          toast.success('Wiederherstellung gestartet!');
                        } catch {
                          toast.error('Wiederherstellung fehlgeschlagen.');
                        }
                      }}
                      className="px-3 py-1.5 text-xs font-medium text-emerald-400 rounded-lg hover:bg-emerald-900/30 transition-colors"
                      style={{ background: 'rgba(16,185,129,0.15)' }}
                    >
                      Wiederherstellen
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-center py-8" style={{ color: 'var(--text-muted)' }}>Keine abgeschlossenen Backups zur Wiederherstellung verfügbar.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
