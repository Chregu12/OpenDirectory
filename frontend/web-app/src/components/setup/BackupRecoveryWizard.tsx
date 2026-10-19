'use client';

import React, { useEffect, useState } from 'react';
import { CloudArrowUpIcon } from '@heroicons/react/24/outline';
import { backupApi, formatError } from '@/lib/api';
import WizardLayout from '@/components/shared/WizardLayout';

interface BackupRecoveryWizardProps {
  onClose: () => void;
}

interface BackupStatus {
  lastBackup?: string | null;
  totalBackups?: number;
  storageUsed?: string;
}

export default function BackupRecoveryWizard({ onClose }: BackupRecoveryWizardProps) {
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  useEffect(() => {
    backupApi.getBackupStatus()
      .then(({ data }) => {
        if (!data || typeof data !== 'object' || Array.isArray(data)
          || data.lastBackup !== undefined && data.lastBackup !== null && (typeof data.lastBackup !== 'string' || !Number.isFinite(Date.parse(data.lastBackup)))
          || data.totalBackups !== undefined && (!Number.isSafeInteger(data.totalBackups) || data.totalBackups < 0)
          || data.storageUsed !== undefined && (typeof data.storageUsed !== 'string' || data.storageUsed.length > 200)) {
          throw new Error('Unbestätigter Backup-Status');
        }
        setStatus(data);
      })
      .catch(error => setStatusError(formatError(error)));
  }, []);

  return (
    <WizardLayout
      title="Backup & Recovery"
      subtitle="Backup-Status und Verfügbarkeit"
      icon={<CloudArrowUpIcon className="h-8 w-8" />}
      color="emerald"
      steps={[{ n: 1, label: 'Status' }]}
      currentStep={1}
      onStepChange={() => {}}
      onClose={onClose}
      onComplete={onClose}
      completeLabel="Schliessen"
    >
      <div className="space-y-6">
        <div role="status" aria-labelledby="backup-setup-unavailable" className="rounded-xl border border-amber-200 bg-amber-50 p-5">
          <h3 id="backup-setup-unavailable" className="font-semibold text-gray-900">Backup-Einrichtung nicht verfügbar (Unsupported)</h3>
          <p className="mt-2 text-sm text-gray-700">
            Die Einrichtung von Backup-Quellen, Zeitplänen und Speicherorten sowie Test-Backups ist in diesem Assistenten nicht implementiert.
            Es steht keine unterstützte, für Ihre Organisation autorisierte Einrichtung zur Verfügung. Backups können hier nicht aktiviert werden.
          </p>
        </div>

        <section aria-label="Backup-Status">
          <h3 className="mb-3 font-semibold text-gray-900">Backup-Übersicht</h3>
          {statusError ? (
            <p role="alert" className="text-sm text-red-700">Backup-Status nicht verfügbar: {statusError}</p>
          ) : status === null ? (
            <p className="text-sm text-gray-600">Backup-Status wird geladen...</p>
          ) : (
            <dl className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div>
                <dt className="text-sm text-gray-600">Letztes Backup</dt>
                <dd>{status.lastBackup ? new Date(status.lastBackup).toLocaleString('de-DE') : 'Unbekannt'}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-600">Backups gesamt</dt>
                <dd>{status.totalBackups ?? 'Unbekannt'}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-600">Speicherverbrauch</dt>
                <dd>{status.storageUsed || 'Unbekannt'}</dd>
              </div>
            </dl>
          )}
        </section>

        <a href="/backup" onClick={onClose} className="text-sm text-emerald-700 underline">Zur Backup-Übersicht</a>
      </div>
    </WizardLayout>
  );
}
