'use client';

import React, { useEffect, useState } from 'react';
import { ChartBarSquareIcon } from '@heroicons/react/24/outline';
import { monitoringApi, prometheusApi, grafanaApi, formatError } from '@/lib/api';
import WizardLayout from '@/components/shared/WizardLayout';

interface MonitoringAlertingWizardProps {
  onClose: () => void;
}

interface ServiceStatus {
  name: string;
  status: string;
  error: string | null;
}

export default function MonitoringAlertingWizard({ onClose }: MonitoringAlertingWizardProps) {
  const [statuses, setStatuses] = useState<ServiceStatus[]>([]);

  useEffect(() => {
    const services = [
      { name: 'Prometheus', read: prometheusApi.getStatus },
      { name: 'Grafana', read: grafanaApi.getStatus },
      { name: 'System', read: monitoringApi.getSystemStatus },
    ];

    Promise.allSettled(services.map(service => service.read())).then(results => {
      setStatuses(results.map((result, index) => ({
        name: services[index].name,
        status: result.status === 'fulfilled' && typeof result.value?.data?.status === 'string' && result.value.data.status.trim()
          ? result.value.data.status.trim()
          : 'Unbekannt',
        error: result.status === 'rejected' ? formatError(result.reason) : null,
      })));
    });
  }, []);

  return (
    <WizardLayout
      title="Monitoring & Alerting"
      subtitle="Monitoring-Status und Verfügbarkeit"
      icon={<ChartBarSquareIcon className="h-8 w-8" />}
      color="cyan"
      steps={[{ n: 1, label: 'Status' }]}
      currentStep={1}
      onStepChange={() => {}}
      onClose={onClose}
      onComplete={onClose}
      completeLabel="Schliessen"
    >
      <div className="space-y-6">
        <div role="status" aria-labelledby="monitoring-setup-unavailable" className="rounded-xl border border-amber-200 bg-amber-50 p-5">
          <h3 id="monitoring-setup-unavailable" className="font-semibold text-gray-900">Monitoring-Einrichtung nicht verfügbar (Unsupported)</h3>
          <p className="mt-2 text-sm text-gray-700">
            Die Einrichtung von Metriken, Alert-Regeln und Benachrichtigungen ist in diesem Assistenten nicht implementiert.
            Es steht keine unterstützte, für Ihre Organisation autorisierte Einrichtung zur Verfügung.
            Monitoring kann hier nicht aktiviert und ein Grafana-Dashboard nicht eingerichtet werden.
          </p>
        </div>

        <section aria-label="Service-Status">
          <h3 className="mb-3 font-semibold text-gray-900">Monitoring-Übersicht</h3>
          {statuses.length === 0 ? (
            <p className="text-sm text-gray-600">Service-Status wird geladen...</p>
          ) : (
            <dl className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              {statuses.map(service => (
                <div key={service.name}>
                  <dt className="text-sm text-gray-600">{service.name}</dt>
                  <dd>
                    {service.error ? (
                      <p role="alert" className="text-sm text-red-700">{service.name}-Status nicht verfügbar: {service.error}</p>
                    ) : service.status}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </section>

        <a href="/monitoring" onClick={onClose} className="text-sm text-cyan-700 underline">Zur Monitoring-Übersicht</a>
      </div>
    </WizardLayout>
  );
}
