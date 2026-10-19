'use client';

import React from 'react';
import { ShieldCheckIcon } from '@heroicons/react/24/outline';
import WizardLayout from '@/components/shared/WizardLayout';

interface SecuritySetupWizardProps {
  onClose: () => void;
}

export default function SecuritySetupWizard({ onClose }: SecuritySetupWizardProps) {
  return <WizardLayout title="Security-Setup" subtitle="Kombinierte Security-Automation nicht verfügbar" color="red"
    icon={<ShieldCheckIcon className="h-8 w-8" />} steps={[{ n: 1, label: 'Nicht verfügbar' }]} currentStep={1}
    onStepChange={() => {}} onClose={onClose} onComplete={onClose} completeLabel="Schliessen">
    <div role="status" className="space-y-4">
      <p>Für diesen Assistenten gibt es keinen angebundenen kombinierten Antivirus-, DLP- und Compliance-Setup-Workflow.</p>
      <p>Es wurden keine Schutzmassnahmen aktiviert, Scans gestartet oder Konfigurationen als erfolgreich gespeichert.</p>
      <p>Fehlende Sicherheitsdaten sind nicht mit null Bedrohungen oder einem erfolgreichen Compliance-Status gleichzusetzen. Eine wirksame Konfiguration erfordert einen unterstützten Provider und eigene serverseitige Berechtigungen.</p>
    </div>
  </WizardLayout>;
}
