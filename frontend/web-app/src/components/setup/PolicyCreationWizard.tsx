'use client';

import React from 'react';
import { DocumentCheckIcon } from '@heroicons/react/24/outline';
import WizardLayout from '@/components/shared/WizardLayout';

interface PolicyCreationWizardProps {
  onClose: () => void;
}

export default function PolicyCreationWizard({ onClose }: PolicyCreationWizardProps) {
  return <WizardLayout title="Policy-Erstellungsassistent" subtitle="Template-Automation nicht verfügbar" color="amber"
    icon={<DocumentCheckIcon className="h-8 w-8" />} steps={[{ n: 1, label: 'Nicht verfügbar' }]} currentStep={1}
    onStepChange={() => {}} onClose={onClose} onComplete={onClose} completeLabel="Schliessen">
    <div role="status" className="space-y-4">
      <p>Dieser Template-Assistent ist nicht an einen unterstützten Erstellungs-, Zuweisungs- und Aktivierungsworkflow angebunden.</p>
      <p>Es wurde keine Richtlinie erstellt, zugewiesen, aktiviert oder im Browser als erfolgreich gespeichert.</p>
      <p>Der vorhandene Richtlinieneditor unterstützt bestätigte Entwürfe und versionierte Änderungen mit eigenen Berechtigungsprüfungen. Eine Aktivierung dort ist keine bestätigte Gerätebereitstellung.</p>
      <a href="/policies" className="text-blue-500 underline">Zum Richtlinieneditor</a>
    </div>
  </WizardLayout>;
}
