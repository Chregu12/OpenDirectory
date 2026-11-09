'use client';

import React, { useState } from 'react';
import { ShieldCheckIcon } from '@heroicons/react/24/outline';
import { PageHeader } from '@/components/ui/PageHeader';
import PIMGroupsPanel from './PIMGroupsPanel';
import PIMAdvancedView from './PIMAdvancedView';

export default function PIMView() {
  const [advanced, setAdvanced] = useState(false);
  return <div className="od-view od-pim-page">
    <PageHeader title="Privileged Identity Management" subtitle="Zeitlich begrenzter Zugriff auf deine Verwaltungsaufgaben." icon={ShieldCheckIcon} />
    <PIMGroupsPanel management />
    <div className="od-pim-advanced">
      <button className="fluent-btn-ghost" aria-expanded={advanced} aria-controls="pim-advanced" onClick={() => setAdvanced(value => !value)}>
        {advanced ? 'Weitere Rollen und Richtlinien schließen' : 'Weitere Rollen und Richtlinien'}
      </button>
      {advanced && <div id="pim-advanced"><PIMAdvancedView /></div>}
    </div>
  </div>;
}
