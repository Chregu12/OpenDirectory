'use client';

import React, { useState } from 'react';
import ABMShell from '@/components/layout/ABMShell';
import ServicePrincipalListColumn, { ServicePrincipal } from './ServicePrincipalListColumn';
import ServicePrincipalDetailPanel from './ServicePrincipalDetailPanel';

interface ServicePrincipalsViewProps {
  onCreateNew?: () => void;
}

export default function ServicePrincipalsView({ onCreateNew }: ServicePrincipalsViewProps) {
  const [selectedSP, setSelectedSP] = useState<ServicePrincipal | null>(null);

  return (
    <ABMShell
      showListColumn
      listColumn={
        <ServicePrincipalListColumn
          selectedId={selectedSP?.id ?? null}
          onSelect={setSelectedSP}
          onCreateNew={onCreateNew}
        />
      }
      detailPanel={
        <ServicePrincipalDetailPanel sp={selectedSP} />
      }
    />
  );
}
