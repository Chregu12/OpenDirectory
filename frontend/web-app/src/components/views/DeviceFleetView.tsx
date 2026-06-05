'use client';

import React, { useState } from 'react';
import ABMShell from '@/components/layout/ABMShell';
import DeviceListColumn, { FleetDevice } from './DeviceListColumn';
import DeviceDetailPanel from './DeviceDetailPanel';

export default function DeviceFleetView() {
  const [selectedDevice, setSelectedDevice] = useState<FleetDevice | null>(null);

  return (
    <ABMShell
      showListColumn
      listColumn={
        <DeviceListColumn
          selectedId={selectedDevice?.id ?? null}
          onSelect={setSelectedDevice}
        />
      }
      detailPanel={
        <DeviceDetailPanel device={selectedDevice} />
      }
    />
  );
}
