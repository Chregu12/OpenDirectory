'use client';
import React from 'react';

interface ABMShellProps {
  listColumn?: React.ReactNode;
  detailPanel: React.ReactNode;
  showListColumn?: boolean;
  detailSelected?: boolean;
  onBackToList?: () => void;
}

export default function ABMShell({ listColumn, detailPanel, showListColumn = true, detailSelected = false, onBackToList }: ABMShellProps) {
  const withList = showListColumn && !!listColumn;
  return <div className={`od-list-detail ${withList ? '' : 'od-list-detail-single'}`} data-detail-selected={detailSelected}>
    {withList && <div className="od-list-column">{listColumn}</div>}
    <div className="od-detail-column">
      {withList && detailSelected && onBackToList && <div className="od-mobile-back"><button type="button" className="fluent-btn-secondary" onClick={onBackToList}>← Zurück zur Liste</button></div>}
      {detailPanel}
    </div>
  </div>;
}
