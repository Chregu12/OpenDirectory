'use client';

import React from 'react';

interface ABMShellProps {
  listColumn?: React.ReactNode;
  detailPanel: React.ReactNode;
  showListColumn?: boolean;
}

/**
 * ABMShell — the 3-column content area shell (sidebar is rendered in UnifiLayout).
 * Wraps: [optional list column 300px fixed] + [detail/main panel flex-1].
 */
export default function ABMShell({ listColumn, detailPanel, showListColumn = true }: ABMShellProps) {
  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>
      {/* Middle list column — 300px fixed */}
      {showListColumn && listColumn && (
        <div
          style={{
            width: 300,
            flexShrink: 0,
            borderRight: '1px solid var(--apple-gray-2)',
            background: '#FFFFFF',
            display: 'flex',
            flexDirection: 'column',
            overflowY: 'auto',
          }}
        >
          {listColumn}
        </div>
      )}

      {/* Right detail / main panel — flex-1 */}
      <div
        style={{
          flex: 1,
          background: '#FFFFFF',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          minWidth: 0,
        }}
      >
        {detailPanel}
      </div>
    </div>
  );
}
