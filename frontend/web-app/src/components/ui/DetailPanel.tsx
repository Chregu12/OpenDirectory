'use client';
import React, { useEffect } from 'react';
import { XMarkIcon } from '@heroicons/react/24/outline';

interface Tab {
  id: string;
  label: string;
}

interface DetailPanelProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  tabs?: Tab[];
  activeTab?: string;
  onTabChange?: (tabId: string) => void;
  children: React.ReactNode;
  actions?: React.ReactNode;
  width?: number | string;
}

export function DetailPanel({
  open,
  onClose,
  title,
  subtitle,
  tabs,
  activeTab,
  onTabChange,
  children,
  actions,
  width = 420,
}: DetailPanelProps) {
  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    if (open) window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onClose]);

  return (
    <>
      {/* Dim overlay on mobile */}
      {open && (
        <div
          className="lg:hidden fixed inset-0 z-20"
          style={{ background: 'rgba(0,0,0,0.3)' }}
          onClick={onClose}
        />
      )}

      <aside
        className={`fluent-detail-panel ${open ? 'open' : ''}`}
        style={{ width }}
      >
        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div style={{ minWidth: 0, flex: 1 }}>
              <h2 style={{ fontSize: 18, fontWeight: 600, color: 'var(--text-primary)', margin: 0, lineHeight: 1.3 }}>
                {title}
              </h2>
              {subtitle && (
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: '2px 0 0 0' }}>
                  {subtitle}
                </p>
              )}
            </div>
            <button
              onClick={onClose}
              style={{ padding: 4, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', borderRadius: 4, flexShrink: 0 }}
            >
              <XMarkIcon style={{ width: 20, height: 20 }} />
            </button>
          </div>

          {/* Actions row */}
          {actions && <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>{actions}</div>}

          {/* Tabs */}
          {tabs && tabs.length > 0 && (
            <div style={{ display: 'flex', gap: 0, marginTop: 12, borderBottom: 'none' }}>
              {tabs.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => onTabChange?.(tab.id)}
                  style={{
                    padding: '6px 12px',
                    background: 'none',
                    border: 'none',
                    borderBottom: activeTab === tab.id ? '2px solid var(--accent-blue)' : '2px solid transparent',
                    color: activeTab === tab.id ? 'var(--accent-blue)' : 'var(--text-secondary)',
                    fontWeight: activeTab === tab.id ? 600 : 400,
                    fontSize: 13,
                    cursor: 'pointer',
                    transition: 'color 0.1s, border-color 0.1s',
                  }}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Scrollable body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
          {children}
        </div>
      </aside>
    </>
  );
}
