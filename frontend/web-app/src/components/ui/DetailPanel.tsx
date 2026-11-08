'use client';
import React from 'react';
import { Dialog } from '@headlessui/react';
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
  return <Dialog open={open} onClose={onClose} className="relative z-[70]">
    <div className="fixed inset-0 bg-black/50" aria-hidden="true" />
    <Dialog.Panel className="fluent-detail-panel open" style={{ width, maxWidth: '100vw', top: 0 }}>
        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div style={{ minWidth: 0, flex: 1 }}>
              <Dialog.Title style={{ fontSize: 18, fontWeight: 600, color: 'var(--text-primary)', margin: 0, lineHeight: 1.3 }}>
                {title}
              </Dialog.Title>
              {subtitle && (
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: '2px 0 0 0' }}>
                  {subtitle}
                </p>
              )}
            </div>
            <button
              aria-label="Details schliessen"
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
            <nav aria-label="Detailbereiche" style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 16 }}>
              {tabs.map(tab => (
                <button
                  key={tab.id}
                  aria-pressed={activeTab === tab.id}
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
            </nav>
          )}
        </div>

        {/* Scrollable body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
          {children}
        </div>
    </Dialog.Panel>
  </Dialog>;
}
