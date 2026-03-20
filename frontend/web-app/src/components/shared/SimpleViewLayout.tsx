'use client';

import React from 'react';
import { CheckCircleIcon, ExclamationTriangleIcon, XCircleIcon } from '@heroicons/react/24/outline';

// ── Types ──────────────────────────────────────────────────────────────────────

export type HeroStatus = 'ok' | 'warning' | 'critical';

export interface HeroConfig {
  status: HeroStatus;
  icon?: React.ReactNode;
  title: string;
  subtitle: string;
}

export interface StatCard {
  value: string | number;
  label: string;
  color?: string; // tailwind text color class, e.g. 'text-blue-600'
}

export interface ListItem {
  key: string;
  icon?: React.ReactNode;
  title: string;
  subtitle?: string;
  trailing?: React.ReactNode;
}

export interface ListSection {
  title: string;
  items: ListItem[];
  maxItems?: number;
}

export interface QuickAction {
  label: string;
  icon?: React.ReactNode;
  onClick: () => void;
  variant?: 'primary' | 'secondary';
  disabled?: boolean;
}

export interface SimpleViewLayoutProps {
  hero: HeroConfig;
  stats: StatCard[];
  sections?: ListSection[];
  actions?: QuickAction[];
  children?: React.ReactNode;
}

// ── Hero Status Styles ─────────────────────────────────────────────────────────

const HERO_STYLES: Record<HeroStatus, { bg: string; iconBg: string; title: string }> = {
  ok: {
    bg: 'bg-gradient-to-br from-green-50 to-emerald-100 border border-green-200',
    iconBg: 'bg-green-200',
    title: 'text-green-900',
  },
  warning: {
    bg: 'bg-gradient-to-br from-orange-50 to-amber-100 border border-orange-200',
    iconBg: 'bg-orange-200',
    title: 'text-orange-900',
  },
  critical: {
    bg: 'bg-gradient-to-br from-red-50 to-red-100 border border-red-200',
    iconBg: 'bg-red-200',
    title: 'text-red-900',
  },
};

const DEFAULT_HERO_ICONS: Record<HeroStatus, React.ReactNode> = {
  ok: <CheckCircleIcon className="w-10 h-10 text-green-600" />,
  warning: <ExclamationTriangleIcon className="w-10 h-10 text-orange-600" />,
  critical: <XCircleIcon className="w-10 h-10 text-red-600" />,
};

// ── Component ──────────────────────────────────────────────────────────────────

export default function SimpleViewLayout({
  hero,
  stats,
  sections,
  actions,
  children,
}: SimpleViewLayoutProps) {
  const heroStyle = HERO_STYLES[hero.status];

  return (
    <div className="p-6 space-y-6">
      {/* Status Hero */}
      <div className={`rounded-2xl p-8 text-center ${heroStyle.bg}`}>
        <div className={`w-20 h-20 mx-auto rounded-full flex items-center justify-center mb-4 ${heroStyle.iconBg}`}>
          {hero.icon || DEFAULT_HERO_ICONS[hero.status]}
        </div>
        <h1 className={`text-2xl font-bold mb-1 ${heroStyle.title}`}>
          {hero.title}
        </h1>
        <p className="text-sm text-gray-600">{hero.subtitle}</p>
      </div>

      {/* Compact Stats */}
      {stats.length > 0 && (
        <div className={`grid grid-cols-2 ${stats.length > 2 ? 'md:grid-cols-4' : 'md:grid-cols-2'} gap-4`}>
          {stats.map((stat, i) => (
            <div key={i} className="bg-white rounded-xl p-4 border border-gray-100 shadow-sm text-center">
              <p className={`text-2xl font-bold ${stat.color || 'text-gray-900'}`}>{stat.value}</p>
              <p className="text-xs text-gray-500 mt-1">{stat.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* List Sections */}
      {sections?.map((section, si) => (
        section.items.length > 0 && (
          <div key={si} className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
            <h3 className="text-sm font-semibold text-gray-900 mb-3">{section.title}</h3>
            <div className="space-y-2">
              {section.items.slice(0, section.maxItems || 5).map(item => (
                <div key={item.key} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    {item.icon}
                    <div>
                      <p className="text-sm font-medium text-gray-900">{item.title}</p>
                      {item.subtitle && <p className="text-xs text-gray-500">{item.subtitle}</p>}
                    </div>
                  </div>
                  {item.trailing}
                </div>
              ))}
            </div>
          </div>
        )
      ))}

      {/* Extra content slot */}
      {children}

      {/* Quick Actions */}
      {actions && actions.length > 0 && (
        <div className="flex justify-center gap-3">
          {actions.map((action, i) => (
            <button
              key={i}
              onClick={action.onClick}
              disabled={action.disabled}
              className={`flex items-center gap-2 px-6 py-3 text-sm font-medium rounded-xl transition-colors shadow-sm ${
                action.variant === 'secondary'
                  ? 'text-gray-700 bg-white border border-gray-200 hover:bg-gray-50'
                  : 'text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50'
              }`}
            >
              {action.icon}
              {action.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
