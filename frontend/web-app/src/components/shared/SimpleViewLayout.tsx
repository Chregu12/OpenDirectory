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
  color?: string;
  icon?: React.ReactNode;
  trend?: { value: string; direction: 'up' | 'down' | 'stable' };
}

export interface ListItem {
  key: string;
  icon?: React.ReactNode;
  title: string;
  subtitle?: string;
  trailing?: React.ReactNode;
  onClick?: () => void;
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

// ── Status colors (subtle, white-based) ─────────────────────────────────────

const STATUS_DOT: Record<HeroStatus, string> = {
  ok: 'bg-emerald-400',
  warning: 'bg-amber-400',
  critical: 'bg-red-400',
};

const STATUS_TEXT: Record<HeroStatus, string> = {
  ok: 'text-emerald-600',
  warning: 'text-amber-600',
  critical: 'text-red-600',
};

const STATUS_ICON_COLOR: Record<HeroStatus, string> = {
  ok: 'text-emerald-500',
  warning: 'text-amber-500',
  critical: 'text-red-500',
};

const DEFAULT_ICONS: Record<HeroStatus, React.ReactNode> = {
  ok: <CheckCircleIcon className="w-6 h-6 text-emerald-500" />,
  warning: <ExclamationTriangleIcon className="w-6 h-6 text-amber-500" />,
  critical: <XCircleIcon className="w-6 h-6 text-red-500" />,
};

// ── Reusable Sub-Components ─────────────────────────────────────────────────

/** Compact status banner – white card with dot indicator */
export function StatusBanner({ config }: { config: HeroConfig }) {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-100 px-6 py-5 flex items-center gap-4">
      <div className="flex-shrink-0">
        {config.icon || DEFAULT_ICONS[config.status]}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${STATUS_DOT[config.status]}`} />
          <h2 className={`text-[15px] font-semibold ${STATUS_TEXT[config.status]}`}>
            {config.title}
          </h2>
        </div>
        <p className="text-[13px] text-gray-400 mt-0.5">{config.subtitle}</p>
      </div>
    </div>
  );
}

/** Stat grid – clean white cards with optional icon and trend */
export function StatGrid({ stats }: { stats: StatCard[] }) {
  if (stats.length === 0) return null;

  const cols = stats.length <= 2 ? 'md:grid-cols-2' : stats.length === 3 ? 'md:grid-cols-3' : 'md:grid-cols-4';

  return (
    <div className={`grid grid-cols-2 ${cols} gap-3`}>
      {stats.map((stat, i) => (
        <div key={i} className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <div className="flex items-center justify-between mb-2">
            <p className="text-[13px] font-medium text-gray-400">{stat.label}</p>
            {stat.icon && <span className="text-gray-300">{stat.icon}</span>}
          </div>
          <p className={`text-2xl font-semibold ${stat.color || 'text-gray-900'}`}>{stat.value}</p>
          {stat.trend && (
            <p className={`text-[12px] mt-1 ${
              stat.trend.direction === 'up' ? 'text-emerald-500' :
              stat.trend.direction === 'down' ? 'text-red-500' :
              'text-gray-400'
            }`}>
              {stat.trend.direction === 'up' ? '↑' : stat.trend.direction === 'down' ? '↓' : '–'} {stat.trend.value}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

/** Info card – white card with title and list of items */
export function InfoCard({ title, items, maxItems = 5 }: { title: string; items: ListItem[]; maxItems?: number }) {
  if (items.length === 0) return null;

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-100">
      <div className="px-5 py-3.5 border-b border-gray-100">
        <h3 className="text-[14px] font-semibold text-gray-900">{title}</h3>
      </div>
      <div className="p-1.5">
        {items.slice(0, maxItems).map(item => (
          <div
            key={item.key}
            onClick={item.onClick}
            className={`flex items-center justify-between px-4 py-3 rounded-lg transition-colors ${
              item.onClick ? 'hover:bg-gray-50 cursor-pointer' : ''
            }`}
          >
            <div className="flex items-center gap-3 min-w-0">
              {item.icon}
              <div className="min-w-0">
                <p className="text-[13px] font-medium text-gray-900 truncate">{item.title}</p>
                {item.subtitle && <p className="text-[11px] text-gray-400 truncate">{item.subtitle}</p>}
              </div>
            </div>
            {item.trailing}
          </div>
        ))}
      </div>
    </div>
  );
}

/** Action bar – row of buttons */
export function ActionBar({ actions }: { actions: QuickAction[] }) {
  if (actions.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-2">
      {actions.map((action, i) => (
        <button
          key={i}
          onClick={action.onClick}
          disabled={action.disabled}
          className={`inline-flex items-center gap-2 px-4 py-2.5 text-[13px] font-medium rounded-lg transition-colors ${
            action.variant === 'secondary'
              ? 'text-gray-600 bg-white border border-gray-200 hover:bg-gray-50 shadow-sm'
              : 'text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 shadow-sm'
          }`}
        >
          {action.icon}
          {action.label}
        </button>
      ))}
    </div>
  );
}

// ── Main Layout ─────────────────────────────────────────────────────────────

export default function SimpleViewLayout({
  hero,
  stats,
  sections,
  actions,
  children,
}: SimpleViewLayoutProps) {
  return (
    <div className="p-6 space-y-4">
      <StatusBanner config={hero} />
      <StatGrid stats={stats} />

      {sections?.map((section, i) => (
        <InfoCard key={i} title={section.title} items={section.items} maxItems={section.maxItems} />
      ))}

      {children}

      {actions && actions.length > 0 && <ActionBar actions={actions} />}
    </div>
  );
}
