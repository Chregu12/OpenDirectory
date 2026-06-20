'use client';
import React from 'react';
import { CommandBar, CommandBarAction } from './CommandBar';
import { StatCards, StatCard } from './StatCards';
import { Breadcrumb, BreadcrumbItem } from './Breadcrumb';

interface ViewShellProps {
  title: string;
  subtitle?: string;
  breadcrumbs?: BreadcrumbItem[];
  primaryAction?: CommandBarAction;
  actions?: CommandBarAction[];
  onRefresh?: () => void;
  statCards?: StatCard[];
  rightContent?: React.ReactNode;
  children: React.ReactNode;
  noPadding?: boolean;
}

export function ViewShell({
  title, subtitle, breadcrumbs,
  primaryAction, actions, onRefresh, statCards, rightContent,
  children, noPadding = false,
}: ViewShellProps) {
  return (
    <div style={{ padding: noPadding ? 0 : '24px 28px', minHeight: '100vh', background: 'var(--bg-base)' }}>
      {breadcrumbs && <Breadcrumb items={breadcrumbs} />}
      <div style={{ marginBottom: 16 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', margin: 0, lineHeight: 1.2 }}>{title}</h1>
        {subtitle && <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 3, marginBottom: 0 }}>{subtitle}</p>}
      </div>
      {(primaryAction || (actions && actions.length > 0) || onRefresh) && (
        <CommandBar
          primary={primaryAction}
          actions={actions}
          onRefresh={onRefresh}
          rightContent={rightContent}
        />
      )}
      {statCards && statCards.length > 0 && <StatCards cards={statCards} />}
      {children}
    </div>
  );
}
