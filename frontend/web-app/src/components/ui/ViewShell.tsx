'use client';
import React from 'react';
import { PageHeader } from './PageHeader';
import { VIEWS } from '@/lib/views';
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
    <div className={noPadding ? "od-view od-view-flush" : "od-view"}>
      {breadcrumbs && <Breadcrumb items={breadcrumbs} />}
      <PageHeader title={title} subtitle={subtitle} icon={VIEWS.find(view => view.name === title)?.icon} />
      {(primaryAction || (actions && actions.length > 0) || onRefresh || rightContent) && (
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
