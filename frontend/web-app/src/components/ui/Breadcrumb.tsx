'use client';
import React from 'react';
import { ChevronRightIcon } from '@heroicons/react/24/outline';

export interface BreadcrumbItem {
  label: string;
  onClick?: () => void;
}

export function Breadcrumb({ items }: { items: BreadcrumbItem[] }) {
  return (
    <nav className="fluent-breadcrumb">
      {items.map((item, i) => (
        <React.Fragment key={i}>
          {i > 0 && <ChevronRightIcon className="fluent-breadcrumb-sep" style={{ width: 12, height: 12 }} />}
          {item.onClick ? (
            <a href="#" onClick={e => { e.preventDefault(); item.onClick!(); }}>{item.label}</a>
          ) : (
            <span style={{ color: 'var(--text-primary)', fontWeight: i === items.length - 1 ? 600 : 400 }}>{item.label}</span>
          )}
        </React.Fragment>
      ))}
    </nav>
  );
}
