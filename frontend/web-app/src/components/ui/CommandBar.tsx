'use client';
import React from 'react';
import { ArrowPathIcon } from '@heroicons/react/24/outline';

export interface CommandBarAction {
  label: string;
  icon?: React.FC<React.SVGProps<SVGSVGElement>>;
  onClick: () => void;
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  disabled?: boolean;
}

interface CommandBarProps {
  primary?: CommandBarAction;
  actions?: CommandBarAction[];
  onRefresh?: () => void;
  rightContent?: React.ReactNode;
  className?: string;
}

export function CommandBar({ primary, actions = [], onRefresh, rightContent, className = '' }: CommandBarProps) {
  return (
    <div className={`fluent-command-bar ${className}`}>
      {primary && (
        <button
          className="fluent-btn-primary"
          onClick={primary.onClick}
          disabled={primary.disabled}
        >
          {primary.icon && <primary.icon style={{ width: 16, height: 16 }} />}
          {primary.label}
        </button>
      )}
      {actions.map((action, i) => (
        <button
          key={i}
          className={action.variant === 'danger' ? 'fluent-btn-secondary' : 'fluent-btn-secondary'}
          style={action.variant === 'danger' ? { color: 'var(--danger)', borderColor: 'var(--danger)' } : {}}
          onClick={action.onClick}
          disabled={action.disabled}
        >
          {action.icon && <action.icon style={{ width: 16, height: 16 }} />}
          {action.label}
        </button>
      ))}
      {onRefresh && (
        <button className="fluent-btn-ghost" onClick={onRefresh} title="Refresh">
          <ArrowPathIcon style={{ width: 16, height: 16 }} />
        </button>
      )}
      {rightContent && <div style={{ marginLeft: 'auto' }}>{rightContent}</div>}
    </div>
  );
}
