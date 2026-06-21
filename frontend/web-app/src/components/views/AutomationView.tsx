'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  PlusIcon,
  TrashIcon,
  PencilIcon,
  XMarkIcon,
  BoltIcon,
  ClockIcon,
  DevicePhoneMobileIcon,
  UserIcon,
  ShieldExclamationIcon,
  LockClosedIcon,
  IdentificationIcon,
  CalendarDaysIcon,
  BellIcon,
  PlayIcon,
  CheckIcon,
  StopIcon,
  GlobeAltIcon,
  ArrowPathIcon,
  UserGroupIcon,
  ComputerDesktopIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

// ── Types ─────────────────────────────────────────────────────────────────────

type TriggerType =
  | 'device_enrolled'
  | 'user_created'
  | 'compliance_violation'
  | 'login_failed'
  | 'certificate_expiring'
  | 'schedule';

type ConditionOperator = 'equals' | 'contains' | 'greater_than' | 'less_than' | 'not_equals';
type ConditionJoin = 'AND' | 'OR';

type ActionType =
  | 'send_notification'
  | 'run_quick_action'
  | 'lock_device'
  | 'add_to_group'
  | 'call_webhook';

type QuickAction = 'enroll_device' | 'onboard_user' | 'deploy_policy';

interface Condition {
  id: string;
  attribute: string;
  operator: ConditionOperator;
  value: string;
}

interface ActionBase {
  id: string;
  type: ActionType;
}

interface SendNotificationAction extends ActionBase {
  type: 'send_notification';
  recipient: string;
  message: string;
}

interface RunQuickActionAction extends ActionBase {
  type: 'run_quick_action';
  quickAction: QuickAction;
}

interface LockDeviceAction extends ActionBase {
  type: 'lock_device';
  deviceSelector: string;
}

interface AddToGroupAction extends ActionBase {
  type: 'add_to_group';
  groupName: string;
}

interface CallWebhookAction extends ActionBase {
  type: 'call_webhook';
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
}

type Action =
  | SendNotificationAction
  | RunQuickActionAction
  | LockDeviceAction
  | AddToGroupAction
  | CallWebhookAction;

interface TriggerConfig {
  type: TriggerType;
  cronExpression?: string;
  platformFilter?: string;
}

interface AutomationRule {
  id: string;
  name: string;
  enabled: boolean;
  trigger: TriggerConfig;
  conditionJoin: ConditionJoin;
  conditions: Condition[];
  actions: Action[];
  lastTriggered?: string;
  createdAt: string;
  updatedAt: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const TRIGGER_OPTIONS: { value: TriggerType; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { value: 'device_enrolled',     label: 'Device enrolled',              icon: ComputerDesktopIcon },
  { value: 'user_created',        label: 'User created',                 icon: UserIcon },
  { value: 'compliance_violation',label: 'Compliance violation detected', icon: ShieldExclamationIcon },
  { value: 'login_failed',        label: 'Login failed 5x',              icon: LockClosedIcon },
  { value: 'certificate_expiring',label: 'Certificate expiring',         icon: IdentificationIcon },
  { value: 'schedule',            label: 'Schedule (cron)',              icon: CalendarDaysIcon },
];

const TRIGGER_ICONS: Record<TriggerType, React.ComponentType<{ className?: string }>> = {
  device_enrolled:      ComputerDesktopIcon,
  user_created:         UserIcon,
  compliance_violation: ShieldExclamationIcon,
  login_failed:         LockClosedIcon,
  certificate_expiring: IdentificationIcon,
  schedule:             CalendarDaysIcon,
};

const PLATFORM_OPTIONS = ['All platforms', 'Windows', 'macOS', 'Linux', 'iOS', 'Android'];

const CONDITION_ATTRIBUTES = [
  'device.platform', 'device.os_version', 'device.compliance_status',
  'user.department', 'user.role', 'user.email',
  'event.severity', 'event.type', 'event.source',
];

const CONDITION_OPERATORS: { value: ConditionOperator; label: string }[] = [
  { value: 'equals',       label: 'equals' },
  { value: 'not_equals',   label: 'not equals' },
  { value: 'contains',     label: 'contains' },
  { value: 'greater_than', label: 'greater than' },
  { value: 'less_than',    label: 'less than' },
];

const ACTION_OPTIONS: { value: ActionType; label: string }[] = [
  { value: 'send_notification', label: 'Send notification' },
  { value: 'run_quick_action',  label: 'Run quick action' },
  { value: 'lock_device',       label: 'Lock device' },
  { value: 'add_to_group',      label: 'Add to group' },
  { value: 'call_webhook',      label: 'Call webhook' },
];

const QUICK_ACTION_OPTIONS: { value: QuickAction; label: string }[] = [
  { value: 'enroll_device',  label: 'Enroll device' },
  { value: 'onboard_user',   label: 'Onboard user' },
  { value: 'deploy_policy',  label: 'Deploy policy' },
];

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;

const TEMPLATE_VARS_HINT = '{{user.id}}, {{device.id}}, {{event.type}}';

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateId(): string {
  return Math.random().toString(36).slice(2, 10);
}

function parseCronHuman(cron: string): string {
  if (!cron.trim()) return '';
  const parts = cron.trim().split(/\s+/);
  if (parts.length < 5) return cron;
  const [minute, hour, dom, month, dow] = parts;
  if (dom === '*' && month === '*' && dow === '*') {
    if (minute !== '*' && hour !== '*') {
      const h = parseInt(hour, 10);
      const m = parseInt(minute, 10);
      const suffix = h < 12 ? 'am' : 'pm';
      const displayHour = h === 0 ? 12 : h > 12 ? h - 12 : h;
      const displayMin = m > 0 ? `:${String(m).padStart(2, '0')}` : '';
      return `Runs every day at ${displayHour}${displayMin}${suffix}`;
    }
    if (minute === '*' && hour === '*') return 'Runs every minute';
    if (minute === '0' && hour === '*') return 'Runs every hour';
  }
  if (dow !== '*' && dom === '*' && month === '*') {
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const dayLabel = days[parseInt(dow, 10)] || dow;
    if (minute !== '*' && hour !== '*') {
      const h = parseInt(hour, 10);
      const m = parseInt(minute, 10);
      const suffix = h < 12 ? 'am' : 'pm';
      const displayHour = h === 0 ? 12 : h > 12 ? h - 12 : h;
      const displayMin = m > 0 ? `:${String(m).padStart(2, '0')}` : '';
      return `Runs every ${dayLabel} at ${displayHour}${displayMin}${suffix}`;
    }
  }
  return `Cron: ${cron}`;
}

function triggerLabel(trigger: TriggerConfig): string {
  const opt = TRIGGER_OPTIONS.find(o => o.value === trigger.type);
  if (!opt) return trigger.type;
  if (trigger.type === 'schedule' && trigger.cronExpression) {
    return parseCronHuman(trigger.cronExpression) || opt.label;
  }
  if (trigger.platformFilter && trigger.platformFilter !== 'All platforms') {
    return `${opt.label} (${trigger.platformFilter})`;
  }
  return opt.label;
}

function actionSummary(action: Action): string {
  switch (action.type) {
    case 'send_notification': return `Notify ${action.recipient || '…'}`;
    case 'run_quick_action':  return `Run: ${action.quickAction?.replace(/_/g, ' ') || '…'}`;
    case 'lock_device':       return `Lock device ${action.deviceSelector || ''}`;
    case 'add_to_group':      return `Add to group "${action.groupName || '…'}"`;
    case 'call_webhook':      return `${action.method || 'POST'} ${action.url || '…'}`;
    default: return 'Action';
  }
}

function ruleNarrative(rule: AutomationRule): string {
  const triggerText = `When [${triggerLabel(rule.trigger)}]`;
  const condText = rule.conditions.length > 0
    ? ` and [${rule.conditions.map(c => `${c.attribute} ${c.operator} "${c.value}"`).join(` ${rule.conditionJoin} `)}]`
    : '';
  const actText = rule.actions.length > 0
    ? `, then [${rule.actions.map(actionSummary).join('; ')}]`
    : ', then [no actions]';
  return triggerText + condText + actText;
}

// ── Default new action ────────────────────────────────────────────────────────

function defaultAction(type: ActionType): Action {
  switch (type) {
    case 'send_notification': return { id: generateId(), type, recipient: '', message: '' };
    case 'run_quick_action':  return { id: generateId(), type, quickAction: 'enroll_device' };
    case 'lock_device':       return { id: generateId(), type, deviceSelector: '{{device.id}}' };
    case 'add_to_group':      return { id: generateId(), type, groupName: '' };
    case 'call_webhook':      return { id: generateId(), type, url: '', method: 'POST' };
  }
}

// ── Sub-components ────────────────────────────────────────────────────────────

interface ToggleSwitchProps {
  checked: boolean;
  onChange: (val: boolean) => void;
  small?: boolean;
}

function ToggleSwitch({ checked, onChange, small }: ToggleSwitchProps) {
  const w = small ? 28 : 36;
  const h = small ? 16 : 20;
  const d = small ? 10 : 14;
  const translateX = small ? 12 : 16;
  return (
    <button
      onClick={() => onChange(!checked)}
      style={{
        width: w,
        height: h,
        borderRadius: h / 2,
        backgroundColor: checked ? '#006FFF' : '#D1D5DB',
        border: 'none',
        cursor: 'pointer',
        position: 'relative',
        transition: 'background-color 0.2s',
        padding: 0,
        flexShrink: 0,
      }}
      aria-checked={checked}
      role="switch"
    >
      <span style={{
        position: 'absolute',
        top: (h - d) / 2,
        left: checked ? translateX - (h - d) / 2 + (h - d) / 2 : (h - d) / 2,
        width: d,
        height: d,
        borderRadius: '50%',
        backgroundColor: '#fff',
        transition: 'left 0.2s',
        boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
      }} />
    </button>
  );
}

// ── Action Editor ─────────────────────────────────────────────────────────────

interface ActionEditorProps {
  action: Action;
  onChange: (action: Action) => void;
  onRemove: () => void;
}

function ActionEditor({ action, onChange, onRemove }: ActionEditorProps) {
  const inputStyle: React.CSSProperties = {
    width: '100%',
    border: '1px solid rgba(255,255,255,0.07)',
    borderRadius: 6,
    padding: '6px 10px',
    fontSize: 13,
    outline: 'none',
    boxSizing: 'border-box',
    color: '#111827',
    background: 'var(--bg-surface, #161b22)',
  };

  const selectStyle: React.CSSProperties = {
    ...inputStyle,
    cursor: 'pointer',
  };

  const renderFields = () => {
    switch (action.type) {
      case 'send_notification':
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: 1 }}>
            <input
              style={inputStyle}
              type="text"
              placeholder="Recipient (email or {{user.email}})"
              value={action.recipient}
              onChange={e => onChange({ ...action, recipient: e.target.value })}
            />
            <textarea
              style={{ ...inputStyle, resize: 'vertical', minHeight: 56 }}
              placeholder={`Message — template vars: ${TEMPLATE_VARS_HINT}`}
              value={action.message}
              onChange={e => onChange({ ...action, message: e.target.value })}
            />
          </div>
        );
      case 'run_quick_action':
        return (
          <div style={{ flex: 1 }}>
            <select
              style={selectStyle}
              value={action.quickAction}
              onChange={e => onChange({ ...action, quickAction: e.target.value as QuickAction })}
            >
              {QUICK_ACTION_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
        );
      case 'lock_device':
        return (
          <div style={{ flex: 1 }}>
            <input
              style={inputStyle}
              type="text"
              placeholder="Device selector (e.g. {{device.id}})"
              value={action.deviceSelector}
              onChange={e => onChange({ ...action, deviceSelector: e.target.value })}
            />
            <p style={{ fontSize: 11, color: '#6B7280', marginTop: 3 }}>
              Hint: {TEMPLATE_VARS_HINT}
            </p>
          </div>
        );
      case 'add_to_group':
        return (
          <div style={{ flex: 1 }}>
            <input
              style={inputStyle}
              type="text"
              placeholder="Group name"
              value={action.groupName}
              onChange={e => onChange({ ...action, groupName: e.target.value })}
            />
          </div>
        );
      case 'call_webhook':
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: 1 }}>
            <div style={{ display: 'flex', gap: 6 }}>
              <select
                style={{ ...selectStyle, width: 100, flexShrink: 0 }}
                value={action.method}
                onChange={e => onChange({ ...action, method: e.target.value as typeof action.method })}
              >
                {HTTP_METHODS.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
              <input
                style={{ ...inputStyle, flex: 1 }}
                type="url"
                placeholder="https://hooks.example.com/..."
                value={action.url}
                onChange={e => onChange({ ...action, url: e.target.value })}
              />
            </div>
            <p style={{ fontSize: 11, color: '#6B7280' }}>
              Hint: {TEMPLATE_VARS_HINT}
            </p>
          </div>
        );
    }
  };

  return (
    <div style={{
      display: 'flex',
      gap: 8,
      alignItems: 'flex-start',
      padding: '10px 12px',
      background: 'var(--bg-surface-raised, #1c2128)',
      borderRadius: 8,
      border: '1px solid rgba(255,255,255,0.07)',
    }}>
      <select
        style={{ ...inputStyle, width: 160, flexShrink: 0 }}
        value={action.type}
        onChange={e => onChange(defaultAction(e.target.value as ActionType))}
      >
        {ACTION_OPTIONS.map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
      {renderFields()}
      <button
        onClick={onRemove}
        title="Remove action"
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: '#9CA3AF',
          padding: '4px',
          borderRadius: 4,
          flexShrink: 0,
          lineHeight: 1,
        }}
        onMouseEnter={e => (e.currentTarget.style.color = '#EF4444')}
        onMouseLeave={e => (e.currentTarget.style.color = '#9CA3AF')}
      >
        <XMarkIcon style={{ width: 16, height: 16 }} />
      </button>
    </div>
  );
}

// ── Condition Editor ──────────────────────────────────────────────────────────

interface ConditionEditorProps {
  condition: Condition;
  onChange: (c: Condition) => void;
  onRemove: () => void;
}

function ConditionEditor({ condition, onChange, onRemove }: ConditionEditorProps) {
  const inputStyle: React.CSSProperties = {
    border: '1px solid rgba(255,255,255,0.07)',
    borderRadius: 6,
    padding: '6px 10px',
    fontSize: 13,
    outline: 'none',
    color: '#111827',
    background: 'var(--bg-surface, #161b22)',
    width: '100%',
    boxSizing: 'border-box',
  };

  return (
    <div style={{
      display: 'flex',
      gap: 6,
      alignItems: 'center',
      flexWrap: 'wrap',
    }}>
      <select
        style={{ ...inputStyle, width: 170 }}
        value={condition.attribute}
        onChange={e => onChange({ ...condition, attribute: e.target.value })}
      >
        {CONDITION_ATTRIBUTES.map(a => <option key={a} value={a}>{a}</option>)}
      </select>
      <select
        style={{ ...inputStyle, width: 120 }}
        value={condition.operator}
        onChange={e => onChange({ ...condition, operator: e.target.value as ConditionOperator })}
      >
        {CONDITION_OPERATORS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <input
        style={{ ...inputStyle, width: 140 }}
        type="text"
        placeholder="value"
        value={condition.value}
        onChange={e => onChange({ ...condition, value: e.target.value })}
      />
      <button
        onClick={onRemove}
        title="Remove condition"
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: '#9CA3AF',
          padding: '4px',
          borderRadius: 4,
          lineHeight: 1,
          flexShrink: 0,
        }}
        onMouseEnter={e => (e.currentTarget.style.color = '#EF4444')}
        onMouseLeave={e => (e.currentTarget.style.color = '#9CA3AF')}
      >
        <XMarkIcon style={{ width: 16, height: 16 }} />
      </button>
    </div>
  );
}

// ── Rule List Item ─────────────────────────────────────────────────────────────

interface RuleListItemProps {
  rule: AutomationRule;
  isSelected: boolean;
  onSelect: () => void;
  onToggle: (enabled: boolean) => void;
  onEdit: () => void;
  onDelete: () => void;
}

function RuleListItem({ rule, isSelected, onSelect, onToggle, onEdit, onDelete }: RuleListItemProps) {
  const TriggerIcon = TRIGGER_ICONS[rule.trigger.type] || BoltIcon;

  return (
    <div
      onClick={onSelect}
      style={{
        padding: '10px 14px',
        cursor: 'pointer',
        borderLeft: isSelected ? '3px solid #006FFF' : '3px solid transparent',
        background: isSelected ? 'rgba(0,111,255,0.15)' : 'var(--bg-surface, #161b22)',
        borderBottom: '1px solid rgba(255,255,255,0.07)',
        transition: 'background 0.1s',
      }}
      onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'var(--bg-surface-raised, #1c2128)'; }}
      onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = 'var(--bg-surface, #161b22)'; }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <TriggerIcon style={{ width: 16, height: 16, color: '#6B7280', flexShrink: 0 }} />
        <span style={{
          flex: 1,
          fontSize: 13,
          fontWeight: 500,
          color: '#111827',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}>
          {rule.name || 'Untitled rule'}
        </span>
        <span style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: rule.enabled ? '#22C55E' : '#D1D5DB',
          flexShrink: 0,
        }} />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 6 }}>
        <span style={{ fontSize: 11, color: '#6B7280' }}>{triggerLabel(rule.trigger)}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }} onClick={e => e.stopPropagation()}>
          <ToggleSwitch checked={rule.enabled} onChange={onToggle} small />
          <button
            onClick={onEdit}
            title="Edit"
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6B7280', padding: '2px', borderRadius: 4, lineHeight: 1 }}
            onMouseEnter={e => (e.currentTarget.style.color = '#006FFF')}
            onMouseLeave={e => (e.currentTarget.style.color = '#6B7280')}
          >
            <PencilIcon style={{ width: 14, height: 14 }} />
          </button>
          <button
            onClick={onDelete}
            title="Delete"
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6B7280', padding: '2px', borderRadius: 4, lineHeight: 1 }}
            onMouseEnter={e => (e.currentTarget.style.color = '#EF4444')}
            onMouseLeave={e => (e.currentTarget.style.color = '#6B7280')}
          >
            <TrashIcon style={{ width: 14, height: 14 }} />
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Rule Editor Panel ─────────────────────────────────────────────────────────

interface RuleEditorProps {
  rule: AutomationRule;
  onChange: (rule: AutomationRule) => void;
  onSave: () => void;
  onCancel: () => void;
  saving: boolean;
}

function RuleEditor({ rule, onChange, onSave, onCancel, saving }: RuleEditorProps) {
  const sectionStyle: React.CSSProperties = {
    border: '1px solid rgba(255,255,255,0.07)',
    borderRadius: 10,
    overflow: 'hidden',
    background: 'var(--bg-surface, #161b22)',
  };

  const sectionHeaderStyle: React.CSSProperties = {
    padding: '10px 16px',
    background: 'var(--bg-surface-raised, #1c2128)',
    borderBottom: '1px solid rgba(255,255,255,0.07)',
    display: 'flex',
    alignItems: 'center',
    gap: 8,
  };

  const sectionTitleStyle: React.CSSProperties = {
    fontSize: 13,
    fontWeight: 600,
    color: '#374151',
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    border: '1px solid rgba(255,255,255,0.07)',
    borderRadius: 6,
    padding: '7px 11px',
    fontSize: 13,
    outline: 'none',
    color: '#111827',
    background: 'var(--bg-surface, #161b22)',
    boxSizing: 'border-box',
  };

  const selectStyle: React.CSSProperties = { ...inputStyle, cursor: 'pointer' };

  const addBtnStyle: React.CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    fontSize: 12,
    fontWeight: 500,
    color: '#006FFF',
    background: 'none',
    border: '1px dashed #93C5FD',
    borderRadius: 6,
    padding: '5px 12px',
    cursor: 'pointer',
    transition: 'background 0.15s',
  };

  const TriggerIcon = TRIGGER_ICONS[rule.trigger.type] || BoltIcon;

  const updateTrigger = (updates: Partial<TriggerConfig>) =>
    onChange({ ...rule, trigger: { ...rule.trigger, ...updates } });

  const addCondition = () =>
    onChange({
      ...rule,
      conditions: [...rule.conditions, {
        id: generateId(),
        attribute: CONDITION_ATTRIBUTES[0],
        operator: 'equals',
        value: '',
      }],
    });

  const updateCondition = (id: string, c: Condition) =>
    onChange({ ...rule, conditions: rule.conditions.map(x => x.id === id ? c : x) });

  const removeCondition = (id: string) =>
    onChange({ ...rule, conditions: rule.conditions.filter(x => x.id !== id) });

  const addAction = () =>
    onChange({ ...rule, actions: [...rule.actions, defaultAction('send_notification')] });

  const updateAction = (id: string, a: Action) =>
    onChange({ ...rule, actions: rule.actions.map(x => x.id === id ? a : x) });

  const removeAction = (id: string) =>
    onChange({ ...rule, actions: rule.actions.filter(x => x.id !== id) });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Rule Name */}
      <div>
        <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#374151', marginBottom: 5 }}>
          Rule Name
        </label>
        <input
          style={{ ...inputStyle, fontSize: 15, fontWeight: 500 }}
          type="text"
          placeholder="e.g. Auto-lock on compliance failure"
          value={rule.name}
          onChange={e => onChange({ ...rule, name: e.target.value })}
          autoFocus
        />
      </div>

      {/* Trigger */}
      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>
          <BoltIcon style={{ width: 15, height: 15, color: '#6366F1' }} />
          <span style={sectionTitleStyle}>Trigger</span>
        </div>
        <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <TriggerIcon style={{ width: 16, height: 16, color: '#6B7280', flexShrink: 0 }} />
            <select
              style={selectStyle}
              value={rule.trigger.type}
              onChange={e => updateTrigger({ type: e.target.value as TriggerType, cronExpression: '', platformFilter: 'All platforms' })}
            >
              {TRIGGER_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>

          {rule.trigger.type === 'schedule' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <input
                style={inputStyle}
                type="text"
                placeholder="Cron expression, e.g. 0 9 * * *"
                value={rule.trigger.cronExpression || ''}
                onChange={e => updateTrigger({ cronExpression: e.target.value })}
              />
              {rule.trigger.cronExpression && (
                <p style={{ fontSize: 11, color: '#6B7280', fontStyle: 'italic' }}>
                  {parseCronHuman(rule.trigger.cronExpression)}
                </p>
              )}
            </div>
          )}

          {rule.trigger.type === 'device_enrolled' && (
            <div>
              <label style={{ fontSize: 11, color: '#6B7280', display: 'block', marginBottom: 4 }}>Platform filter</label>
              <select
                style={selectStyle}
                value={rule.trigger.platformFilter || 'All platforms'}
                onChange={e => updateTrigger({ platformFilter: e.target.value })}
              >
                {PLATFORM_OPTIONS.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
          )}
        </div>
      </div>

      {/* Conditions */}
      <div style={sectionStyle}>
        <div style={{ ...sectionHeaderStyle, justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <CheckIcon style={{ width: 15, height: 15, color: '#10B981' }} />
            <span style={sectionTitleStyle}>Conditions</span>
            <span style={{ fontSize: 11, color: '#9CA3AF' }}>(optional)</span>
          </div>
          {rule.conditions.length > 1 && (
            <div style={{ display: 'flex', gap: 4 }}>
              {(['AND', 'OR'] as ConditionJoin[]).map(j => (
                <button
                  key={j}
                  onClick={() => onChange({ ...rule, conditionJoin: j })}
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    padding: '2px 8px',
                    borderRadius: 4,
                    border: '1px solid',
                    cursor: 'pointer',
                    borderColor: rule.conditionJoin === j ? '#006FFF' : '#D1D5DB',
                    background: rule.conditionJoin === j ? 'rgba(0,111,255,0.15)' : 'var(--bg-surface, #161b22)',
                    color: rule.conditionJoin === j ? '#006FFF' : '#6B7280',
                  }}
                >
                  {j}
                </button>
              ))}
            </div>
          )}
        </div>
        <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rule.conditions.length === 0 && (
            <p style={{ fontSize: 12, color: '#9CA3AF', fontStyle: 'italic' }}>
              No conditions — rule will trigger on every matching event.
            </p>
          )}
          {rule.conditions.map((c, i) => (
            <React.Fragment key={c.id}>
              {i > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ flex: 1, height: 1, background: '#E5E7EB' }} />
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#9CA3AF' }}>{rule.conditionJoin}</span>
                  <div style={{ flex: 1, height: 1, background: '#E5E7EB' }} />
                </div>
              )}
              <ConditionEditor
                condition={c}
                onChange={updated => updateCondition(c.id, updated)}
                onRemove={() => removeCondition(c.id)}
              />
            </React.Fragment>
          ))}
          <button
            style={addBtnStyle}
            onClick={addCondition}
            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,111,255,0.15)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'none')}
          >
            <PlusIcon style={{ width: 13, height: 13 }} />
            Add Condition
          </button>
        </div>
      </div>

      {/* Actions */}
      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>
          <PlayIcon style={{ width: 15, height: 15, color: '#F59E0B' }} />
          <span style={sectionTitleStyle}>Actions</span>
        </div>
        <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rule.actions.length === 0 && (
            <p style={{ fontSize: 12, color: '#9CA3AF', fontStyle: 'italic' }}>
              No actions defined yet.
            </p>
          )}
          {rule.actions.map(a => (
            <ActionEditor
              key={a.id}
              action={a}
              onChange={updated => updateAction(a.id, updated)}
              onRemove={() => removeAction(a.id)}
            />
          ))}
          <button
            style={addBtnStyle}
            onClick={addAction}
            onMouseEnter={e => (e.currentTarget.style.background = '#FFFBEB')}
            onMouseLeave={e => (e.currentTarget.style.background = 'none')}
          >
            <PlusIcon style={{ width: 13, height: 13 }} />
            Add Action
          </button>
        </div>
      </div>

      {/* Footer buttons */}
      <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', paddingTop: 4 }}>
        <button
          onClick={onCancel}
          style={{
            padding: '8px 20px',
            fontSize: 13,
            fontWeight: 500,
            borderRadius: 7,
            border: '1px solid rgba(255,255,255,0.07)',
            background: 'var(--bg-surface, #161b22)',
            color: '#374151',
            cursor: 'pointer',
          }}
        >
          Cancel
        </button>
        <button
          onClick={onSave}
          disabled={saving}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '8px 20px',
            fontSize: 13,
            fontWeight: 600,
            borderRadius: 7,
            border: 'none',
            background: saving ? '#93C5FD' : '#006FFF',
            color: '#fff',
            cursor: saving ? 'default' : 'pointer',
          }}
        >
          {saving ? (
            <ArrowPathIcon style={{ width: 15, height: 15, animation: 'spin 1s linear infinite' }} />
          ) : (
            <CheckIcon style={{ width: 15, height: 15 }} />
          )}
          {saving ? 'Saving…' : 'Save Rule'}
        </button>
      </div>
    </div>
  );
}

// ── Rule Detail View ──────────────────────────────────────────────────────────

interface RuleDetailProps {
  rule: AutomationRule;
  onEdit: () => void;
  onToggle: (enabled: boolean) => void;
  onRunNow: () => void;
  running: boolean;
}

function RuleDetail({ rule, onEdit, onToggle, onRunNow, running }: RuleDetailProps) {
  const TriggerIcon = TRIGGER_ICONS[rule.trigger.type] || BoltIcon;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{
        background: 'var(--bg-surface, #161b22)',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 10,
        padding: '16px 20px',
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, color: '#111827', margin: 0 }}>
              {rule.name || 'Untitled rule'}
            </h2>
            <p style={{ fontSize: 12, color: '#6B7280', marginTop: 6, lineHeight: 1.5 }}>
              {ruleNarrative(rule)}
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 12, color: '#6B7280' }}>{rule.enabled ? 'Enabled' : 'Disabled'}</span>
              <ToggleSwitch checked={rule.enabled} onChange={onToggle} />
            </div>
            <button
              onClick={onRunNow}
              disabled={running}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '7px 14px',
                fontSize: 12,
                fontWeight: 600,
                borderRadius: 7,
                border: '1px solid #D1D5DB',
                background: running ? 'var(--bg-surface-raised, #1c2128)' : 'var(--bg-surface, #161b22)',
                color: running ? '#9CA3AF' : '#374151',
                cursor: running ? 'default' : 'pointer',
              }}
            >
              {running
                ? <ArrowPathIcon style={{ width: 14, height: 14 }} />
                : <PlayIcon style={{ width: 14, height: 14 }} />}
              {running ? 'Running…' : 'Run Now'}
            </button>
            <button
              onClick={onEdit}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '7px 14px',
                fontSize: 12,
                fontWeight: 600,
                borderRadius: 7,
                border: 'none',
                background: '#006FFF',
                color: '#fff',
                cursor: 'pointer',
              }}
            >
              <PencilIcon style={{ width: 14, height: 14 }} />
              Edit
            </button>
          </div>
        </div>

        {rule.lastTriggered && (
          <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
            <ClockIcon style={{ width: 13, height: 13, color: '#9CA3AF' }} />
            <span style={{ fontSize: 11, color: '#9CA3AF' }}>
              Last triggered: {new Date(rule.lastTriggered).toLocaleString()}
            </span>
          </div>
        )}
      </div>

      {/* Trigger card */}
      <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ padding: '10px 16px', background: 'var(--bg-surface-raised, #1c2128)', borderBottom: '1px solid rgba(255,255,255,0.07)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <BoltIcon style={{ width: 14, height: 14, color: '#6366F1' }} />
          <span style={{ fontSize: 13, fontWeight: 600, color: '#374151' }}>Trigger</span>
        </div>
        <div style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8,
            background: 'rgba(0,111,255,0.15)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}>
            <TriggerIcon style={{ width: 18, height: 18, color: '#006FFF' }} />
          </div>
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: '#111827', margin: 0 }}>
              {triggerLabel(rule.trigger)}
            </p>
            {rule.trigger.type === 'schedule' && rule.trigger.cronExpression && (
              <p style={{ fontSize: 11, color: '#6B7280', margin: '2px 0 0' }}>
                Cron: <code style={{ fontFamily: 'monospace', background: '#F3F4F6', padding: '1px 4px', borderRadius: 3 }}>
                  {rule.trigger.cronExpression}
                </code>
              </p>
            )}
            {rule.trigger.type === 'device_enrolled' && rule.trigger.platformFilter && rule.trigger.platformFilter !== 'All platforms' && (
              <p style={{ fontSize: 11, color: '#6B7280', margin: '2px 0 0' }}>
                Platform: {rule.trigger.platformFilter}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Conditions card */}
      {rule.conditions.length > 0 && (
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '10px 16px', background: 'var(--bg-surface-raised, #1c2128)', borderBottom: '1px solid rgba(255,255,255,0.07)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <CheckIcon style={{ width: 14, height: 14, color: '#10B981' }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: '#374151' }}>
              Conditions
            </span>
            <span style={{ fontSize: 11, color: '#6B7280' }}>
              (joined by <strong>{rule.conditionJoin}</strong>)
            </span>
          </div>
          <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 6 }}>
            {rule.conditions.map((c, i) => (
              <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                {i > 0 && (
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#9CA3AF', padding: '0 4px' }}>
                    {rule.conditionJoin}
                  </span>
                )}
                <span style={{ fontSize: 12, fontFamily: 'monospace', background: '#F3F4F6', padding: '3px 8px', borderRadius: 5, color: '#374151' }}>
                  {c.attribute}
                </span>
                <span style={{ fontSize: 11, color: '#6B7280' }}>{c.operator.replace(/_/g, ' ')}</span>
                <span style={{ fontSize: 12, fontFamily: 'monospace', background: '#F0FDF4', padding: '3px 8px', borderRadius: 5, color: '#166534' }}>
                  {c.value || '""'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Actions card */}
      <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ padding: '10px 16px', background: 'var(--bg-surface-raised, #1c2128)', borderBottom: '1px solid rgba(255,255,255,0.07)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <PlayIcon style={{ width: 14, height: 14, color: '#F59E0B' }} />
          <span style={{ fontSize: 13, fontWeight: 600, color: '#374151' }}>Actions</span>
        </div>
        <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rule.actions.length === 0 && (
            <p style={{ fontSize: 12, color: '#9CA3AF', fontStyle: 'italic' }}>No actions configured.</p>
          )}
          {rule.actions.map((a, i) => (
            <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 20, height: 20, borderRadius: '50%',
                background: '#FEF3C7',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 10, fontWeight: 700, color: '#92400E', flexShrink: 0,
              }}>
                {i + 1}
              </div>
              <span style={{ fontSize: 12, color: '#374151' }}>{actionSummary(a)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Empty State ───────────────────────────────────────────────────────────────

function EmptyState({ onCreate }: { onCreate: () => void }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      height: '100%',
      textAlign: 'center',
      padding: 40,
    }}>
      <div style={{
        width: 64, height: 64,
        borderRadius: 16,
        background: 'rgba(0,111,255,0.15)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        marginBottom: 16,
      }}>
        <BoltIcon style={{ width: 30, height: 30, color: '#006FFF' }} />
      </div>
      <h3 style={{ fontSize: 16, fontWeight: 600, color: '#111827', margin: '0 0 8px' }}>
        No rule selected
      </h3>
      <p style={{ fontSize: 13, color: '#6B7280', maxWidth: 280, lineHeight: 1.6, margin: '0 0 20px' }}>
        Select a rule from the list or create a new one to get started with automation.
      </p>
      <button
        onClick={onCreate}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '9px 20px',
          fontSize: 13, fontWeight: 600,
          borderRadius: 8, border: 'none',
          background: '#006FFF', color: '#fff',
          cursor: 'pointer',
        }}
      >
        <PlusIcon style={{ width: 16, height: 16 }} />
        New Rule
      </button>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

function emptyRule(): AutomationRule {
  return {
    id: '',
    name: '',
    enabled: true,
    trigger: { type: 'device_enrolled', platformFilter: 'All platforms' },
    conditionJoin: 'AND',
    conditions: [],
    actions: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

export default function AutomationView() {
  const [rules, setRules] = useState<AutomationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [mode, setMode] = useState<'view' | 'edit' | 'create'>('view');
  const [editingRule, setEditingRule] = useState<AutomationRule | null>(null);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);

  // Load rules
  const loadRules = useCallback(async () => {
    try {
      const res = await fetch('/api/automation/rules');
      if (res.ok) {
        const data = await res.json();
        const list: AutomationRule[] = data.rules || data.data || data || [];
        setRules(list);
      }
    } catch {
      // If backend not available, show empty state gracefully
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const selectedRule = rules.find(r => r.id === selectedRuleId) ?? null;

  // Handlers
  const handleNewRule = () => {
    setEditingRule(emptyRule());
    setSelectedRuleId(null);
    setMode('create');
  };

  const handleEdit = (rule: AutomationRule) => {
    setEditingRule({ ...rule });
    setMode('edit');
  };

  const handleSelect = (rule: AutomationRule) => {
    if (mode === 'edit' || mode === 'create') return;
    setSelectedRuleId(rule.id);
    setMode('view');
  };

  const handleCancel = () => {
    setEditingRule(null);
    setMode('view');
  };

  const handleSave = async () => {
    if (!editingRule) return;
    if (!editingRule.name.trim()) { toast.error('Rule name is required'); return; }
    if (editingRule.actions.length === 0) { toast.error('Add at least one action'); return; }

    setSaving(true);
    try {
      const isNew = mode === 'create';
      const url = isNew ? '/api/automation/rules' : `/api/automation/rules/${editingRule.id}`;
      const method = isNew ? 'POST' : 'PUT';

      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(editingRule),
      });

      if (res.ok) {
        const data = await res.json();
        const saved: AutomationRule = data.rule || data;
        if (isNew) {
          setRules(prev => [saved, ...prev]);
          setSelectedRuleId(saved.id);
        } else {
          setRules(prev => prev.map(r => r.id === saved.id ? saved : r));
          setSelectedRuleId(saved.id);
        }
        toast.success(isNew ? 'Rule created!' : 'Rule saved!');
        setMode('view');
        setEditingRule(null);
      } else {
        // Fallback: optimistic update when backend not wired
        const fallback: AutomationRule = {
          ...editingRule,
          id: editingRule.id || generateId(),
          updatedAt: new Date().toISOString(),
          createdAt: editingRule.createdAt || new Date().toISOString(),
        };
        if (isNew) {
          setRules(prev => [fallback, ...prev]);
          setSelectedRuleId(fallback.id);
        } else {
          setRules(prev => prev.map(r => r.id === fallback.id ? fallback : r));
          setSelectedRuleId(fallback.id);
        }
        toast.success(isNew ? 'Rule created (local)' : 'Rule saved (local)');
        setMode('view');
        setEditingRule(null);
      }
    } catch {
      // Optimistic update on network error
      const fallback: AutomationRule = {
        ...editingRule,
        id: editingRule.id || generateId(),
        updatedAt: new Date().toISOString(),
        createdAt: editingRule.createdAt || new Date().toISOString(),
      };
      const isNew = mode === 'create';
      if (isNew) {
        setRules(prev => [fallback, ...prev]);
        setSelectedRuleId(fallback.id);
      } else {
        setRules(prev => prev.map(r => r.id === fallback.id ? fallback : r));
        setSelectedRuleId(fallback.id);
      }
      toast.success(isNew ? 'Rule created (local)' : 'Rule saved (local)');
      setMode('view');
      setEditingRule(null);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await fetch(`/api/automation/rules/${id}`, { method: 'DELETE' });
    } catch {}
    setRules(prev => prev.filter(r => r.id !== id));
    if (selectedRuleId === id) {
      setSelectedRuleId(null);
      setMode('view');
    }
    toast.success('Rule deleted');
  };

  const handleToggle = async (id: string, enabled: boolean) => {
    const endpoint = enabled ? `/api/automation/rules/${id}/enable` : `/api/automation/rules/${id}/disable`;
    try {
      await fetch(endpoint, { method: 'POST' });
    } catch {}
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled } : r));
  };

  const handleRunNow = async () => {
    if (!selectedRuleId) return;
    setRunning(true);
    try {
      await fetch(`/api/automation/rules/${selectedRuleId}/run`, { method: 'POST' });
      toast.success('Rule triggered!');
    } catch {
      toast('Rule triggered (simulated)', { icon: 'ℹ️' });
    } finally {
      setRunning(false);
    }
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
        <div style={{
          width: 32, height: 32, borderRadius: '50%',
          border: '3px solid #E5E7EB',
          borderTopColor: '#006FFF',
          animation: 'spin 0.8s linear infinite',
        }} />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', height: '100%', background: 'var(--bg-surface-raised, #1c2128)', overflow: 'hidden' }}>
      {/* Spinner keyframe */}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

      {/* Left Panel — Rule List (280px) */}
      <div style={{
        width: 280,
        flexShrink: 0,
        background: 'var(--bg-surface, #161b22)',
        borderRight: '1px solid rgba(255,255,255,0.07)',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        overflow: 'hidden',
      }}>
        {/* Panel header */}
        <div style={{
          padding: '14px 16px',
          borderBottom: '1px solid rgba(255,255,255,0.07)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'var(--bg-surface, #161b22)',
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <BoltIcon style={{ width: 18, height: 18, color: '#006FFF' }} />
            <span style={{ fontSize: 14, fontWeight: 700, color: '#111827' }}>Automation Rules</span>
          </div>
          <button
            onClick={handleNewRule}
            title="New Rule"
            style={{
              display: 'flex', alignItems: 'center', gap: 4,
              padding: '5px 10px',
              fontSize: 12, fontWeight: 600,
              borderRadius: 6, border: 'none',
              background: '#006FFF', color: '#fff',
              cursor: 'pointer',
            }}
          >
            <PlusIcon style={{ width: 13, height: 13 }} />
            New
          </button>
        </div>

        {/* Rule list */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {rules.length === 0 ? (
            <div style={{ padding: 20, textAlign: 'center' }}>
              <BoltIcon style={{ width: 28, height: 28, color: '#D1D5DB', margin: '0 auto 8px' }} />
              <p style={{ fontSize: 12, color: '#9CA3AF' }}>No automation rules yet.</p>
              <p style={{ fontSize: 12, color: '#9CA3AF' }}>Click "New" to create one.</p>
            </div>
          ) : (
            rules.map(rule => (
              <RuleListItem
                key={rule.id}
                rule={rule}
                isSelected={rule.id === selectedRuleId}
                onSelect={() => handleSelect(rule)}
                onToggle={(enabled) => handleToggle(rule.id, enabled)}
                onEdit={() => { handleSelect(rule); handleEdit(rule); }}
                onDelete={() => handleDelete(rule.id)}
              />
            ))
          )}
        </div>

        {/* Footer stats */}
        <div style={{
          padding: '10px 16px',
          borderTop: '1px solid rgba(255,255,255,0.07)',
          background: 'var(--bg-surface-raised, #1c2128)',
          flexShrink: 0,
        }}>
          <p style={{ fontSize: 11, color: '#9CA3AF', margin: 0 }}>
            {rules.length} rule{rules.length !== 1 ? 's' : ''} ·{' '}
            {rules.filter(r => r.enabled).length} active
          </p>
        </div>
      </div>

      {/* Right Panel — Editor / Detail / Empty */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 24, minWidth: 0 }}>
        {(mode === 'edit' || mode === 'create') && editingRule ? (
          <div style={{ maxWidth: 720 }}>
            <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{
                fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                letterSpacing: '0.05em', color: '#6B7280',
                background: '#F3F4F6', padding: '3px 8px', borderRadius: 4,
              }}>
                {mode === 'create' ? 'New Rule' : 'Edit Rule'}
              </span>
            </div>
            <RuleEditor
              rule={editingRule}
              onChange={setEditingRule}
              onSave={handleSave}
              onCancel={handleCancel}
              saving={saving}
            />
          </div>
        ) : selectedRule ? (
          <div style={{ maxWidth: 720 }}>
            <RuleDetail
              rule={selectedRule}
              onEdit={() => handleEdit(selectedRule)}
              onToggle={(enabled) => handleToggle(selectedRule.id, enabled)}
              onRunNow={handleRunNow}
              running={running}
            />
          </div>
        ) : (
          <EmptyState onCreate={handleNewRule} />
        )}
      </div>
    </div>
  );
}
