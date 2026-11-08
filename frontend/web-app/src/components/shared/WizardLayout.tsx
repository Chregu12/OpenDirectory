'use client';

import React from 'react';
import { Dialog } from '@headlessui/react';
import {
  CheckIcon,
  ArrowRightIcon,
  ArrowLeftIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';

// ── Types ──────────────────────────────────────────────────────────────────────

export interface WizardStep {
  n: number;
  label: string;
}

export type WizardColor =
  | 'blue' | 'green' | 'emerald' | 'cyan' | 'teal'
  | 'indigo' | 'purple' | 'violet' | 'red' | 'rose'
  | 'orange' | 'amber';

export interface WizardLayoutProps {
  /** Title displayed in the header */
  title: string;
  /** Subtitle displayed below the title */
  subtitle: string;
  /** Icon component displayed next to the title */
  icon?: React.ReactNode;
  /** Primary color theme */
  color: WizardColor;
  /** Step definitions */
  steps: WizardStep[];
  /** Current active step number */
  currentStep: number;
  /** Called when the step changes (back/next) */
  onStepChange: (step: number) => void;
  /** Called when the wizard is closed */
  onClose: () => void;
  /** Called when the final step's action button is clicked */
  onComplete: () => void;
  /** Whether the complete action is in progress */
  saving?: boolean;
  /** Label for the final action button */
  completeLabel?: string;
  /** Label shown while saving */
  savingLabel?: string;
  /** Max width class (default: max-w-4xl) */
  maxWidth?: string;
  /** Step content - rendered in the scrollable area */
  children: React.ReactNode;
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function WizardLayout({
  title,
  subtitle,
  icon,
  color,
  steps,
  currentStep,
  onStepChange,
  onClose,
  onComplete,
  saving = false,
  completeLabel = 'Fertig',
  savingLabel = 'Speichern...',
  maxWidth = 'max-w-4xl',
  children,
}: WizardLayoutProps) {
  const maxStep = Math.max(...steps.map(s => s.n));
  const isLastStep = currentStep >= maxStep;

  return <Dialog open onClose={() => { if (!saving) onClose(); }} className="od-modal-frame" aria-label={title}>
    <Dialog.Panel className={`od-modal-panel ${maxWidth} !p-0 flex flex-col`}>
      <header className="p-5 sm:p-6 border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-start justify-between gap-4"><div>
          <div className="flex items-center gap-3">{icon}<Dialog.Title className="text-xl font-semibold">{title}</Dialog.Title></div>
          <p className="mt-2 text-sm" style={{ color: 'var(--text-secondary)' }}>{subtitle}</p>
        </div><button type="button" disabled={saving} onClick={onClose} aria-label="Assistent schliessen"><XMarkIcon className="h-5 w-5" /></button></div>
        <ol aria-label="Fortschritt" className="flex flex-wrap gap-x-6 gap-y-3 mt-6">
          {steps.map(step => <li key={step.n} aria-current={step.n === currentStep ? 'step' : undefined} className="flex items-center gap-2 text-sm"
            style={{ color: step.n === currentStep ? 'var(--text-primary)' : 'var(--text-secondary)', fontWeight: step.n === currentStep ? 600 : 400 }}>
            <span className="od-badge">{step.n < currentStep ? <><CheckIcon className="h-4 w-4" /><span className="sr-only">Abgeschlossen:</span></> : step.n}</span>{step.label}
          </li>)}
        </ol>
      </header>
      <div className="flex-1 overflow-y-auto p-5 sm:p-6">{children}</div>
      <footer className="border-t p-5 sm:p-6 flex flex-wrap items-center justify-between gap-3" style={{ borderColor: 'var(--border)' }}>
        <button type="button" disabled={saving} onClick={() => currentStep === steps[0].n ? onClose() : onStepChange(currentStep - 1)} className="fluent-btn-secondary">
          <ArrowLeftIcon className="h-4 w-4" />{currentStep === steps[0].n ? 'Abbrechen' : 'Zurück'}
        </button>
        <button type="button" disabled={saving} onClick={isLastStep ? onComplete : () => onStepChange(currentStep + 1)} className="fluent-btn-primary">
          {saving ? savingLabel : isLastStep ? completeLabel : 'Weiter'}{!isLastStep && <ArrowRightIcon className="h-4 w-4" />}
        </button>
      </footer>
    </Dialog.Panel>
  </Dialog>;
}
