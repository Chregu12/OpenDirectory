'use client';

import React from 'react';
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

// ── Color Maps ─────────────────────────────────────────────────────────────────

const COLOR_MAP: Record<WizardColor, {
  gradient: string;
  subtitleText: string;
  stepDone: string;
  stepDoneText: string;
  stepActive: string;
  stepActiveRing: string;
  stepInactive: string;
  stepInactiveText: string;
  lineDone: string;
  lineInactive: string;
  labelActive: string;
  labelInactive: string;
  button: string;
  buttonHover: string;
}> = {
  blue:    { gradient: 'from-blue-600 to-blue-700',     subtitleText: 'text-blue-200',    stepDone: 'bg-blue-300',    stepDoneText: 'text-blue-800',    stepActive: 'bg-white text-blue-700',    stepActiveRing: 'ring-blue-300',    stepInactive: 'bg-blue-500/40',    stepInactiveText: 'text-blue-200',    lineDone: 'bg-blue-300',    lineInactive: 'bg-blue-500/40',    labelActive: 'text-white',    labelInactive: 'text-blue-200',    button: 'bg-blue-600',    buttonHover: 'hover:bg-blue-700' },
  green:   { gradient: 'from-green-600 to-green-700',   subtitleText: 'text-green-200',   stepDone: 'bg-green-300',   stepDoneText: 'text-green-800',   stepActive: 'bg-white text-green-700',   stepActiveRing: 'ring-green-300',   stepInactive: 'bg-green-500/40',   stepInactiveText: 'text-green-200',   lineDone: 'bg-green-300',   lineInactive: 'bg-green-500/40',   labelActive: 'text-white',   labelInactive: 'text-green-200',   button: 'bg-green-600',   buttonHover: 'hover:bg-green-700' },
  emerald: { gradient: 'from-emerald-600 to-green-600', subtitleText: 'text-emerald-100', stepDone: 'bg-emerald-300', stepDoneText: 'text-emerald-800', stepActive: 'bg-white text-emerald-700', stepActiveRing: 'ring-emerald-300', stepInactive: 'bg-emerald-500/40', stepInactiveText: 'text-emerald-200', lineDone: 'bg-emerald-300', lineInactive: 'bg-emerald-500/40', labelActive: 'text-white', labelInactive: 'text-emerald-200', button: 'bg-emerald-600', buttonHover: 'hover:bg-emerald-700' },
  cyan:    { gradient: 'from-cyan-600 to-teal-600',     subtitleText: 'text-cyan-100',    stepDone: 'bg-cyan-300',    stepDoneText: 'text-cyan-800',    stepActive: 'bg-white text-cyan-700',    stepActiveRing: 'ring-cyan-300',    stepInactive: 'bg-cyan-500/40',    stepInactiveText: 'text-cyan-200',    lineDone: 'bg-cyan-300',    lineInactive: 'bg-cyan-500/40',    labelActive: 'text-white',    labelInactive: 'text-cyan-200',    button: 'bg-cyan-600',    buttonHover: 'hover:bg-cyan-700' },
  teal:    { gradient: 'from-teal-600 to-emerald-600',  subtitleText: 'text-teal-100',    stepDone: 'bg-teal-300',    stepDoneText: 'text-teal-800',    stepActive: 'bg-white text-teal-700',    stepActiveRing: 'ring-teal-300',    stepInactive: 'bg-teal-500/40',    stepInactiveText: 'text-teal-200',    lineDone: 'bg-teal-300',    lineInactive: 'bg-teal-500/40',    labelActive: 'text-white',    labelInactive: 'text-teal-200',    button: 'bg-teal-600',    buttonHover: 'hover:bg-teal-700' },
  indigo:  { gradient: 'from-indigo-600 to-purple-600', subtitleText: 'text-indigo-200',  stepDone: 'bg-indigo-300',  stepDoneText: 'text-indigo-800',  stepActive: 'bg-white text-indigo-700',  stepActiveRing: 'ring-indigo-300',  stepInactive: 'bg-indigo-500/40',  stepInactiveText: 'text-indigo-200',  lineDone: 'bg-indigo-300',  lineInactive: 'bg-indigo-500/40',  labelActive: 'text-white',  labelInactive: 'text-indigo-200',  button: 'bg-indigo-600',  buttonHover: 'hover:bg-indigo-700' },
  purple:  { gradient: 'from-purple-600 to-violet-600', subtitleText: 'text-purple-200',  stepDone: 'bg-purple-300',  stepDoneText: 'text-purple-800',  stepActive: 'bg-white text-purple-700',  stepActiveRing: 'ring-purple-300',  stepInactive: 'bg-purple-500/40',  stepInactiveText: 'text-purple-200',  lineDone: 'bg-purple-300',  lineInactive: 'bg-purple-500/40',  labelActive: 'text-white',  labelInactive: 'text-purple-200',  button: 'bg-purple-600',  buttonHover: 'hover:bg-purple-700' },
  violet:  { gradient: 'from-violet-600 to-purple-600', subtitleText: 'text-violet-200',  stepDone: 'bg-violet-300',  stepDoneText: 'text-violet-800',  stepActive: 'bg-white text-violet-700',  stepActiveRing: 'ring-violet-300',  stepInactive: 'bg-violet-500/40',  stepInactiveText: 'text-violet-200',  lineDone: 'bg-violet-300',  lineInactive: 'bg-violet-500/40',  labelActive: 'text-white',  labelInactive: 'text-violet-200',  button: 'bg-violet-600',  buttonHover: 'hover:bg-violet-700' },
  red:     { gradient: 'from-red-600 to-rose-600',      subtitleText: 'text-red-100',     stepDone: 'bg-red-300',     stepDoneText: 'text-red-800',     stepActive: 'bg-white text-red-700',     stepActiveRing: 'ring-red-300',     stepInactive: 'bg-red-500/40',     stepInactiveText: 'text-red-200',     lineDone: 'bg-red-300',     lineInactive: 'bg-red-500/40',     labelActive: 'text-white',     labelInactive: 'text-red-200',     button: 'bg-red-600',     buttonHover: 'hover:bg-red-700' },
  rose:    { gradient: 'from-rose-600 to-pink-600',     subtitleText: 'text-rose-200',    stepDone: 'bg-rose-300',    stepDoneText: 'text-rose-800',    stepActive: 'bg-white text-rose-700',    stepActiveRing: 'ring-rose-300',    stepInactive: 'bg-rose-500/40',    stepInactiveText: 'text-rose-200',    lineDone: 'bg-rose-300',    lineInactive: 'bg-rose-500/40',    labelActive: 'text-white',    labelInactive: 'text-rose-200',    button: 'bg-rose-600',    buttonHover: 'hover:bg-rose-700' },
  orange:  { gradient: 'from-orange-500 to-red-500',    subtitleText: 'text-orange-200',  stepDone: 'bg-orange-300',  stepDoneText: 'text-orange-800',  stepActive: 'bg-white text-orange-700',  stepActiveRing: 'ring-orange-300',  stepInactive: 'bg-orange-500/40',  stepInactiveText: 'text-orange-200',  lineDone: 'bg-orange-300',  lineInactive: 'bg-orange-500/40',  labelActive: 'text-white',  labelInactive: 'text-orange-200',  button: 'bg-orange-600',  buttonHover: 'hover:bg-orange-700' },
  amber:   { gradient: 'from-amber-500 to-orange-500',  subtitleText: 'text-amber-200',   stepDone: 'bg-amber-300',   stepDoneText: 'text-amber-800',   stepActive: 'bg-white text-amber-700',   stepActiveRing: 'ring-amber-300',   stepInactive: 'bg-amber-500/40',   stepInactiveText: 'text-amber-200',   lineDone: 'bg-amber-300',   lineInactive: 'bg-amber-500/40',   labelActive: 'text-white',   labelInactive: 'text-amber-200',   button: 'bg-amber-600',   buttonHover: 'hover:bg-amber-700' },
};

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
  const c = COLOR_MAP[color];
  const maxStep = Math.max(...steps.map(s => s.n));
  const isLastStep = currentStep >= maxStep;

  return (
    <div className="fixed inset-0 bg-gray-900/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className={`bg-white rounded-2xl shadow-2xl w-full ${maxWidth} max-h-[90vh] flex flex-col overflow-hidden`}>

        {/* ── Header ──────────────────────────────────────────────────────── */}
        <div className={`bg-gradient-to-r ${c.gradient} px-8 py-6 text-white relative`}>
          {/* Close */}
          <button onClick={onClose} className="absolute top-4 right-4 text-white/70 hover:text-white">
            <XMarkIcon className="h-6 w-6" />
          </button>

          {/* Title */}
          <div className="flex items-center gap-3 mb-2">
            {icon}
            <h2 className="text-2xl font-bold">{title}</h2>
          </div>
          <p className={`${c.subtitleText} text-sm`}>{subtitle}</p>

          {/* Stepper */}
          <div className="flex items-center gap-2 mt-6">
            {steps.map((s, i) => (
              <React.Fragment key={s.n}>
                {i > 0 && (
                  <div className={`flex-1 h-0.5 ${s.n <= currentStep ? c.lineDone : c.lineInactive}`} />
                )}
                <div className="flex flex-col items-center gap-1">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold transition-all ${
                    s.n < currentStep
                      ? `${c.stepDone} ${c.stepDoneText}`
                      : s.n === currentStep
                      ? `${c.stepActive} ring-4 ${c.stepActiveRing}`
                      : `${c.stepInactive} ${c.stepInactiveText}`
                  }`}>
                    {s.n < currentStep ? <CheckIcon className="h-4 w-4" /> : s.n}
                  </div>
                  <span className={`text-xs whitespace-nowrap ${s.n === currentStep ? `${c.labelActive} font-medium` : c.labelInactive}`}>
                    {s.label}
                  </span>
                </div>
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* ── Content ─────────────────────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto p-8">
          {children}
        </div>

        {/* ── Footer ──────────────────────────────────────────────────────── */}
        <div className="border-t border-gray-200 px-8 py-4 flex items-center justify-between bg-gray-50">
          <button
            onClick={() => currentStep === steps[0].n ? onClose() : onStepChange(currentStep - 1)}
            className="flex items-center gap-2 px-4 py-2 text-sm text-gray-600 hover:text-gray-900 transition-colors"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            {currentStep === steps[0].n ? 'Abbrechen' : 'Zurück'}
          </button>

          {!isLastStep ? (
            <button
              onClick={() => onStepChange(currentStep + 1)}
              className={`flex items-center gap-2 px-6 py-2.5 ${c.button} text-white rounded-lg ${c.buttonHover} transition-colors text-sm font-medium`}
            >
              Weiter <ArrowRightIcon className="h-4 w-4" />
            </button>
          ) : (
            <button
              onClick={onComplete}
              disabled={saving}
              className={`flex items-center gap-2 px-6 py-2.5 ${c.button} text-white rounded-lg ${c.buttonHover} transition-colors text-sm font-medium disabled:opacity-50`}
            >
              {saving ? (
                <>
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
                  {savingLabel}
                </>
              ) : (
                <>
                  <CheckIcon className="h-4 w-4" />
                  {completeLabel}
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
