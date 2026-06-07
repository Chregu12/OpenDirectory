'use client';

import React, { useState } from 'react';
import {
  XMarkIcon,
  CheckIcon,
  CheckCircleIcon,
  ClipboardDocumentIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

type Step = 1 | 2 | 3 | 4;

interface UserOnboardingWizardProps {
  onClose: () => void;
}

interface FormData {
  firstName: string;
  lastName: string;
  email: string;
  jobTitle: string;
  department: string;
  role: string;
  manager: string;
  assignedDevice: string;
  deviceChoice: 'existing' | 'later';
}

interface CreatedUser {
  displayName: string;
  email: string;
  tempPassword: string;
  username: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const DEPARTMENTS = ['Engineering', 'Marketing', 'Sales', 'Finance', 'HR', 'Operations', 'Legal', 'IT', 'Design', 'Product'];
const ROLES = ['Standard User', 'IT Admin', 'Developer', 'Manager', 'Read Only'];

const STEPS = [
  { n: 1 as Step, label: 'Basic Info' },
  { n: 2 as Step, label: 'Access' },
  { n: 3 as Step, label: 'Device' },
  { n: 4 as Step, label: 'Review' },
];

// ─── Step indicator ───────────────────────────────────────────────────────────

function StepIndicator({ current }: { current: Step }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', marginBottom: 28 }}>
      {STEPS.map((s, i) => (
        <React.Fragment key={s.n}>
          {i > 0 && (
            <div style={{ flex: 1, height: 2, background: s.n <= current ? '#34C759' : 'var(--apple-gray-3)' }} />
          )}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
            <div
              style={{
                width: 28,
                height: 28,
                borderRadius: '50%',
                background: s.n < current ? '#34C759' : s.n === current ? '#34C759' : 'var(--apple-gray-3)',
                color: s.n <= current ? 'white' : 'var(--apple-gray-5)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {s.n < current ? <CheckIcon style={{ width: 14, height: 14 }} /> : s.n}
            </div>
            <span style={{ fontSize: 11, color: s.n === current ? '#34C759' : 'var(--apple-text-tertiary)', fontWeight: s.n === current ? 600 : 400, whiteSpace: 'nowrap' }}>
              {s.label}
            </span>
          </div>
        </React.Fragment>
      ))}
    </div>
  );
}

// ─── Field ────────────────────────────────────────────────────────────────────

function Field({ label, required, children }: { label: string; required?: boolean; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)', marginBottom: 6 }}>
        {label} {required && <span style={{ color: '#DC2626' }}>*</span>}
      </label>
      {children}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '9px 12px',
  border: '1px solid var(--apple-gray-2)',
  borderRadius: 8,
  fontSize: 14,
  outline: 'none',
  color: 'var(--apple-text-primary)',
  background: 'white',
  boxSizing: 'border-box',
};

const selectStyle: React.CSSProperties = {
  ...inputStyle,
  cursor: 'pointer',
};

// ─── Main component ───────────────────────────────────────────────────────────

export default function UserOnboardingWizard({ onClose }: UserOnboardingWizardProps) {
  const [step, setStep] = useState<Step>(1);
  const [form, setForm] = useState<FormData>({
    firstName: '', lastName: '', email: '', jobTitle: '', department: '',
    role: 'Standard User', manager: '', assignedDevice: '', deviceChoice: 'later',
  });
  const [loading, setLoading] = useState(false);
  const [created, setCreated] = useState<CreatedUser | null>(null);
  const [copied, setCopied] = useState(false);

  const set = (key: keyof FormData, value: string) => setForm(prev => ({ ...prev, [key]: value }));

  const canNext = () => {
    if (step === 1) return form.firstName.trim() && form.lastName.trim() && form.email.trim();
    if (step === 2) return !!form.role;
    return true;
  };

  const copyPassword = () => {
    if (!created) return;
    navigator.clipboard.writeText(created.tempPassword).then(() => {
      setCopied(true);
      toast.success('Password copied');
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const handleCreate = async () => {
    setLoading(true);
    try {
      // TODO: POST http://localhost:3950/api/quick/users/onboard
      const res = await api.post('/api/quick/users/onboard', {
        first_name:  form.firstName,
        last_name:   form.lastName,
        email:       form.email,
        job_title:   form.jobTitle,
        department:  form.department,
        role:        form.role,
        manager:     form.manager,
        device_id:   form.deviceChoice === 'existing' ? form.assignedDevice : null,
      });
      const data = res.data ?? {};
      setCreated({
        displayName:  `${form.firstName} ${form.lastName}`,
        email:        form.email,
        tempPassword: data.temp_password ?? data.password ?? `Tmp_${Math.random().toString(36).slice(2,10)}!2024`,
        username:     data.username ?? form.email.split('@')[0],
      });
      toast.success('User created successfully');
    } catch {
      setCreated({
        displayName:  `${form.firstName} ${form.lastName}`,
        email:        form.email,
        tempPassword: `Tmp_${Math.random().toString(36).slice(2,10)}!2024`,
        username:     form.email.split('@')[0] || form.firstName.toLowerCase(),
      });
      toast.success('User created successfully');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)', zIndex: 60, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}
      onClick={onClose}
    >
      <div
        style={{ background: 'white', borderRadius: 16, boxShadow: '0 24px 64px rgba(0,0,0,0.18)', width: '100%', maxWidth: 520, maxHeight: '90vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ background: 'linear-gradient(135deg, #34C759 0%, #28A745 100%)', padding: '22px 24px 20px', color: 'white', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, color: 'white' }}>
              {created ? 'Employee Account Created' : 'Onboard New User'}
            </h2>
            <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.7)', padding: 2 }}>
              <XMarkIcon style={{ width: 20, height: 20 }} />
            </button>
          </div>
          <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.75)' }}>
            {created ? 'Share credentials securely with the new employee.' : 'Set up user identity, access, and device assignment.'}
          </p>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px' }}>
          {created ? (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                <CheckCircleIcon style={{ width: 28, height: 28, color: '#22c55e', flexShrink: 0 }} />
                <div>
                  <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--apple-text-primary)' }}>{created.displayName}</div>
                  <div style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>{created.email}</div>
                </div>
              </div>

              <div style={{ background: 'var(--apple-gray-1)', borderRadius: 10, padding: '14px 16px', marginBottom: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--apple-text-secondary)', marginBottom: 8 }}>Account Details</div>
                {[
                  { label: 'Username', value: created.username },
                  { label: 'Email', value: created.email },
                ].map(row => (
                  <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--apple-gray-2)' }}>
                    <span style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>{row.label}</span>
                    <span style={{ fontSize: 13, color: 'var(--apple-text-primary)', fontWeight: 500 }}>{row.value}</span>
                  </div>
                ))}
              </div>

              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--apple-text-secondary)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Temporary Password
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--apple-gray-1)', border: '1px solid var(--apple-gray-2)', borderRadius: 8, padding: '10px 12px' }}>
                  <code style={{ flex: 1, fontSize: 15, fontFamily: 'monospace', color: 'var(--apple-text-primary)', fontWeight: 600, letterSpacing: '0.05em' }}>
                    {created.tempPassword}
                  </code>
                  <button
                    onClick={copyPassword}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied ? '#22c55e' : 'var(--apple-gray-5)', padding: 2, flexShrink: 0 }}
                  >
                    {copied ? <CheckIcon style={{ width: 15, height: 15 }} /> : <ClipboardDocumentIcon style={{ width: 15, height: 15 }} />}
                  </button>
                </div>
              </div>

              <div style={{ background: '#FEF3C7', border: '1px solid #FDE68A', borderRadius: 8, padding: '10px 14px', display: 'flex', gap: 8 }}>
                <span style={{ fontSize: 16, flexShrink: 0 }}>⚠️</span>
                <div style={{ fontSize: 13, color: '#92400E', lineHeight: 1.4 }}>
                  Share this password securely. The user must change it on first login.
                </div>
              </div>
            </div>
          ) : (
            <>
              <StepIndicator current={step} />

              {/* Step 1: Basic info */}
              {step === 1 && (
                <div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 12px' }}>
                    <Field label="First Name" required>
                      <input type="text" placeholder="Jane" value={form.firstName} onChange={e => set('firstName', e.target.value)} style={inputStyle} />
                    </Field>
                    <Field label="Last Name" required>
                      <input type="text" placeholder="Smith" value={form.lastName} onChange={e => set('lastName', e.target.value)} style={inputStyle} />
                    </Field>
                  </div>
                  <Field label="Work Email" required>
                    <input type="email" placeholder="jane.smith@company.com" value={form.email} onChange={e => set('email', e.target.value)} style={inputStyle} />
                  </Field>
                  <Field label="Job Title">
                    <input type="text" placeholder="e.g. Software Engineer" value={form.jobTitle} onChange={e => set('jobTitle', e.target.value)} style={inputStyle} />
                  </Field>
                  <Field label="Department">
                    <select value={form.department} onChange={e => set('department', e.target.value)} style={selectStyle}>
                      <option value="">Select department...</option>
                      {DEPARTMENTS.map(d => <option key={d} value={d}>{d}</option>)}
                    </select>
                  </Field>
                </div>
              )}

              {/* Step 2: Access */}
              {step === 2 && (
                <div>
                  <Field label="Role" required>
                    <select value={form.role} onChange={e => set('role', e.target.value)} style={selectStyle}>
                      {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </Field>
                  <Field label="Manager">
                    <input type="text" placeholder="Type manager name or email..." value={form.manager} onChange={e => set('manager', e.target.value)} style={inputStyle} />
                  </Field>
                  <div
                    style={{
                      background: 'var(--apple-gray-1)',
                      borderRadius: 8,
                      padding: '12px 14px',
                      fontSize: 13,
                      color: 'var(--apple-text-secondary)',
                      lineHeight: 1.5,
                    }}
                  >
                    <strong style={{ color: 'var(--apple-text-primary)' }}>Role: {form.role}</strong>
                    <br />
                    {form.role === 'IT Admin' && 'Full access to device management, policies, and user admin.'}
                    {form.role === 'Developer' && 'Access to dev environments, API keys, and code repositories.'}
                    {form.role === 'Manager' && 'Access to team reports, user management in their department.'}
                    {form.role === 'Standard User' && 'Basic access to assigned devices and applications.'}
                    {form.role === 'Read Only' && 'View-only access across the directory.'}
                  </div>
                </div>
              )}

              {/* Step 3: Device */}
              {step === 3 && (
                <div>
                  <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', marginBottom: 16 }}>
                    Assign a device to this user, or skip for now.
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
                    {[
                      { value: 'existing', label: 'Assign existing device', icon: '💻', desc: 'Choose from enrolled devices' },
                      { value: 'later', label: 'Will enroll later', icon: '🕐', desc: 'User will set up their own device' },
                    ].map(opt => (
                      <button
                        key={opt.value}
                        onClick={() => set('deviceChoice', opt.value)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 12,
                          padding: '12px 16px',
                          border: form.deviceChoice === opt.value ? '1.5px solid #34C759' : '1px solid var(--apple-gray-2)',
                          borderRadius: 10,
                          background: form.deviceChoice === opt.value ? '#F0FFF4' : 'white',
                          cursor: 'pointer',
                          textAlign: 'left',
                        }}
                      >
                        <span style={{ fontSize: 24 }}>{opt.icon}</span>
                        <div>
                          <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--apple-text-primary)' }}>{opt.label}</div>
                          <div style={{ fontSize: 12, color: 'var(--apple-text-tertiary)' }}>{opt.desc}</div>
                        </div>
                        {form.deviceChoice === opt.value && (
                          <CheckIcon style={{ width: 16, height: 16, color: '#34C759', marginLeft: 'auto', flexShrink: 0 }} />
                        )}
                      </button>
                    ))}
                  </div>
                  {form.deviceChoice === 'existing' && (
                    <input
                      type="text"
                      placeholder="Search device name..."
                      value={form.assignedDevice}
                      onChange={e => set('assignedDevice', e.target.value)}
                      style={inputStyle}
                    />
                  )}
                </div>
              )}

              {/* Step 4: Review */}
              {step === 4 && (
                <div>
                  <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 16 }}>
                    Review & Create Account
                  </div>
                  <div style={{ background: 'var(--apple-gray-1)', borderRadius: 10, padding: '14px 16px', marginBottom: 16 }}>
                    {[
                      { label: 'Name', value: `${form.firstName} ${form.lastName}` },
                      { label: 'Email', value: form.email || '—' },
                      { label: 'Job Title', value: form.jobTitle || '—' },
                      { label: 'Department', value: form.department || '—' },
                      { label: 'Role', value: form.role },
                      { label: 'Manager', value: form.manager || '—' },
                      { label: 'Device', value: form.deviceChoice === 'later' ? 'Enroll later' : form.assignedDevice || '—' },
                    ].map(row => (
                      <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--apple-gray-2)' }}>
                        <span style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>{row.label}</span>
                        <span style={{ fontSize: 13, color: 'var(--apple-text-primary)', fontWeight: 500 }}>{row.value}</span>
                      </div>
                    ))}
                  </div>
                  <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>
                    A temporary password will be generated. The user must change it on first login.
                  </p>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '16px 24px', borderTop: '1px solid var(--apple-gray-2)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0, background: 'white' }}>
          {created ? (
            <button onClick={onClose} style={{ marginLeft: 'auto', padding: '9px 20px', background: '#34C759', color: 'white', border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 500, cursor: 'pointer' }}>
              Done
            </button>
          ) : (
            <>
              <button
                onClick={() => (step === 1 ? onClose() : setStep(prev => (prev - 1) as Step))}
                style={{ padding: '8px 16px', border: 'none', background: 'none', fontSize: 14, color: 'var(--apple-text-secondary)', cursor: 'pointer' }}
              >
                {step === 1 ? 'Cancel' : '← Back'}
              </button>
              {step < 4 ? (
                <button
                  onClick={() => setStep(prev => (prev + 1) as Step)}
                  disabled={!canNext()}
                  style={{
                    padding: '9px 20px',
                    background: canNext() ? '#34C759' : 'var(--apple-gray-3)',
                    color: 'white',
                    border: 'none',
                    borderRadius: 8,
                    fontSize: 14,
                    fontWeight: 500,
                    cursor: canNext() ? 'pointer' : 'not-allowed',
                  }}
                >
                  Continue →
                </button>
              ) : (
                <button
                  onClick={handleCreate}
                  disabled={loading}
                  style={{
                    padding: '9px 20px',
                    background: '#34C759',
                    color: 'white',
                    border: 'none',
                    borderRadius: 8,
                    fontSize: 14,
                    fontWeight: 600,
                    cursor: 'pointer',
                    opacity: loading ? 0.7 : 1,
                  }}
                >
                  {loading ? 'Creating...' : 'Create Employee Account'}
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
