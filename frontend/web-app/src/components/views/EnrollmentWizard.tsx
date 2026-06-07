'use client';

import React, { useState } from 'react';
import {
  CheckCircleIcon,
  XMarkIcon,
  ClipboardDocumentIcon,
  CheckIcon,
} from '@heroicons/react/24/outline';
import { qaPost, EnrollDeviceResult } from '@/lib/quickActionsApi';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

type Platform = 'macos' | 'windows' | 'linux' | 'ios' | 'android';
type Step = 1 | 2 | 3 | 4;

interface EnrollmentWizardProps {
  onClose: () => void;
}

interface FormData {
  platform: Platform | null;
  deviceName: string;
  serial: string;
  assignedUser: string;
  ou: string;
}

// ─── Platform data ─────────────────────────────────────────────────────────────

const PLATFORMS = [
  { id: 'macos' as Platform,   icon: '🍎', label: 'macOS',   desc: 'Ventura, Sonoma, Sequoia' },
  { id: 'windows' as Platform, icon: '🪟', label: 'Windows', desc: 'Windows 10/11, Server' },
  { id: 'linux' as Platform,   icon: '🐧', label: 'Linux',   desc: 'Ubuntu, Debian, RHEL' },
  { id: 'ios' as Platform,     icon: '📱', label: 'iOS',     desc: 'iPhone, iPad (15+)' },
  { id: 'android' as Platform, icon: '🤖', label: 'Android', desc: 'Android 12+' },
];

const SAMPLE_OUS = [
  'OU=Workstations,DC=corp,DC=local',
  'OU=Laptops,DC=corp,DC=local',
  'OU=Servers,DC=corp,DC=local',
  'OU=Mobile,DC=corp,DC=local',
  'OU=IOT,DC=corp,DC=local',
];

// ─── Step indicator ───────────────────────────────────────────────────────────

const STEPS = [
  { n: 1 as Step, label: 'Platform' },
  { n: 2 as Step, label: 'Details' },
  { n: 3 as Step, label: 'Placement' },
  { n: 4 as Step, label: 'Confirm' },
];

function StepIndicator({ current }: { current: Step }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 28 }}>
      {STEPS.map((s, i) => (
        <React.Fragment key={s.n}>
          {i > 0 && (
            <div
              style={{
                flex: 1,
                height: 2,
                background: s.n <= current ? '#0071E3' : 'var(--apple-gray-3)',
              }}
            />
          )}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
            <div
              style={{
                width: 28,
                height: 28,
                borderRadius: '50%',
                background: s.n < current ? '#0071E3' : s.n === current ? '#0071E3' : 'var(--apple-gray-3)',
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
            <span
              style={{
                fontSize: 11,
                color: s.n === current ? '#0071E3' : 'var(--apple-text-tertiary)',
                fontWeight: s.n === current ? 600 : 400,
                whiteSpace: 'nowrap',
              }}
            >
              {s.label}
            </span>
          </div>
        </React.Fragment>
      ))}
    </div>
  );
}

// ─── CopyField ────────────────────────────────────────────────────────────────

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 11, color: 'var(--apple-text-secondary)', marginBottom: 4 }}>{label}</div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          background: 'var(--apple-gray-1)',
          border: '1px solid var(--apple-gray-2)',
          borderRadius: 8,
          padding: '8px 12px',
        }}
      >
        <code style={{ flex: 1, fontSize: 13, fontFamily: 'monospace', color: 'var(--apple-text-primary)', wordBreak: 'break-all' }}>
          {value}
        </code>
        <button
          onClick={copy}
          style={{
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: copied ? '#22c55e' : 'var(--apple-gray-5)',
            padding: 2,
            flexShrink: 0,
          }}
        >
          {copied
            ? <CheckIcon style={{ width: 15, height: 15 }} />
            : <ClipboardDocumentIcon style={{ width: 15, height: 15 }} />}
        </button>
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function EnrollmentWizard({ onClose }: EnrollmentWizardProps) {
  const [step, setStep]       = useState<Step>(1);
  const [form, setForm]       = useState<FormData>({ platform: null, deviceName: '', serial: '', assignedUser: '', ou: SAMPLE_OUS[0] });
  const [loading, setLoading]       = useState(false);
  const [token, setToken]           = useState<string | null>(null);
  const [enrollResult, setEnrollResult] = useState<EnrollDeviceResult | null>(null);

  const set = (key: keyof FormData, value: string | Platform | null) =>
    setForm(prev => ({ ...prev, [key]: value }));

  const canNext = () => {
    if (step === 1) return form.platform !== null;
    if (step === 2) return form.deviceName.trim().length > 0;
    return true;
  };

  const handleEnroll = async () => {
    setLoading(true);
    try {
      const result = await qaPost<EnrollDeviceResult>('/api/quick/devices/enroll', {
        platform:       form.platform,
        deviceName:     form.deviceName,
        serialNumber:   form.serial || undefined,
        assignedUserId: form.assignedUser || undefined,
        ouDn:           form.ou || undefined,
      });
      setEnrollResult(result);
      // Use enrollmentUrl or deviceId as the display token
      setToken(result.enrollmentUrl ?? result.deviceId ?? '');
      // Notify device list to refresh
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('device-enrolled', { detail: result }));
      }
      toast.success('Device enrolled successfully');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Enrollment failed');
    } finally {
      setLoading(false);
    }
  };

  const getInstructions = (platform: Platform, tok: string) => {
    switch (platform) {
      case 'macos':
        return [
          'Open System Preferences → Privacy & Security → Profiles',
          'Click "Install OpenDirectory Profile"',
          `Enter the enrollment token when prompted: ${tok}`,
        ];
      case 'windows':
        return [
          'Open PowerShell as Administrator',
          `Run: odm-enroll.ps1 -Token ${tok}`,
          'Follow the on-screen setup wizard',
        ];
      case 'linux':
        return [
          `curl -s https://mdm.opendirectory.local/enroll | sudo bash -s -- --token ${tok}`,
          'Restart the OpenDirectory agent: sudo systemctl restart od-agent',
        ];
      case 'ios':
        return [
          'Open the OpenDirectory app on your iPhone/iPad',
          'Tap "Enroll" and scan the QR code below',
          'Follow the profile installation prompt',
        ];
      case 'android':
        return [
          'Open the OpenDirectory app on your Android device',
          'Tap "Enroll" and scan the QR code below',
          'Accept the device management profile',
        ];
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        backdropFilter: 'blur(4px)',
        zIndex: 60,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'white',
          borderRadius: 16,
          boxShadow: '0 24px 64px rgba(0,0,0,0.18)',
          width: '100%',
          maxWidth: 560,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            background: 'linear-gradient(135deg, #0071E3 0%, #0055B3 100%)',
            padding: '22px 24px 20px',
            color: 'white',
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, color: 'white' }}>Enroll a New Device</h2>
            <button
              onClick={onClose}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.7)', padding: 2 }}
            >
              <XMarkIcon style={{ width: 20, height: 20 }} />
            </button>
          </div>
          <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.75)' }}>
            Add a device to OpenDirectory management
          </p>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px 24px 0' }}>
          {token ? (
            /* Success state */
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 48, marginBottom: 12 }}>
                <CheckCircleIcon style={{ width: 56, height: 56, color: '#22c55e', margin: '0 auto' }} />
              </div>
              <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--apple-text-primary)', marginBottom: 6 }}>
                Device Enrolled!
              </h3>
              <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', marginBottom: 20 }}>
                Complete setup on your {PLATFORMS.find(p => p.id === form.platform)?.label} device:
              </p>

              {enrollResult?.deviceId && (
                <CopyField label="Device ID" value={enrollResult.deviceId} />
              )}
              {token && <CopyField label="Enrollment URL / Token" value={token} />}

              {form.platform && (
                <div
                  style={{
                    background: 'var(--apple-gray-1)',
                    borderRadius: 10,
                    padding: '14px 16px',
                    textAlign: 'left',
                    marginTop: 12,
                    marginBottom: 20,
                  }}
                >
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--apple-text-secondary)', marginBottom: 10 }}>
                    Setup Instructions
                  </div>
                  <ol style={{ margin: 0, paddingLeft: 18 }}>
                    {(enrollResult?.nextSteps?.length
                      ? enrollResult.nextSteps
                      : getInstructions(form.platform, token ?? '')
                    ).map((s, i) => (
                      <li key={i} style={{ fontSize: 13, color: 'var(--apple-text-primary)', marginBottom: 6, lineHeight: 1.4 }}>
                        {s}
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {(form.platform === 'ios' || form.platform === 'android') && (
                <div
                  style={{
                    background: 'var(--apple-gray-1)',
                    borderRadius: 10,
                    padding: '16px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginBottom: 20,
                  }}
                >
                  <div
                    style={{
                      width: 100,
                      height: 100,
                      background: '#1D1D1F',
                      borderRadius: 8,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: 'white',
                      fontSize: 11,
                    }}
                  >
                    QR Code
                  </div>
                </div>
              )}
            </div>
          ) : (
            <>
              <StepIndicator current={step} />

              {/* Step 1: Platform */}
              {step === 1 && (
                <div>
                  <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 16 }}>
                    Choose a platform
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
                    {PLATFORMS.map(p => (
                      <button
                        key={p.id}
                        onClick={() => set('platform', p.id)}
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          gap: 8,
                          padding: '16px 8px',
                          border: form.platform === p.id ? '2px solid #0071E3' : '1.5px solid var(--apple-gray-2)',
                          borderRadius: 12,
                          background: form.platform === p.id ? 'var(--apple-blue-light)' : 'white',
                          cursor: 'pointer',
                          transition: 'all 0.15s',
                        }}
                      >
                        <span style={{ fontSize: 28 }}>{p.icon}</span>
                        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--apple-text-primary)' }}>{p.label}</span>
                        <span style={{ fontSize: 10, color: 'var(--apple-text-tertiary)', textAlign: 'center', lineHeight: 1.3 }}>{p.desc}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Step 2: Device details */}
              {step === 2 && (
                <div>
                  <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 16 }}>
                    Device Details
                  </h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                    <div>
                      <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)', marginBottom: 6 }}>
                        Device Name <span style={{ color: '#DC2626' }}>*</span>
                      </label>
                      <input
                        type="text"
                        placeholder="e.g. MBA-johndoe"
                        value={form.deviceName}
                        onChange={e => set('deviceName', e.target.value)}
                        style={{
                          width: '100%',
                          padding: '9px 12px',
                          border: '1px solid var(--apple-gray-2)',
                          borderRadius: 8,
                          fontSize: 14,
                          outline: 'none',
                          color: 'var(--apple-text-primary)',
                        }}
                      />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)', marginBottom: 6 }}>
                        Serial Number <span style={{ color: 'var(--apple-text-tertiary)', fontWeight: 400 }}>(optional)</span>
                      </label>
                      <input
                        type="text"
                        placeholder="e.g. C02XG2JHJGH5"
                        value={form.serial}
                        onChange={e => set('serial', e.target.value)}
                        style={{
                          width: '100%',
                          padding: '9px 12px',
                          border: '1px solid var(--apple-gray-2)',
                          borderRadius: 8,
                          fontSize: 14,
                          outline: 'none',
                          color: 'var(--apple-text-primary)',
                        }}
                      />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)', marginBottom: 6 }}>
                        Assign to User <span style={{ color: 'var(--apple-text-tertiary)', fontWeight: 400 }}>(optional)</span>
                      </label>
                      <input
                        type="text"
                        placeholder="Type a username or email..."
                        value={form.assignedUser}
                        onChange={e => set('assignedUser', e.target.value)}
                        style={{
                          width: '100%',
                          padding: '9px 12px',
                          border: '1px solid var(--apple-gray-2)',
                          borderRadius: 8,
                          fontSize: 14,
                          outline: 'none',
                          color: 'var(--apple-text-primary)',
                        }}
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Step 3: OU placement */}
              {step === 3 && (
                <div>
                  <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 16 }}>
                    Organisational Unit Placement
                  </h3>
                  <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', marginBottom: 16 }}>
                    Select which OU this device should be placed in:
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {SAMPLE_OUS.map(ou => (
                      <button
                        key={ou}
                        onClick={() => set('ou', ou)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 10,
                          padding: '10px 14px',
                          border: form.ou === ou ? '1.5px solid #0071E3' : '1px solid var(--apple-gray-2)',
                          borderRadius: 8,
                          background: form.ou === ou ? 'var(--apple-blue-light)' : 'white',
                          cursor: 'pointer',
                          textAlign: 'left',
                        }}
                      >
                        <span style={{ fontSize: 16 }}>📁</span>
                        <span style={{ fontSize: 13, fontFamily: 'monospace', color: 'var(--apple-text-primary)' }}>{ou}</span>
                        {form.ou === ou && (
                          <CheckIcon style={{ width: 15, height: 15, color: '#0071E3', marginLeft: 'auto' }} />
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Step 4: Confirm */}
              {step === 4 && (
                <div>
                  <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 16 }}>
                    Confirm Enrollment
                  </h3>
                  <div
                    style={{
                      background: 'var(--apple-gray-1)',
                      borderRadius: 10,
                      padding: '14px 16px',
                      marginBottom: 16,
                    }}
                  >
                    {[
                      { label: 'Platform', value: PLATFORMS.find(p => p.id === form.platform)?.icon + ' ' + PLATFORMS.find(p => p.id === form.platform)?.label },
                      { label: 'Device Name', value: form.deviceName },
                      { label: 'Serial', value: form.serial || '—' },
                      { label: 'Assigned User', value: form.assignedUser || '—' },
                      { label: 'OU Placement', value: form.ou },
                    ].map(row => (
                      <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--apple-gray-2)' }}>
                        <span style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>{row.label}</span>
                        <span style={{ fontSize: 13, color: 'var(--apple-text-primary)', fontWeight: 500, textAlign: 'right', maxWidth: '60%', wordBreak: 'break-all' }}>
                          {row.value}
                        </span>
                      </div>
                    ))}
                  </div>
                  <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>
                    An enrollment token will be generated. Use it to complete device-side setup.
                  </p>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '16px 24px',
            borderTop: '1px solid var(--apple-gray-2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexShrink: 0,
            background: 'white',
          }}
        >
          {token ? (
            <button
              onClick={onClose}
              style={{
                marginLeft: 'auto',
                padding: '9px 20px',
                background: '#0071E3',
                color: 'white',
                border: 'none',
                borderRadius: 8,
                fontSize: 14,
                fontWeight: 500,
                cursor: 'pointer',
              }}
            >
              Done
            </button>
          ) : (
            <>
              <button
                onClick={() => (step === 1 ? onClose() : setStep(prev => (prev - 1) as Step))}
                style={{
                  padding: '8px 16px',
                  border: 'none',
                  background: 'none',
                  fontSize: 14,
                  color: 'var(--apple-text-secondary)',
                  cursor: 'pointer',
                }}
              >
                {step === 1 ? 'Cancel' : '← Back'}
              </button>

              {step < 4 ? (
                <button
                  onClick={() => setStep(prev => (prev + 1) as Step)}
                  disabled={!canNext()}
                  style={{
                    padding: '9px 20px',
                    background: canNext() ? '#0071E3' : 'var(--apple-gray-3)',
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
                  onClick={handleEnroll}
                  disabled={loading}
                  style={{
                    padding: '9px 20px',
                    background: '#0071E3',
                    color: 'white',
                    border: 'none',
                    borderRadius: 8,
                    fontSize: 14,
                    fontWeight: 600,
                    cursor: 'pointer',
                    opacity: loading ? 0.7 : 1,
                  }}
                >
                  {loading ? 'Enrolling...' : 'Enroll Now'}
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
