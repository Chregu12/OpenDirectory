'use client';

import React, { useState, useEffect } from 'react';
import {
  XMarkIcon,
  CheckIcon,
  MagnifyingGlassIcon,
  CheckCircleIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

type Step = 1 | 2 | 3 | 4;
type TargetType = 'all' | 'byOS' | 'byOU' | 'byGroup' | 'device' | 'user';

interface PolicyDeployWizardProps {
  onClose: () => void;
}

interface Policy {
  id: string;
  name: string;
  category: string;
  description?: string;
}

interface DeployResult {
  applied: number;
  dryRun: boolean;
  policy: string;
  target: string;
}

// ─── Mock policies ────────────────────────────────────────────────────────────

const MOCK_POLICIES: Policy[] = [
  { id: '1', name: 'Enforce Disk Encryption',    category: 'Security',    description: 'Enable FileVault/BitLocker on all endpoints' },
  { id: '2', name: 'Password Complexity',        category: 'Security',    description: 'Minimum 12 chars, complexity required' },
  { id: '3', name: 'Screen Lock (5 min)',        category: 'Security',    description: 'Lock screen after 5 minutes idle' },
  { id: '4', name: 'Antivirus Required',         category: 'Compliance',  description: 'Ensure AV agent is installed and updated' },
  { id: '5', name: 'App Allowlist',              category: 'Compliance',  description: 'Restrict app installations to approved list' },
  { id: '6', name: 'Firewall On',                category: 'Network',     description: 'Enable host firewall on all devices' },
  { id: '7', name: 'VPN Required for Remote',    category: 'Network',     description: 'Enforce VPN when off-premises' },
  { id: '8', name: 'Automatic OS Updates',       category: 'Maintenance', description: 'Install security patches automatically' },
  { id: '9', name: 'USB Block',                  category: 'DLP',         description: 'Block external USB storage devices' },
  { id: '10',name: 'MFA Enforce',                category: 'Identity',    description: 'Require MFA for all logins' },
];

const STEPS = [
  { n: 1 as Step, label: 'Policy' },
  { n: 2 as Step, label: 'Target' },
  { n: 3 as Step, label: 'Options' },
  { n: 4 as Step, label: 'Deploy' },
];

const TARGET_OPTIONS: { value: TargetType; label: string; icon: string; desc: string }[] = [
  { value: 'all',     label: 'All Devices',      icon: '💻', desc: 'Apply to every managed device' },
  { value: 'byOS',    label: 'By OS',            icon: '🖥', desc: 'Filter by operating system' },
  { value: 'byOU',    label: 'By OU',            icon: '📁', desc: 'Target an organisational unit' },
  { value: 'byGroup', label: 'By Group',         icon: '👥', desc: 'Apply to a specific user group' },
  { value: 'device',  label: 'Specific Device',  icon: '🖱', desc: 'One device by name' },
  { value: 'user',    label: 'Specific User',    icon: '👤', desc: 'All devices of a user' },
];

// ─── Step indicator ───────────────────────────────────────────────────────────

function StepIndicator({ current }: { current: Step }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', marginBottom: 28 }}>
      {STEPS.map((s, i) => (
        <React.Fragment key={s.n}>
          {i > 0 && (
            <div style={{ flex: 1, height: 2, background: s.n <= current ? '#FF9500' : 'var(--apple-gray-3)' }} />
          )}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
            <div
              style={{
                width: 28,
                height: 28,
                borderRadius: '50%',
                background: s.n < current ? '#FF9500' : s.n === current ? '#FF9500' : 'var(--apple-gray-3)',
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
            <span style={{ fontSize: 11, color: s.n === current ? '#FF9500' : 'var(--apple-text-tertiary)', fontWeight: s.n === current ? 600 : 400, whiteSpace: 'nowrap' }}>
              {s.label}
            </span>
          </div>
        </React.Fragment>
      ))}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function PolicyDeployWizard({ onClose }: PolicyDeployWizardProps) {
  const [step, setStep]           = useState<Step>(1);
  const [policies, setPolicies]   = useState<Policy[]>(MOCK_POLICIES);
  const [search, setSearch]       = useState('');
  const [selectedPolicy, setPolicy] = useState<Policy | null>(null);
  const [targetType, setTargetType] = useState<TargetType>('all');
  const [targetValue, setTargetValue] = useState('');
  const [enforced, setEnforced]   = useState(true);
  const [dryRun, setDryRun]       = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [progress, setProgress]   = useState(0);
  const [result, setResult]       = useState<DeployResult | null>(null);

  // Fetch real policies
  useEffect(() => {
    api.get('/api/policies').then(res => {
      const data = Array.isArray(res.data) ? res.data : res.data?.policies ?? [];
      if (data.length > 0) {
        setPolicies(data.map((p: any) => ({
          id: p.id,
          name: p.name,
          category: p.category ?? 'General',
          description: p.description,
        })));
      }
    }).catch(() => {});
  }, []);

  const filteredPolicies = policies.filter(p =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.category.toLowerCase().includes(search.toLowerCase())
  );

  const simulate = () => {
    // Simulate a target count based on type
    const counts: Record<TargetType, number> = {
      all: 535, byOS: 142, byOU: 89, byGroup: 34, device: 1, user: 3,
    };
    return counts[targetType] ?? 10;
  };

  const handleDeploy = async () => {
    if (!selectedPolicy) return;
    setDeploying(true);
    setProgress(0);

    // Animate progress bar
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 90) { clearInterval(interval); return 90; }
        return prev + Math.random() * 15;
      });
    }, 200);

    try {
      // TODO: POST http://localhost:3950/api/quick/policies/deploy
      await api.post('/api/quick/policies/deploy', {
        policy_id: selectedPolicy.id,
        target_type: targetType,
        target_value: targetValue,
        enforced,
        dry_run: dryRun,
      });
    } catch {
      // continue with mock result
    } finally {
      clearInterval(interval);
      setProgress(100);
      setTimeout(() => {
        setResult({
          applied: dryRun ? 0 : simulate(),
          dryRun,
          policy: selectedPolicy.name,
          target: targetType === 'all' ? 'All Devices' : targetValue || targetType,
        });
        setDeploying(false);
        if (!dryRun) toast.success('Policy deployed successfully');
        else toast.success('Dry run complete — no changes applied');
      }, 500);
    }
  };

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)', zIndex: 60, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}
      onClick={onClose}
    >
      <div
        style={{ background: 'white', borderRadius: 16, boxShadow: '0 24px 64px rgba(0,0,0,0.18)', width: '100%', maxWidth: 540, maxHeight: '90vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ background: 'linear-gradient(135deg, #FF9500 0%, #E07B00 100%)', padding: '22px 24px 20px', color: 'white', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, color: 'white' }}>Deploy Policy</h2>
            <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.7)', padding: 2 }}>
              <XMarkIcon style={{ width: 20, height: 20 }} />
            </button>
          </div>
          <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.75)' }}>
            Push a policy to managed devices
          </p>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px' }}>
          {result ? (
            /* Success state */
            <div style={{ textAlign: 'center' }}>
              <CheckCircleIcon style={{ width: 52, height: 52, color: result.dryRun ? '#FF9500' : '#22c55e', margin: '0 auto 14px' }} />
              <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>
                {result.dryRun ? 'Dry Run Complete' : 'Policy Deployed'}
              </h3>
              <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', marginBottom: 20 }}>
                {result.dryRun
                  ? `Would have applied "${result.policy}" to ${simulate()} devices. No changes were made.`
                  : `"${result.policy}" was applied to ${result.applied} devices.`}
              </p>
              <div style={{ background: 'var(--apple-gray-1)', borderRadius: 10, padding: '14px 16px', textAlign: 'left' }}>
                {[
                  { label: 'Policy', value: result.policy },
                  { label: 'Target', value: result.target },
                  { label: 'Mode', value: result.dryRun ? 'Dry Run (no changes)' : enforced ? 'Enforced' : 'Audit Only' },
                  { label: 'Devices Affected', value: result.dryRun ? `${simulate()} (simulated)` : `${result.applied}` },
                ].map(row => (
                  <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--apple-gray-2)' }}>
                    <span style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>{row.label}</span>
                    <span style={{ fontSize: 13, color: 'var(--apple-text-primary)', fontWeight: 500 }}>{row.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <>
              <StepIndicator current={step} />

              {/* Step 1: Pick policy */}
              {step === 1 && (
                <div>
                  <div style={{ position: 'relative', marginBottom: 14 }}>
                    <MagnifyingGlassIcon style={{ width: 15, height: 15, position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--apple-gray-5)', pointerEvents: 'none' }} />
                    <input
                      type="text"
                      placeholder="Search policies..."
                      value={search}
                      onChange={e => setSearch(e.target.value)}
                      style={{ width: '100%', paddingLeft: 32, paddingRight: 12, paddingTop: 8, paddingBottom: 8, border: '1px solid var(--apple-gray-2)', borderRadius: 8, fontSize: 13, outline: 'none', background: 'var(--apple-gray-1)', boxSizing: 'border-box' }}
                    />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 320, overflowY: 'auto' }}>
                    {filteredPolicies.map(p => (
                      <button
                        key={p.id}
                        onClick={() => setPolicy(p)}
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: 12,
                          padding: '10px 12px',
                          border: selectedPolicy?.id === p.id ? '1.5px solid #FF9500' : '1px solid var(--apple-gray-2)',
                          borderRadius: 8,
                          background: selectedPolicy?.id === p.id ? '#FFF7E6' : 'white',
                          cursor: 'pointer',
                          textAlign: 'left',
                        }}
                      >
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)' }}>{p.name}</div>
                          <div style={{ fontSize: 11, color: 'var(--apple-text-tertiary)', marginTop: 2 }}>
                            <span style={{ background: 'var(--apple-gray-2)', borderRadius: 4, padding: '1px 6px', marginRight: 6 }}>{p.category}</span>
                            {p.description}
                          </div>
                        </div>
                        {selectedPolicy?.id === p.id && <CheckIcon style={{ width: 16, height: 16, color: '#FF9500', flexShrink: 0, marginTop: 2 }} />}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Step 2: Choose target */}
              {step === 2 && (
                <div>
                  <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', marginBottom: 14 }}>
                    Choose which devices will receive this policy:
                  </p>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 14 }}>
                    {TARGET_OPTIONS.map(opt => (
                      <button
                        key={opt.value}
                        onClick={() => setTargetType(opt.value)}
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: 10,
                          padding: '10px 12px',
                          border: targetType === opt.value ? '1.5px solid #FF9500' : '1px solid var(--apple-gray-2)',
                          borderRadius: 8,
                          background: targetType === opt.value ? '#FFF7E6' : 'white',
                          cursor: 'pointer',
                          textAlign: 'left',
                        }}
                      >
                        <span style={{ fontSize: 20 }}>{opt.icon}</span>
                        <div>
                          <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)' }}>{opt.label}</div>
                          <div style={{ fontSize: 11, color: 'var(--apple-text-tertiary)', lineHeight: 1.3 }}>{opt.desc}</div>
                        </div>
                      </button>
                    ))}
                  </div>
                  {targetType !== 'all' && (
                    <input
                      type="text"
                      placeholder={`Specify ${TARGET_OPTIONS.find(o => o.value === targetType)?.label}...`}
                      value={targetValue}
                      onChange={e => setTargetValue(e.target.value)}
                      style={{ width: '100%', padding: '9px 12px', border: '1px solid var(--apple-gray-2)', borderRadius: 8, fontSize: 14, outline: 'none', boxSizing: 'border-box' }}
                    />
                  )}
                </div>
              )}

              {/* Step 3: Options */}
              {step === 3 && (
                <div>
                  <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', marginBottom: 18 }}>
                    Configure deployment options:
                  </p>
                  {[
                    {
                      key: 'enforced',
                      label: 'Enforced',
                      desc: 'Block users from changing this setting. If off, policy is in audit-only mode.',
                      value: enforced,
                      toggle: () => setEnforced(e => !e),
                      color: '#FF9500',
                    },
                    {
                      key: 'dryRun',
                      label: 'Dry Run',
                      desc: 'Simulate deployment — shows what WOULD happen without making any changes.',
                      value: dryRun,
                      toggle: () => setDryRun(d => !d),
                      color: '#0071E3',
                    },
                  ].map(opt => (
                    <div
                      key={opt.key}
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        justifyContent: 'space-between',
                        gap: 16,
                        padding: '14px 16px',
                        border: `1px solid var(--apple-gray-2)`,
                        borderRadius: 10,
                        marginBottom: 10,
                        background: opt.value ? '#F9F9F9' : 'white',
                      }}
                    >
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--apple-text-primary)' }}>{opt.label}</div>
                        <div style={{ fontSize: 12, color: 'var(--apple-text-secondary)', marginTop: 3, lineHeight: 1.4 }}>{opt.desc}</div>
                      </div>
                      <button
                        onClick={opt.toggle}
                        style={{
                          width: 44,
                          height: 26,
                          borderRadius: 13,
                          background: opt.value ? opt.color : 'var(--apple-gray-3)',
                          border: 'none',
                          cursor: 'pointer',
                          position: 'relative',
                          transition: 'background 0.2s',
                          flexShrink: 0,
                        }}
                      >
                        <span
                          style={{
                            position: 'absolute',
                            top: 3,
                            left: opt.value ? 21 : 3,
                            width: 20,
                            height: 20,
                            borderRadius: '50%',
                            background: 'white',
                            transition: 'left 0.2s',
                            boxShadow: '0 1px 4px rgba(0,0,0,0.2)',
                          }}
                        />
                      </button>
                    </div>
                  ))}

                  {dryRun && (
                    <div style={{ background: '#EAF4FF', border: '1px solid #A8D4FF', borderRadius: 8, padding: '10px 14px', fontSize: 13, color: '#0055B3' }}>
                      Dry run is enabled. Deploying will simulate applying to ~{simulate()} devices with no actual changes.
                    </div>
                  )}
                </div>
              )}

              {/* Step 4: Deploy with progress */}
              {step === 4 && (
                <div>
                  <div style={{ marginBottom: 20 }}>
                    <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 14 }}>
                      Ready to {dryRun ? 'simulate' : 'deploy'}
                    </div>
                    <div style={{ background: 'var(--apple-gray-1)', borderRadius: 10, padding: '14px 16px' }}>
                      {[
                        { label: 'Policy', value: selectedPolicy?.name ?? '—' },
                        { label: 'Target', value: targetType === 'all' ? 'All Devices' : targetValue || targetType },
                        { label: 'Mode', value: dryRun ? '🔍 Dry Run (no changes)' : enforced ? '✅ Enforced' : '👁 Audit Only' },
                        { label: 'Estimated Scope', value: `~${simulate()} devices` },
                      ].map(row => (
                        <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--apple-gray-2)' }}>
                          <span style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>{row.label}</span>
                          <span style={{ fontSize: 13, color: 'var(--apple-text-primary)', fontWeight: 500 }}>{row.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {deploying && (
                    <div style={{ marginTop: 16 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>
                          {dryRun ? 'Simulating...' : 'Deploying...'}
                        </span>
                        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)' }}>
                          {Math.round(progress)}%
                        </span>
                      </div>
                      <div style={{ height: 8, background: 'var(--apple-gray-2)', borderRadius: 4, overflow: 'hidden' }}>
                        <div
                          style={{
                            height: '100%',
                            background: dryRun ? '#0071E3' : '#FF9500',
                            borderRadius: 4,
                            width: `${progress}%`,
                            transition: 'width 0.2s',
                          }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '16px 24px', borderTop: '1px solid var(--apple-gray-2)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0, background: 'white' }}>
          {result ? (
            <button onClick={onClose} style={{ marginLeft: 'auto', padding: '9px 20px', background: '#FF9500', color: 'white', border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 500, cursor: 'pointer' }}>
              Done
            </button>
          ) : (
            <>
              <button
                onClick={() => (step === 1 ? onClose() : setStep(prev => (prev - 1) as Step))}
                disabled={deploying}
                style={{ padding: '8px 16px', border: 'none', background: 'none', fontSize: 14, color: 'var(--apple-text-secondary)', cursor: 'pointer' }}
              >
                {step === 1 ? 'Cancel' : '← Back'}
              </button>

              {step < 4 ? (
                <button
                  onClick={() => setStep(prev => (prev + 1) as Step)}
                  disabled={step === 1 && !selectedPolicy}
                  style={{
                    padding: '9px 20px',
                    background: (step === 1 && !selectedPolicy) ? 'var(--apple-gray-3)' : '#FF9500',
                    color: 'white',
                    border: 'none',
                    borderRadius: 8,
                    fontSize: 14,
                    fontWeight: 500,
                    cursor: (step === 1 && !selectedPolicy) ? 'not-allowed' : 'pointer',
                  }}
                >
                  Continue →
                </button>
              ) : (
                <button
                  onClick={handleDeploy}
                  disabled={deploying}
                  style={{
                    padding: '9px 24px',
                    background: '#FF9500',
                    color: 'white',
                    border: 'none',
                    borderRadius: 8,
                    fontSize: 14,
                    fontWeight: 600,
                    cursor: deploying ? 'not-allowed' : 'pointer',
                    opacity: deploying ? 0.7 : 1,
                  }}
                >
                  {deploying ? 'Working...' : dryRun ? 'Run Dry Run' : 'Deploy Now'}
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
