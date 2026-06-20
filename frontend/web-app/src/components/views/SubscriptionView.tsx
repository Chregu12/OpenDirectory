'use client';
import React, { useState, useEffect } from 'react';
import {
  ArrowPathIcon,
  SparklesIcon,
  UserGroupIcon,
  CreditCardIcon,
  CalendarIcon,
  CheckCircleIcon,
  XCircleIcon,
} from '@heroicons/react/24/outline';

interface ModuleFeature {
  feature: string;
  status: 'included' | 'add-on' | 'unavailable';
  included: boolean;
  used: number;
  limit: number | null;
}

const MOCK_FEATURES: ModuleFeature[] = [
  { feature: 'Directory Services (LDAP)', status: 'included', included: true, used: 1, limit: 1 },
  { feature: 'Device Management (MDM)', status: 'included', included: true, used: 87, limit: 250 },
  { feature: 'Multi-Factor Authentication', status: 'included', included: true, used: 64, limit: 250 },
  { feature: 'Group Policy Objects', status: 'included', included: true, used: 14, limit: null },
  { feature: 'RADIUS Authentication', status: 'included', included: true, used: 3, limit: 10 },
  { feature: 'Certificate Authority', status: 'included', included: true, used: 120, limit: 500 },
  { feature: 'Audit & Compliance', status: 'included', included: true, used: 1, limit: 1 },
  { feature: 'Privileged Identity Management', status: 'add-on', included: false, used: 0, limit: 0 },
  { feature: 'Advanced Threat Detection', status: 'add-on', included: false, used: 0, limit: 0 },
  { feature: 'SIEM Integration', status: 'unavailable', included: false, used: 0, limit: 0 },
];

const PLAN = 'Business';
const SEATS_USED = 87;
const SEATS_TOTAL = 250;
const RENEWAL_DATE = '2026-12-31';

export default function SubscriptionView() {
  const [features, setFeatures] = useState<ModuleFeature[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch('/api/config/modules');
      if (r.ok) {
        const data = await r.json();
        const modules: string[] = Array.isArray(data) ? data : (data.modules ?? []);
        const mapped: ModuleFeature[] = modules.map((m: string) => ({
          feature: m,
          status: 'included' as const,
          included: true,
          used: 0,
          limit: null,
        }));
        setFeatures(mapped.length > 0 ? mapped : MOCK_FEATURES);
      } else {
        setFeatures(MOCK_FEATURES);
      }
    } catch {
      setFeatures(MOCK_FEATURES);
    } finally {
      setLoading(false);
    }
  }

  const filtered = features.filter(f =>
    f.feature.toLowerCase().includes(search.toLowerCase())
  );

  const statusBadge = (status: string) => {
    const map: Record<string, { bg: string; color: string; label: string }> = {
      included:    { bg: 'rgba(63,185,80,0.15)',  color: '#3fb950', label: 'Included' },
      'add-on':    { bg: 'rgba(0,111,255,0.15)',   color: '#006FFF', label: 'Add-on' },
      unavailable: { bg: 'rgba(110,118,129,0.15)', color: '#6e7681', label: 'Unavailable' },
    };
    const s = map[status] ?? map['unavailable'];
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: s.bg, color: s.color }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color, display: 'inline-block' }} />
        {s.label}
      </span>
    );
  };

  return (
    <div style={{ padding: '24px 28px', minHeight: '100vh', background: 'var(--bg-base, #0e1115)' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Subscription</h1>
        <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginTop: 4, marginBottom: 0 }}>OpenDirectory license and entitlements</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>PLAN</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <SparklesIcon style={{ width: 20, height: 20, color: '#006FFF' }} />
            {PLAN}
          </div>
          <div style={{ fontSize: 12, color: '#006FFF', marginTop: 4 }}>Active license</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>SEATS USED</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{SEATS_USED}</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary, #8b949e)', marginTop: 4 }}>of {SEATS_TOTAL} total</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>SEATS AVAILABLE</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{SEATS_TOTAL - SEATS_USED}</div>
          <div style={{ fontSize: 12, color: '#3fb950', marginTop: 4 }}>seats remaining</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>RENEWAL DATE</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <CalendarIcon style={{ width: 18, height: 18, color: '#8b949e' }} />
            {RENEWAL_DATE}
          </div>
          <div style={{ fontSize: 12, color: '#d29922', marginTop: 4 }}>Annual billing</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button className="fluent-btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <SparklesIcon style={{ width: 14, height: 14 }} />
          Upgrade Plan
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <UserGroupIcon style={{ width: 14, height: 14 }} />
          Manage Seats
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={load} disabled={loading}>
          <ArrowPathIcon style={{ width: 14, height: 14 }} />
          Refresh
        </button>
        <div style={{ marginLeft: 'auto' }}>
          <input
            type="search"
            placeholder="Search features..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ padding: '6px 12px', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, color: 'var(--text-primary, #e4e6ea)', fontSize: 13, width: 220, outline: 'none' }}
          />
        </div>
      </div>

      <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, overflow: 'hidden' }}>
        <table className="fluent-table" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
          <thead>
            <tr>
              {['Feature', 'Status', 'Included', 'Used', 'Limit'].map(col => (
                <th key={col} style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-muted, #6e7681)', borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>Loading...</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>No features found</td></tr>
            ) : filtered.map((f, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                <td style={{ padding: '11px 16px', color: 'var(--text-primary, #e4e6ea)', fontWeight: 500 }}>{f.feature}</td>
                <td style={{ padding: '11px 16px' }}>{statusBadge(f.status)}</td>
                <td style={{ padding: '11px 16px' }}>
                  {f.included
                    ? <CheckCircleIcon style={{ width: 16, height: 16, color: '#3fb950' }} />
                    : <XCircleIcon style={{ width: 16, height: 16, color: '#6e7681' }} />}
                </td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>{f.used}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>{f.limit === null ? '∞' : f.limit === 0 ? '—' : f.limit}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: 16, padding: '12px 16px', background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 10, display: 'flex', alignItems: 'center', gap: 10 }}>
        <CreditCardIcon style={{ width: 16, height: 16, color: '#006FFF', flexShrink: 0 }} />
        <span style={{ fontSize: 12, color: 'var(--text-secondary, #8b949e)' }}>
          Next invoice: <strong style={{ color: 'var(--text-primary, #e4e6ea)' }}>$2,490 USD</strong> on {RENEWAL_DATE} · Payment method: Visa ending in 4242
        </span>
      </div>
    </div>
  );
}
