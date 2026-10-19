'use client';
import React, { useState, useEffect } from 'react';
import {
  PlusIcon,
  ArrowPathIcon,
  PencilIcon,
  TrashIcon,
  LinkIcon,
  ShieldCheckIcon,
  ComputerDesktopIcon,
  PlayIcon,
} from '@heroicons/react/24/outline';

interface GPO {
  id: string;
  name: string;
  status: 'enabled' | 'disabled' | 'enforced';
  links: number;
  settings: number;
  modified: string;
  scope: string;
}

const MOCK_GPOS: GPO[] = [
  { id: '1', name: 'Default Domain Policy', status: 'enabled', links: 1, settings: 84, modified: '2024-12-01', scope: 'Domain' },
  { id: '2', name: 'Password Policy', status: 'enabled', links: 2, settings: 12, modified: '2024-11-15', scope: 'Domain' },
  { id: '3', name: 'Software Restriction Policy', status: 'enabled', links: 3, settings: 45, modified: '2024-10-20', scope: 'OU: Workstations' },
  { id: '4', name: 'Firewall Rules', status: 'enabled', links: 1, settings: 28, modified: '2024-09-05', scope: 'OU: Servers' },
  { id: '5', name: 'Legacy IE Settings', status: 'disabled', links: 0, settings: 5, modified: '2023-06-01', scope: 'None' },
];

interface SimulateResult {
  target: string;
  appliedPolicies: { name: string; scope: string; settings: number }[];
  effectiveSettings: number;
}

export default function GPOView() {
  const [items, setItems] = useState<GPO[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [simulateTarget, setSimulateTarget] = useState('');
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<SimulateResult | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch('/api/policies?type=gpo');
      if (r.ok) {
        const data = await r.json();
        const raw: any[] = Array.isArray(data) ? data : (data.policies ?? data.items ?? []);
        const mapped: GPO[] = raw.map((g: any) => ({
          id:       g.id ?? String(Math.random()),
          name:     g.name ?? g.displayName ?? 'Unknown Policy',
          status:   g.status ?? (g.enabled === false ? 'disabled' : 'enabled'),
          links:    g.links ?? g.linkCount ?? 0,
          settings: g.settings ?? g.settingCount ?? 0,
          modified: g.modified ?? g.modifiedDate ?? '—',
          scope:    g.scope ?? g.targetOU ?? 'Domain',
        }));
        setItems(mapped.length > 0 ? mapped : MOCK_GPOS);
      } else {
        setItems(MOCK_GPOS);
      }
    } catch {
      setItems(MOCK_GPOS);
    } finally {
      setLoading(false);
    }
  }

  const filtered = items.filter(i =>
    i.name.toLowerCase().includes(search.toLowerCase()) ||
    i.scope.toLowerCase().includes(search.toLowerCase())
  );

  const linked = items.filter(i => i.links > 0).length;
  const disabled = items.filter(i => i.status === 'disabled').length;
  const totalSettings = items.reduce((s, i) => s + i.settings, 0);

  const statusBadge = (status: string) => {
    const map: Record<string, { bg: string; color: string; label: string }> = {
      enabled:  { bg: 'rgba(63,185,80,0.15)',  color: '#3fb950', label: 'Enabled' },
      disabled: { bg: 'rgba(110,118,129,0.15)', color: '#6e7681', label: 'Disabled' },
      enforced: { bg: 'rgba(0,111,255,0.15)',   color: '#006FFF', label: 'Enforced' },
    };
    const s = map[status] ?? map['disabled'];
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: s.bg, color: s.color }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color, display: 'inline-block' }} />
        {s.label}
      </span>
    );
  };

  async function handleSimulate(e: React.FormEvent) {
    e.preventDefault();
    if (!simulateTarget.trim()) return;
    setSimulating(true);
    setSimResult(null);
    try {
      const r = await fetch('/api/policies/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: simulateTarget }),
      });
      if (r.ok) {
        setSimResult(await r.json());
      } else {
        throw new Error('simulate failed');
      }
    } catch {
      // Show mock result
      const applied = items
        .filter(i => i.status === 'enabled' && i.links > 0)
        .map(i => ({ name: i.name, scope: i.scope, settings: i.settings }));
      setSimResult({
        target: simulateTarget,
        appliedPolicies: applied,
        effectiveSettings: applied.reduce((s, p) => s + p.settings, 0),
      });
    } finally {
      setSimulating(false);
    }
  }

  return (
    <div style={{ padding: '24px 28px', minHeight: '100vh', background: 'var(--bg-base, #0e1115)' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Group Policy</h1>
        <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginTop: 4, marginBottom: 0 }}>Windows Group Policy Objects and assignments</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>TOTAL GPOs</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{items.length}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Defined policies</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>LINKED</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{linked}</div>
          <div style={{ fontSize: 12, color: '#3fb950', marginTop: 4 }}>Active in domain</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>DISABLED</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: disabled > 0 ? '#6e7681' : 'var(--text-primary, #e4e6ea)' }}>{disabled}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Not applied</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>COMPUTERS AFFECTED</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{totalSettings}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Total setting entries</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button className="fluent-btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <PlusIcon style={{ width: 14, height: 14 }} />
          New GPO
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <PencilIcon style={{ width: 14, height: 14 }} />
          Edit
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <LinkIcon style={{ width: 14, height: 14 }} />
          Link GPO
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#f85149' }}>
          <TrashIcon style={{ width: 14, height: 14 }} />
          Delete
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={load} disabled={loading}>
          <ArrowPathIcon style={{ width: 14, height: 14 }} />
          Refresh
        </button>
        <div style={{ marginLeft: 'auto' }}>
          <input
            type="search"
            placeholder="Search policies..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ padding: '6px 12px', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, color: 'var(--text-primary, #e4e6ea)', fontSize: 13, width: 200, outline: 'none' }}
          />
        </div>
      </div>

      <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, overflow: 'hidden', marginBottom: 20 }}>
        <table className="fluent-table" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
          <thead>
            <tr>
              {['Name', 'Status', 'Links', 'Settings Count', 'Modified', 'Scope'].map(col => (
                <th key={col} style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-muted, #6e7681)', borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>Loading...</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>No GPOs found</td></tr>
            ) : filtered.map(item => (
              <tr key={item.id} style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                <td style={{ padding: '11px 16px', fontWeight: 600, color: 'var(--text-primary, #e4e6ea)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <ShieldCheckIcon style={{ width: 15, height: 15, color: '#006FFF', flexShrink: 0 }} />
                    {item.name}
                  </div>
                </td>
                <td style={{ padding: '11px 16px' }}>{statusBadge(item.status)}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>{item.links}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>{item.settings}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-muted, #6e7681)', fontSize: 12 }}>{item.modified}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)', fontSize: 12 }}>
                  <span style={{ fontFamily: 'monospace' }}>{item.scope}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Resultant Set of Policy Simulator */}
      <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
          <ComputerDesktopIcon style={{ width: 16, height: 16, color: '#006FFF' }} />
          <h2 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Resultant Set of Policy</h2>
          <span style={{ fontSize: 11, color: 'var(--text-muted, #6e7681)', marginLeft: 4 }}>RSoP Simulator</span>
        </div>
        <form onSubmit={handleSimulate} style={{ display: 'flex', gap: 10, alignItems: 'flex-end', marginBottom: 16 }}>
          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>
              Username or Computer Name
            </label>
            <input
              type="text"
              placeholder="e.g. jdoe@corp.local or DESKTOP-A1B2C3"
              value={simulateTarget}
              onChange={e => setSimulateTarget(e.target.value)}
              style={{ width: '100%', padding: '8px 12px', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, color: 'var(--text-primary, #e4e6ea)', fontSize: 13, outline: 'none', boxSizing: 'border-box' }}
            />
          </div>
          <button type="submit" className="fluent-btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px' }} disabled={simulating || !simulateTarget.trim()}>
            <PlayIcon style={{ width: 14, height: 14 }} />
            {simulating ? 'Simulating...' : 'Simulate'}
          </button>
        </form>

        {simResult && (
          <div style={{ background: 'var(--bg-overlay, #252c37)', border: '1px solid var(--border-strong, rgba(255,255,255,0.14))', borderRadius: 10, padding: '16px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary, #e4e6ea)' }}>
                  RSoP for: <span style={{ color: '#006FFF', fontFamily: 'monospace' }}>{simResult.target}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary, #8b949e)', marginTop: 2 }}>
                  {simResult.appliedPolicies.length} policies applied · {simResult.effectiveSettings} effective settings
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {simResult.appliedPolicies.map((p, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-surface, #161b22)', borderRadius: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <ShieldCheckIcon style={{ width: 13, height: 13, color: '#3fb950' }} />
                    <span style={{ fontSize: 13, color: 'var(--text-primary, #e4e6ea)' }}>{p.name}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 12, fontSize: 12 }}>
                    <span style={{ color: 'var(--text-muted, #6e7681)', fontFamily: 'monospace' }}>{p.scope}</span>
                    <span style={{ color: 'var(--text-secondary, #8b949e)' }}>{p.settings} settings</span>
                  </div>
                </div>
              ))}
              {simResult.appliedPolicies.length === 0 && (
                <div style={{ fontSize: 13, color: 'var(--text-muted, #6e7681)', textAlign: 'center', padding: '8px 0' }}>
                  No policies apply to this target
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
