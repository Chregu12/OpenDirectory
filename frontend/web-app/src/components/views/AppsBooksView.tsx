'use client';
import React, { useState, useEffect } from 'react';
import {
  PlusIcon,
  ArrowPathIcon,
  KeyIcon,
  CubeIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

interface AppLicense {
  id: string;
  name: string;
  platform: string;
  licenses: number;
  assigned: number;
  available: number;
  price: string;
  expires: string;
}

const MOCK_APPS: AppLicense[] = [
  { id: '1', name: 'Microsoft 365', platform: 'All', licenses: 100, assigned: 87, available: 13, price: '$12/mo', expires: '2025-12-31' },
  { id: '2', name: 'Adobe Creative Cloud', platform: 'macOS/Win', licenses: 25, assigned: 22, available: 3, price: '$55/mo', expires: '2025-06-30' },
  { id: '3', name: 'Final Cut Pro', platform: 'macOS', licenses: 10, assigned: 8, available: 2, price: '$299', expires: 'N/A' },
  { id: '4', name: 'Slack', platform: 'All', licenses: 150, assigned: 143, available: 7, price: '$7.25/mo', expires: '2025-09-30' },
  { id: '5', name: 'Xcode', platform: 'macOS', licenses: 20, assigned: 18, available: 2, price: 'Free', expires: 'N/A' },
  { id: '6', name: 'Visual Studio 2022', platform: 'Windows', licenses: 15, assigned: 12, available: 3, price: '$45/mo', expires: '2025-11-30' },
];

export default function AppsBooksView() {
  const [items, setItems] = useState<AppLicense[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch('/api/apps?type=vpp');
      if (r.ok) {
        const data = await r.json();
        const raw: any[] = Array.isArray(data) ? data : (data.apps ?? data.items ?? []);
        const mapped: AppLicense[] = raw.map((a: any) => ({
          id:        a.id ?? String(Math.random()),
          name:      a.name ?? a.title ?? 'Unknown App',
          platform:  a.platform ?? 'All',
          licenses:  a.licenses ?? a.totalLicenses ?? 0,
          assigned:  a.assigned ?? a.usedLicenses ?? 0,
          available: a.available ?? (a.totalLicenses - a.usedLicenses) ?? 0,
          price:     a.price ?? '—',
          expires:   a.expires ?? a.expiryDate ?? 'N/A',
        }));
        setItems(mapped.length > 0 ? mapped : MOCK_APPS);
      } else {
        setItems(MOCK_APPS);
      }
    } catch {
      setItems(MOCK_APPS);
    } finally {
      setLoading(false);
    }
  }

  const filtered = items.filter(i =>
    i.name.toLowerCase().includes(search.toLowerCase()) ||
    i.platform.toLowerCase().includes(search.toLowerCase())
  );

  const totalLicenses = items.reduce((s, i) => s + i.licenses, 0);
  const totalAssigned = items.reduce((s, i) => s + i.assigned, 0);
  const totalAvailable = items.reduce((s, i) => s + i.available, 0);
  const now = new Date();
  const expiringSoon = items.filter(i => {
    if (i.expires === 'N/A' || i.expires === '—') return false;
    const d = new Date(i.expires);
    const diff = (d.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
    return diff > 0 && diff <= 90;
  }).length;

  const platformBadge = (platform: string) => {
    const map: Record<string, { bg: string; color: string }> = {
      'macOS':     { bg: 'rgba(110,118,129,0.15)', color: '#8b949e' },
      'Windows':   { bg: 'rgba(0,111,255,0.15)',   color: '#006FFF' },
      'iOS':       { bg: 'rgba(28,33,40,0.8)',      color: '#c9d1d9' },
      'All':       { bg: 'rgba(63,185,80,0.15)',    color: '#3fb950' },
      'macOS/Win': { bg: 'rgba(110,118,129,0.15)', color: '#8b949e' },
    };
    const s = map[platform] ?? { bg: 'rgba(110,118,129,0.15)', color: '#8b949e' };
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: s.bg, color: s.color }}>
        {platform}
      </span>
    );
  };

  const utilizationBar = (assigned: number, total: number) => {
    const pct = total > 0 ? Math.round((assigned / total) * 100) : 0;
    const color = pct >= 95 ? '#f85149' : pct >= 80 ? '#d29922' : '#3fb950';
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2, overflow: 'hidden' }}>
          <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2 }} />
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted, #6e7681)', minWidth: 32 }}>{pct}%</span>
      </div>
    );
  };

  return (
    <div style={{ padding: '24px 28px', minHeight: '100vh', background: 'var(--bg-base, #0e1115)' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Apps & Books</h1>
        <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginTop: 4, marginBottom: 0 }}>Volume Purchase Program licenses and content</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>TOTAL LICENSES</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{totalLicenses}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Across all apps</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>ASSIGNED</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{totalAssigned}</div>
          <div style={{ fontSize: 12, color: '#006FFF', marginTop: 4 }}>{totalLicenses > 0 ? Math.round((totalAssigned / totalLicenses) * 100) : 0}% utilization</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>AVAILABLE</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{totalAvailable}</div>
          <div style={{ fontSize: 12, color: '#3fb950', marginTop: 4 }}>Unassigned seats</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>EXPIRING SOON</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: expiringSoon > 0 ? '#d29922' : 'var(--text-primary, #e4e6ea)' }}>{expiringSoon}</div>
          <div style={{ fontSize: 12, color: expiringSoon > 0 ? '#d29922' : '#8b949e', marginTop: 4 }}>Within 90 days</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button className="fluent-btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <PlusIcon style={{ width: 14, height: 14 }} />
          Add App
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <KeyIcon style={{ width: 14, height: 14 }} />
          Assign Licenses
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#f85149' }}>
          <ExclamationTriangleIcon style={{ width: 14, height: 14 }} />
          Revoke
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={load} disabled={loading}>
          <ArrowPathIcon style={{ width: 14, height: 14 }} />
          Refresh
        </button>
        <div style={{ marginLeft: 'auto' }}>
          <input
            type="search"
            placeholder="Search apps..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ padding: '6px 12px', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, color: 'var(--text-primary, #e4e6ea)', fontSize: 13, width: 200, outline: 'none' }}
          />
        </div>
      </div>

      <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, overflow: 'hidden' }}>
        <table className="fluent-table" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
          <thead>
            <tr>
              {['Name', 'Platform', 'Licenses', 'Assigned', 'Available', 'Price', 'Expires'].map(col => (
                <th key={col} style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-muted, #6e7681)', borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>Loading...</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>No apps found</td></tr>
            ) : filtered.map(item => {
              const expiresSoon = item.expires !== 'N/A' && item.expires !== '—' &&
                (new Date(item.expires).getTime() - now.getTime()) / (1000 * 60 * 60 * 24) <= 90;
              return (
                <tr key={item.id} style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                  <td style={{ padding: '11px 16px', fontWeight: 600, color: 'var(--text-primary, #e4e6ea)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <CubeIcon style={{ width: 15, height: 15, color: '#006FFF', flexShrink: 0 }} />
                      {item.name}
                    </div>
                  </td>
                  <td style={{ padding: '11px 16px' }}>{platformBadge(item.platform)}</td>
                  <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>{item.licenses}</td>
                  <td style={{ padding: '11px 16px', minWidth: 120 }}>
                    <div style={{ marginBottom: 2, fontSize: 12, color: 'var(--text-secondary, #8b949e)' }}>{item.assigned}</div>
                    {utilizationBar(item.assigned, item.licenses)}
                  </td>
                  <td style={{ padding: '11px 16px', color: item.available <= 2 ? '#f85149' : 'var(--text-secondary, #8b949e)' }}>
                    {item.available}
                  </td>
                  <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)', fontFamily: 'monospace', fontSize: 12 }}>{item.price}</td>
                  <td style={{ padding: '11px 16px', color: expiresSoon ? '#d29922' : 'var(--text-muted, #6e7681)', fontSize: 12 }}>
                    {expiresSoon && <ExclamationTriangleIcon style={{ width: 12, height: 12, display: 'inline', marginRight: 4 }} />}
                    {item.expires}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
