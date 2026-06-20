'use client';
import React, { useState, useEffect } from 'react';
import {
  PlusIcon,
  ArrowPathIcon,
  MapPinIcon,
  ServerIcon,
  XMarkIcon,
  ArrowUpTrayIcon,
} from '@heroicons/react/24/outline';

interface Site {
  id: string;
  name: string;
  address: string;
  devices: number;
  status: 'online' | 'offline' | 'degraded';
  subnet: string;
  lastSeen: string;
}

const MOCK_SITES: Site[] = [
  { id: '1', name: 'Headquarters', address: 'Zurich, CH', devices: 42, status: 'online', subnet: '10.0.1.0/24', lastSeen: '2 min ago' },
  { id: '2', name: 'Berlin Office', address: 'Berlin, DE', devices: 18, status: 'online', subnet: '10.0.2.0/24', lastSeen: '5 min ago' },
  { id: '3', name: 'London Branch', address: 'London, UK', devices: 31, status: 'online', subnet: '10.0.3.0/24', lastSeen: '1 min ago' },
  { id: '4', name: 'Remote Data Center', address: 'Frankfurt, DE', devices: 12, status: 'degraded', subnet: '10.1.0.0/24', lastSeen: '15 min ago' },
  { id: '5', name: 'Warsaw Office', address: 'Warsaw, PL', devices: 0, status: 'offline', subnet: '10.0.5.0/24', lastSeen: '3 days ago' },
];

interface NewSiteForm {
  name: string;
  address: string;
  subnet: string;
  description: string;
}

export default function LocationsView() {
  const [items, setItems] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState<NewSiteForm>({ name: '', address: '', subnet: '', description: '' });
  const [saving, setSaving] = useState(false);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      // No backend exists yet — use mock data
      await new Promise(r => setTimeout(r, 300));
      setItems(MOCK_SITES);
    } catch {
      setItems(MOCK_SITES);
    } finally {
      setLoading(false);
    }
  }

  const filtered = items.filter(i =>
    i.name.toLowerCase().includes(search.toLowerCase()) ||
    i.address.toLowerCase().includes(search.toLowerCase()) ||
    i.subnet.includes(search)
  );

  const online = items.filter(i => i.status === 'online').length;
  const offline = items.filter(i => i.status === 'offline').length;
  const totalDevices = items.reduce((s, i) => s + i.devices, 0);

  const statusBadge = (status: string) => {
    const map: Record<string, { bg: string; color: string; label: string }> = {
      online:   { bg: 'rgba(63,185,80,0.15)',   color: '#3fb950', label: 'Online' },
      offline:  { bg: 'rgba(110,118,129,0.15)', color: '#6e7681', label: 'Offline' },
      degraded: { bg: 'rgba(210,153,34,0.15)',  color: '#d29922', label: 'Degraded' },
    };
    const s = map[status] ?? map['offline'];
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: s.bg, color: s.color }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color, display: 'inline-block' }} />
        {s.label}
      </span>
    );
  };

  async function handleAddSite(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await new Promise(r => setTimeout(r, 400));
      const newSite: Site = {
        id: String(Date.now()),
        name: form.name,
        address: form.address,
        devices: 0,
        status: 'online',
        subnet: form.subnet,
        lastSeen: 'Just now',
      };
      setItems(prev => [...prev, newSite]);
      setForm({ name: '', address: '', subnet: '', description: '' });
      setShowModal(false);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={{ padding: '24px 28px', minHeight: '100vh', background: 'var(--bg-base, #0e1115)' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Locations & Sites</h1>
        <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginTop: 4, marginBottom: 0 }}>Network sites and physical locations</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>TOTAL SITES</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{items.length}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Registered locations</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>ONLINE</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: '#3fb950' }}>{online}</div>
          <div style={{ fontSize: 12, color: '#3fb950', marginTop: 4 }}>Sites reachable</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>OFFLINE</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: offline > 0 ? '#f85149' : 'var(--text-primary, #e4e6ea)' }}>{offline}</div>
          <div style={{ fontSize: 12, color: offline > 0 ? '#f85149' : '#8b949e', marginTop: 4 }}>Unreachable</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>DEVICES</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{totalDevices}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Across all sites</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button className="fluent-btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={() => setShowModal(true)}>
          <PlusIcon style={{ width: 14, height: 14 }} />
          Add Site
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ArrowUpTrayIcon style={{ width: 14, height: 14 }} />
          Import from CSV
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={load} disabled={loading}>
          <ArrowPathIcon style={{ width: 14, height: 14 }} />
          Refresh
        </button>
        <div style={{ marginLeft: 'auto' }}>
          <input
            type="search"
            placeholder="Search sites..."
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
              {['Name', 'Address', 'Devices', 'Status', 'Subnet', 'Last Seen'].map(col => (
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
              <tr><td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>No sites found</td></tr>
            ) : filtered.map(item => (
              <tr key={item.id} style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                <td style={{ padding: '11px 16px', fontWeight: 600, color: 'var(--text-primary, #e4e6ea)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <MapPinIcon style={{ width: 15, height: 15, color: '#006FFF', flexShrink: 0 }} />
                  {item.name}
                </td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>{item.address}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    <ServerIcon style={{ width: 13, height: 13 }} />
                    {item.devices}
                  </span>
                </td>
                <td style={{ padding: '11px 16px' }}>{statusBadge(item.status)}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-muted, #6e7681)', fontFamily: 'monospace', fontSize: 12 }}>{item.subnet}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-muted, #6e7681)', fontSize: 12 }}>{item.lastSeen}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Add Site Modal */}
      {showModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }} onClick={() => setShowModal(false)}>
          <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border-strong, rgba(255,255,255,0.14))', borderRadius: 14, width: '100%', maxWidth: 480, overflow: 'hidden' }} onClick={e => e.stopPropagation()}>
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Add Site</h2>
              <button onClick={() => setShowModal(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted, #6e7681)', padding: 4 }}>
                <XMarkIcon style={{ width: 18, height: 18 }} />
              </button>
            </div>
            <form onSubmit={handleAddSite} style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 14 }}>
              {[
                { label: 'Name', key: 'name', placeholder: 'e.g. New York Office', required: true },
                { label: 'Address', key: 'address', placeholder: 'e.g. New York, US', required: true },
                { label: 'Subnet', key: 'subnet', placeholder: 'e.g. 10.0.4.0/24', required: false },
                { label: 'Description', key: 'description', placeholder: 'Optional description', required: false },
              ].map(field => (
                <div key={field.key}>
                  <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>{field.label}</label>
                  <input
                    type="text"
                    placeholder={field.placeholder}
                    required={field.required}
                    value={(form as any)[field.key]}
                    onChange={e => setForm(prev => ({ ...prev, [field.key]: e.target.value }))}
                    style={{ width: '100%', padding: '8px 12px', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, color: 'var(--text-primary, #e4e6ea)', fontSize: 13, outline: 'none', boxSizing: 'border-box' }}
                  />
                </div>
              ))}
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
                <button type="button" className="fluent-btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
                <button type="submit" className="fluent-btn-primary" disabled={saving}>
                  {saving ? 'Adding...' : 'Add Site'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
