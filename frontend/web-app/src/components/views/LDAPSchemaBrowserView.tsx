'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  CircleStackIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  XCircleIcon,
  InformationCircleIcon,
  TagIcon,
  ListBulletIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ObjectClass {
  oid: string;
  name: string;
  description?: string;
  superClasses?: string[];
  must?: string[];
  may?: string[];
  type?: string; // STRUCTURAL | AUXILIARY | ABSTRACT
}

interface AttributeType {
  oid: string;
  name: string;
  description?: string;
  syntax?: string;
  singleValue?: boolean;
  equality?: string;
  ordering?: string;
  substrings?: string;
}

type Tab = 'objectClasses' | 'attributeTypes';

// ─── Add Object Class Modal ────────────────────────────────────────────────────

function AddObjectClassModal({
  onClose,
  onAdded,
}: {
  onClose: () => void;
  onAdded: () => void;
}) {
  const [form, setForm] = useState({
    oid: '',
    name: '',
    description: '',
    superClasses: '',
    must: '',
    may: '',
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.oid.trim()) { setError('OID is required.'); return; }
    if (!form.name.trim()) { setError('Name is required.'); return; }
    setSubmitting(true);
    setError('');
    try {
      await api.post('/api/schema/object-classes', {
        oid: form.oid.trim(),
        name: form.name.trim(),
        description: form.description.trim() || undefined,
        superClasses: form.superClasses ? form.superClasses.split(',').map(s => s.trim()).filter(Boolean) : [],
        must: form.must ? form.must.split(',').map(s => s.trim()).filter(Boolean) : [],
        may: form.may ? form.may.split(',').map(s => s.trim()).filter(Boolean) : [],
      });
      onAdded();
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to add object class.');
    } finally {
      setSubmitting(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    width: '100%', padding: '8px 12px', border: '1px solid var(--border-strong)',
    borderRadius: 8, fontSize: 14, outline: 'none', boxSizing: 'border-box',
    fontFamily: 'inherit', background: 'var(--bg-overlay)', color: 'var(--text-primary)',
  };
  const labelStyle: React.CSSProperties = {
    display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 4,
  };
  const hintStyle: React.CSSProperties = {
    fontSize: 11, color: 'var(--text-muted)', marginTop: 3,
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 50,
      background: 'rgba(0,0,0,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: 'var(--bg-surface)', borderRadius: 12, padding: 28, width: 520, maxWidth: '95vw',
        boxShadow: '0 20px 60px rgba(0,0,0,0.18)', maxHeight: '90vh', overflowY: 'auto',
        border: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Add Object Class</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <XCircleIcon style={{ width: 22, height: 22 }} />
          </button>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={labelStyle}>OID *</label>
            <input style={inputStyle} placeholder="e.g. 1.3.6.1.4.1.99999.1" value={form.oid}
              onChange={e => setForm(f => ({ ...f, oid: e.target.value }))} />
          </div>
          <div>
            <label style={labelStyle}>Name *</label>
            <input style={inputStyle} placeholder="e.g. myCustomObject" value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          </div>
          <div>
            <label style={labelStyle}>Description</label>
            <input style={inputStyle} placeholder="Optional description" value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>
          <div>
            <label style={labelStyle}>Superclasses</label>
            <input style={inputStyle} placeholder="Comma-separated, e.g. top, person" value={form.superClasses}
              onChange={e => setForm(f => ({ ...f, superClasses: e.target.value }))} />
            <p style={hintStyle}>Comma-separated list of parent object classes</p>
          </div>
          <div>
            <label style={labelStyle}>Must Attributes (required)</label>
            <input style={inputStyle} placeholder="e.g. cn, sn" value={form.must}
              onChange={e => setForm(f => ({ ...f, must: e.target.value }))} />
            <p style={hintStyle}>Comma-separated attribute names</p>
          </div>
          <div>
            <label style={labelStyle}>May Attributes (optional)</label>
            <input style={inputStyle} placeholder="e.g. mail, telephoneNumber" value={form.may}
              onChange={e => setForm(f => ({ ...f, may: e.target.value }))} />
            <p style={hintStyle}>Comma-separated attribute names</p>
          </div>

          {error && (
            <div style={{
              background: 'var(--danger-light)', border: '1px solid var(--danger)', borderRadius: 8,
              padding: '10px 12px', color: 'var(--danger)', fontSize: 13,
            }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 4 }}>
            <button type="button" onClick={onClose} style={{
              padding: '8px 18px', borderRadius: 8, border: '1px solid var(--border-strong)',
              background: 'var(--bg-overlay)', color: 'var(--text-secondary)', fontSize: 14, fontWeight: 500, cursor: 'pointer',
            }}>Cancel</button>
            <button type="submit" disabled={submitting} style={{
              padding: '8px 18px', borderRadius: 8, border: 'none',
              background: submitting ? '#93c5fd' : '#0066CC', color: '#fff',
              fontSize: 14, fontWeight: 500, cursor: submitting ? 'not-allowed' : 'pointer',
            }}>
              {submitting ? 'Adding…' : 'Add Object Class'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Add Attribute Type Modal ──────────────────────────────────────────────────

function AddAttributeTypeModal({
  onClose,
  onAdded,
}: {
  onClose: () => void;
  onAdded: () => void;
}) {
  const [form, setForm] = useState({
    oid: '',
    name: '',
    description: '',
    syntax: '',
    singleValue: false,
    equality: '',
    ordering: '',
    substrings: '',
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.oid.trim()) { setError('OID is required.'); return; }
    if (!form.name.trim()) { setError('Name is required.'); return; }
    setSubmitting(true);
    setError('');
    try {
      await api.post('/api/schema/attribute-types', {
        oid: form.oid.trim(),
        name: form.name.trim(),
        description: form.description.trim() || undefined,
        syntax: form.syntax.trim() || undefined,
        singleValue: form.singleValue,
        equality: form.equality.trim() || undefined,
        ordering: form.ordering.trim() || undefined,
        substrings: form.substrings.trim() || undefined,
      });
      onAdded();
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to add attribute type.');
    } finally {
      setSubmitting(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    width: '100%', padding: '8px 12px', border: '1px solid var(--border-strong)',
    borderRadius: 8, fontSize: 14, outline: 'none', boxSizing: 'border-box',
    fontFamily: 'inherit', background: 'var(--bg-overlay)', color: 'var(--text-primary)',
  };
  const labelStyle: React.CSSProperties = {
    display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 4,
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 50,
      background: 'rgba(0,0,0,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: 'var(--bg-surface)', borderRadius: 12, padding: 28, width: 520, maxWidth: '95vw',
        boxShadow: '0 20px 60px rgba(0,0,0,0.18)', maxHeight: '90vh', overflowY: 'auto',
        border: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Add Attribute Type</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <XCircleIcon style={{ width: 22, height: 22 }} />
          </button>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={labelStyle}>OID *</label>
            <input style={inputStyle} placeholder="e.g. 1.3.6.1.4.1.99999.2.1" value={form.oid}
              onChange={e => setForm(f => ({ ...f, oid: e.target.value }))} />
          </div>
          <div>
            <label style={labelStyle}>Name *</label>
            <input style={inputStyle} placeholder="e.g. myCustomAttribute" value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          </div>
          <div>
            <label style={labelStyle}>Description</label>
            <input style={inputStyle} placeholder="Optional description" value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>
          <div>
            <label style={labelStyle}>Syntax OID</label>
            <input style={inputStyle} placeholder="e.g. 1.3.6.1.4.1.1466.115.121.1.15 (DirectoryString)" value={form.syntax}
              onChange={e => setForm(f => ({ ...f, syntax: e.target.value }))} />
          </div>
          <div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 14, color: 'var(--text-secondary)', fontWeight: 500 }}>
              <input
                type="checkbox"
                checked={form.singleValue}
                onChange={e => setForm(f => ({ ...f, singleValue: e.target.checked }))}
                style={{ width: 16, height: 16, accentColor: '#0066CC' }}
              />
              Single-valued attribute
            </label>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <label style={labelStyle}>Equality Rule</label>
              <input style={inputStyle} placeholder="e.g. caseIgnoreMatch" value={form.equality}
                onChange={e => setForm(f => ({ ...f, equality: e.target.value }))} />
            </div>
            <div>
              <label style={labelStyle}>Ordering Rule</label>
              <input style={inputStyle} placeholder="e.g. caseIgnoreOrderingMatch" value={form.ordering}
                onChange={e => setForm(f => ({ ...f, ordering: e.target.value }))} />
            </div>
          </div>
          <div>
            <label style={labelStyle}>Substring Rule</label>
            <input style={inputStyle} placeholder="e.g. caseIgnoreSubstringsMatch" value={form.substrings}
              onChange={e => setForm(f => ({ ...f, substrings: e.target.value }))} />
          </div>

          {error && (
            <div style={{
              background: 'var(--danger-light)', border: '1px solid var(--danger)', borderRadius: 8,
              padding: '10px 12px', color: 'var(--danger)', fontSize: 13,
            }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 4 }}>
            <button type="button" onClick={onClose} style={{
              padding: '8px 18px', borderRadius: 8, border: '1px solid var(--border-strong)',
              background: 'var(--bg-overlay)', color: 'var(--text-secondary)', fontSize: 14, fontWeight: 500, cursor: 'pointer',
            }}>Cancel</button>
            <button type="submit" disabled={submitting} style={{
              padding: '8px 18px', borderRadius: 8, border: 'none',
              background: submitting ? '#93c5fd' : '#0066CC', color: '#fff',
              fontSize: 14, fontWeight: 500, cursor: submitting ? 'not-allowed' : 'pointer',
            }}>
              {submitting ? 'Adding…' : 'Add Attribute Type'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Object Class Detail Panel ─────────────────────────────────────────────────

function ObjectClassDetail({ oc }: { oc: ObjectClass }) {
  const chip = (text: string, bg: string, color: string) => (
    <span key={text} style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 9999,
      background: bg, color, fontSize: 12, fontWeight: 500, marginRight: 4, marginBottom: 4,
      fontFamily: 'monospace',
    }}>
      {text}
    </span>
  );

  const row = (label: string, value: React.ReactNode) => (
    <div key={label} style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
      <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', minWidth: 110, textTransform: 'uppercase', letterSpacing: '0.04em', paddingTop: 2 }}>
        {label}
      </span>
      <div style={{ fontSize: 13, color: 'var(--text-primary)', flex: 1 }}>{value}</div>
    </div>
  );

  return (
    <div style={{ padding: '20px 24px' }}>
      <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 4px' }}>{oc.name}</h3>
      <p style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-muted)', margin: '0 0 20px' }}>{oc.oid}</p>

      {oc.description && (
        <div style={{
          background: 'var(--bg-surface-raised)', border: '1px solid var(--border)', borderRadius: 8,
          padding: '10px 14px', marginBottom: 20,
        }}>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>{oc.description}</p>
        </div>
      )}

      {row('Type', oc.type ? (
        <span style={{
          display: 'inline-block', padding: '2px 10px', borderRadius: 9999, fontSize: 12, fontWeight: 500,
          background: oc.type === 'STRUCTURAL' ? 'var(--accent-light)' : oc.type === 'AUXILIARY' ? 'var(--success-light)' : 'var(--bg-overlay)',
          color: oc.type === 'STRUCTURAL' ? 'var(--accent)' : oc.type === 'AUXILIARY' ? 'var(--success)' : 'var(--text-muted)',
          border: `1px solid ${oc.type === 'STRUCTURAL' ? 'var(--accent)' : oc.type === 'AUXILIARY' ? 'var(--success)' : 'var(--border)'}`,
        }}>
          {oc.type}
        </span>
      ) : <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>—</span>)}

      {row('Superclasses', oc.superClasses && oc.superClasses.length > 0
        ? <div>{oc.superClasses.map(sc => chip(sc, 'var(--bg-overlay)', 'var(--text-secondary)'))}</div>
        : <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>None</span>
      )}

      {row('Must Have', oc.must && oc.must.length > 0
        ? <div>{oc.must.map(a => chip(a, 'var(--danger-light)', 'var(--danger)'))}</div>
        : <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>None</span>
      )}

      {row('May Have', oc.may && oc.may.length > 0
        ? <div>{oc.may.map(a => chip(a, 'var(--success-light)', 'var(--success)'))}</div>
        : <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>None</span>
      )}
    </div>
  );
}

// ─── Attribute Type Detail Panel ──────────────────────────────────────────────

function AttributeTypeDetail({ at }: { at: AttributeType }) {
  const row = (label: string, value: React.ReactNode) => (
    <div key={label} style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
      <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', minWidth: 110, textTransform: 'uppercase', letterSpacing: '0.04em', paddingTop: 2 }}>
        {label}
      </span>
      <div style={{ fontSize: 13, color: 'var(--text-primary)', flex: 1 }}>{value}</div>
    </div>
  );

  const mono = (text: string) => (
    <code style={{ fontFamily: 'monospace', fontSize: 12, background: 'var(--bg-overlay)', padding: '2px 6px', borderRadius: 4, color: 'var(--text-secondary)' }}>
      {text}
    </code>
  );

  return (
    <div style={{ padding: '20px 24px' }}>
      <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 4px' }}>{at.name}</h3>
      <p style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-muted)', margin: '0 0 20px' }}>{at.oid}</p>

      {at.description && (
        <div style={{
          background: 'var(--bg-surface-raised)', border: '1px solid var(--border)', borderRadius: 8,
          padding: '10px 14px', marginBottom: 20,
        }}>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>{at.description}</p>
        </div>
      )}

      {row('Syntax', at.syntax ? mono(at.syntax) : <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>—</span>)}
      {row('Single-valued', (
        <span style={{
          display: 'inline-block', padding: '2px 10px', borderRadius: 9999, fontSize: 12, fontWeight: 500,
          background: at.singleValue ? 'var(--accent-light)' : 'var(--bg-overlay)',
          color: at.singleValue ? 'var(--accent)' : 'var(--text-muted)',
          border: `1px solid ${at.singleValue ? 'var(--accent)' : 'var(--border)'}`,
        }}>
          {at.singleValue ? 'Yes' : 'No'}
        </span>
      ))}
      {row('Equality', at.equality ? mono(at.equality) : <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>—</span>)}
      {row('Ordering', at.ordering ? mono(at.ordering) : <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>—</span>)}
      {row('Substrings', at.substrings ? mono(at.substrings) : <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>—</span>)}
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────

export default function LDAPSchemaBrowserView() {
  const [tab, setTab] = useState<Tab>('objectClasses');
  const [search, setSearch] = useState('');

  const [objectClasses, setObjectClasses] = useState<ObjectClass[]>([]);
  const [attributeTypes, setAttributeTypes] = useState<AttributeType[]>([]);
  const [loadingOC, setLoadingOC] = useState(true);
  const [loadingAT, setLoadingAT] = useState(true);
  const [errorOC, setErrorOC] = useState('');
  const [errorAT, setErrorAT] = useState('');

  const [selectedOC, setSelectedOC] = useState<ObjectClass | null>(null);
  const [selectedAT, setSelectedAT] = useState<AttributeType | null>(null);

  const [showAddOC, setShowAddOC] = useState(false);
  const [showAddAT, setShowAddAT] = useState(false);

  const fetchObjectClasses = useCallback(async () => {
    setLoadingOC(true);
    setErrorOC('');
    try {
      const res = await api.get('/api/schema/object-classes');
      const raw = res.data;
      const list: any[] = raw.objectClasses ?? raw.data ?? (Array.isArray(raw) ? raw : []);
      const normalized: ObjectClass[] = list.map((oc: any) => ({
        oid: oc.oid || oc.numericOid || '',
        name: oc.name || (Array.isArray(oc.names) ? oc.names[0] : '') || 'Unknown',
        description: oc.description || oc.desc || undefined,
        superClasses: oc.superClasses || oc.sup || [],
        must: oc.must || oc.mustAttributes || [],
        may: oc.may || oc.mayAttributes || [],
        type: oc.type || oc.kind || undefined,
      }));
      setObjectClasses(normalized);
      if (!selectedOC && normalized.length > 0) setSelectedOC(normalized[0]);
    } catch (err: any) {
      setErrorOC(err?.response?.data?.error || err?.message || 'Failed to load object classes.');
    } finally {
      setLoadingOC(false);
    }
  }, [selectedOC]);

  const fetchAttributeTypes = useCallback(async () => {
    setLoadingAT(true);
    setErrorAT('');
    try {
      const res = await api.get('/api/schema/attribute-types');
      const raw = res.data;
      const list: any[] = raw.attributeTypes ?? raw.data ?? (Array.isArray(raw) ? raw : []);
      const normalized: AttributeType[] = list.map((at: any) => ({
        oid: at.oid || at.numericOid || '',
        name: at.name || (Array.isArray(at.names) ? at.names[0] : '') || 'Unknown',
        description: at.description || at.desc || undefined,
        syntax: at.syntax || at.syntaxOid || undefined,
        singleValue: Boolean(at.singleValue || at.single_value),
        equality: at.equality || at.equalityMatchingRule || undefined,
        ordering: at.ordering || at.orderingMatchingRule || undefined,
        substrings: at.substrings || at.substringMatchingRule || undefined,
      }));
      setAttributeTypes(normalized);
      if (!selectedAT && normalized.length > 0) setSelectedAT(normalized[0]);
    } catch (err: any) {
      setErrorAT(err?.response?.data?.error || err?.message || 'Failed to load attribute types.');
    } finally {
      setLoadingAT(false);
    }
  }, [selectedAT]);

  useEffect(() => {
    fetchObjectClasses();
    fetchAttributeTypes();
  }, []);   // eslint-disable-line react-hooks/exhaustive-deps

  // Filter helpers
  const filteredOC = objectClasses.filter(oc =>
    !search || oc.name.toLowerCase().includes(search.toLowerCase()) || oc.oid.includes(search)
  );
  const filteredAT = attributeTypes.filter(at =>
    !search || at.name.toLowerCase().includes(search.toLowerCase()) || at.oid.includes(search)
  );

  const tabStyle = (active: boolean): React.CSSProperties => ({
    padding: '8px 20px', borderRadius: 8, border: 'none', cursor: 'pointer',
    fontSize: 14, fontWeight: 500,
    background: active ? '#0066CC' : 'transparent',
    color: active ? '#fff' : 'var(--text-muted)',
    transition: 'background 0.15s, color 0.15s',
  });

  const listItemStyle = (selected: boolean): React.CSSProperties => ({
    padding: '10px 16px', cursor: 'pointer', borderBottom: '1px solid var(--border)',
    background: selected ? 'var(--accent-light)' : 'var(--bg-surface)',
    borderLeft: selected ? '3px solid var(--accent)' : '3px solid transparent',
    transition: 'background 0.1s',
  });

  return (
    <div style={{ padding: 24, fontFamily: 'inherit' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 36, height: 36, background: 'var(--accent-light)', border: '1px solid var(--accent)',
            borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <CircleStackIcon style={{ width: 20, height: 20, color: '#0066CC' }} />
          </div>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>LDAP Schema Browser</h1>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0 }}>
              {objectClasses.length} object classes · {attributeTypes.length} attribute types
            </p>
          </div>
        </div>

        {/* Add button — context-aware */}
        {tab === 'objectClasses' ? (
          <button
            onClick={() => setShowAddOC(true)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '8px 16px', background: '#0066CC', color: '#fff',
              border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 500, cursor: 'pointer',
            }}
          >
            <PlusIcon style={{ width: 16, height: 16 }} />
            Add Object Class
          </button>
        ) : (
          <button
            onClick={() => setShowAddAT(true)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '8px 16px', background: '#0066CC', color: '#fff',
              border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 500, cursor: 'pointer',
            }}
          >
            <PlusIcon style={{ width: 16, height: 16 }} />
            Add Attribute Type
          </button>
        )}
      </div>

      {/* Tab bar + search */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: 20, gap: 16,
      }}>
        <div style={{ display: 'flex', gap: 4, background: 'var(--bg-surface-raised)', borderRadius: 10, padding: 4 }}>
          <button
            style={tabStyle(tab === 'objectClasses')}
            onClick={() => { setTab('objectClasses'); setSearch(''); }}
          >
            <ListBulletIcon style={{ width: 15, height: 15, display: 'inline', marginRight: 6, verticalAlign: 'text-bottom' }} />
            Object Classes
          </button>
          <button
            style={tabStyle(tab === 'attributeTypes')}
            onClick={() => { setTab('attributeTypes'); setSearch(''); }}
          >
            <TagIcon style={{ width: 15, height: 15, display: 'inline', marginRight: 6, verticalAlign: 'text-bottom' }} />
            Attribute Types
          </button>
        </div>

        {/* Search */}
        <div style={{ position: 'relative', width: 280 }}>
          <MagnifyingGlassIcon style={{
            position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)',
            width: 16, height: 16, color: 'var(--text-muted)', pointerEvents: 'none',
          }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={tab === 'objectClasses' ? 'Search object classes…' : 'Search attribute types…'}
            style={{
              width: '100%', padding: '8px 12px 8px 32px', border: '1px solid var(--border-strong)',
              borderRadius: 8, fontSize: 14, outline: 'none', boxSizing: 'border-box',
              fontFamily: 'inherit', background: 'var(--bg-surface)', color: 'var(--text-primary)',
            }}
          />
        </div>
      </div>

      {/* Main panel — list + detail */}
      <div style={{
        display: 'grid', gridTemplateColumns: '300px 1fr', gap: 0,
        background: 'var(--bg-surface)', borderRadius: 10, border: '1px solid var(--border)',
        overflow: 'hidden', minHeight: 480,
      }}>

        {/* ── Object Classes tab ── */}
        {tab === 'objectClasses' && (
          <>
            {/* List */}
            <div style={{ borderRight: '1px solid var(--border)', overflowY: 'auto', maxHeight: 600 }}>
              {loadingOC ? (
                <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 14 }}>Loading…</div>
              ) : errorOC ? (
                <div style={{ padding: 24 }}>
                  <p style={{ color: 'var(--danger)', fontSize: 13, marginBottom: 8 }}>{errorOC}</p>
                  <button onClick={fetchObjectClasses} style={{ fontSize: 12, padding: '4px 10px', border: '1px solid var(--border-strong)', borderRadius: 6, cursor: 'pointer', background: 'var(--bg-overlay)', color: 'var(--text-secondary)' }}>
                    Retry
                  </button>
                </div>
              ) : filteredOC.length === 0 ? (
                <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 14 }}>
                  {search ? 'No results found.' : 'No object classes.'}
                </div>
              ) : (
                filteredOC.map(oc => (
                  <div
                    key={oc.oid}
                    style={listItemStyle(selectedOC?.oid === oc.oid)}
                    onClick={() => setSelectedOC(oc)}
                  >
                    <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', margin: 0 }}>{oc.name}</p>
                    <p style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)', margin: '2px 0 0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {oc.oid}
                    </p>
                  </div>
                ))
              )}
            </div>

            {/* Detail */}
            <div style={{ overflowY: 'auto', maxHeight: 600 }}>
              {selectedOC ? (
                <ObjectClassDetail oc={selectedOC} />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', gap: 8 }}>
                  <InformationCircleIcon style={{ width: 32, height: 32 }} />
                  <p style={{ fontSize: 14, margin: 0 }}>Select an object class to view details</p>
                </div>
              )}
            </div>
          </>
        )}

        {/* ── Attribute Types tab ── */}
        {tab === 'attributeTypes' && (
          <>
            {/* List */}
            <div style={{ borderRight: '1px solid var(--border)', overflowY: 'auto', maxHeight: 600 }}>
              {loadingAT ? (
                <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 14 }}>Loading…</div>
              ) : errorAT ? (
                <div style={{ padding: 24 }}>
                  <p style={{ color: 'var(--danger)', fontSize: 13, marginBottom: 8 }}>{errorAT}</p>
                  <button onClick={fetchAttributeTypes} style={{ fontSize: 12, padding: '4px 10px', border: '1px solid var(--border-strong)', borderRadius: 6, cursor: 'pointer', background: 'var(--bg-overlay)', color: 'var(--text-secondary)' }}>
                    Retry
                  </button>
                </div>
              ) : filteredAT.length === 0 ? (
                <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 14 }}>
                  {search ? 'No results found.' : 'No attribute types.'}
                </div>
              ) : (
                filteredAT.map(at => (
                  <div
                    key={at.oid}
                    style={listItemStyle(selectedAT?.oid === at.oid)}
                    onClick={() => setSelectedAT(at)}
                  >
                    <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', margin: 0 }}>{at.name}</p>
                    <p style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)', margin: '2px 0 0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {at.oid}
                    </p>
                  </div>
                ))
              )}
            </div>

            {/* Detail */}
            <div style={{ overflowY: 'auto', maxHeight: 600 }}>
              {selectedAT ? (
                <AttributeTypeDetail at={selectedAT} />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', gap: 8 }}>
                  <InformationCircleIcon style={{ width: 32, height: 32 }} />
                  <p style={{ fontSize: 14, margin: 0 }}>Select an attribute type to view details</p>
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* Modals */}
      {showAddOC && (
        <AddObjectClassModal
          onClose={() => setShowAddOC(false)}
          onAdded={() => { fetchObjectClasses(); }}
        />
      )}
      {showAddAT && (
        <AddAttributeTypeModal
          onClose={() => setShowAddAT(false)}
          onAdded={() => { fetchAttributeTypes(); }}
        />
      )}
    </div>
  );
}
