'use client';

import React, { useState, useRef, useCallback, useEffect } from 'react';
import {
  PlayIcon,
  ClipboardDocumentIcon,
  ClockIcon,
  TrashIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline';

// ── Types ──────────────────────────────────────────────────────────────────────

type HttpMethod = 'GET' | 'POST' | 'PATCH' | 'DELETE';

interface HistoryEntry {
  id: string;
  method: HttpMethod;
  url: string;
  body?: string;
  timestamp: number;
  statusCode?: number;
}

interface QueryResult {
  statusCode: number;
  durationMs: number;
  body: unknown;
}

// ── Shortcut definitions ───────────────────────────────────────────────────────

const SHORTCUTS: { label: string; method: HttpMethod; url: string; body?: string }[] = [
  { label: 'All Users',   method: 'GET',  url: '/api/graph/v1.0/users' },
  { label: 'All Groups',  method: 'GET',  url: '/api/graph/v1.0/groups' },
  { label: 'All Devices', method: 'GET',  url: '/api/graph/v1.0/devices' },
  { label: 'My Profile',  method: 'GET',  url: '/api/graph/v1.0/me' },
];

// ── JSON Syntax Highlighter ───────────────────────────────────────────────────

function highlightJson(value: unknown, indent = 0): React.ReactNode {
  const pad = '  '.repeat(indent);
  const padInner = '  '.repeat(indent + 1);

  if (value === null) {
    return <span style={{ color: '#9ca3af' }}>null</span>;
  }
  if (typeof value === 'boolean') {
    return <span style={{ color: '#f97316' }}>{String(value)}</span>;
  }
  if (typeof value === 'number') {
    return <span style={{ color: '#f97316' }}>{value}</span>;
  }
  if (typeof value === 'string') {
    return <span style={{ color: '#86efac' }}>"{value}"</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span>{'[]'}</span>;
    return (
      <>
        {'['}
        {value.map((item, i) => (
          <div key={i} style={{ marginLeft: '1.5rem' }}>
            {highlightJson(item, indent + 1)}
            {i < value.length - 1 ? ',' : ''}
          </div>
        ))}
        {pad}{']'}
      </>
    );
  }
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return <span>{'{}'}</span>;
    return (
      <>
        {'{'}
        {entries.map(([k, v], i) => (
          <div key={k} style={{ marginLeft: '1.5rem' }}>
            <span style={{ color: '#93c5fd' }}>"{k}"</span>
            <span style={{ color: '#e5e7eb' }}>: </span>
            {highlightJson(v, indent + 1)}
            {i < entries.length - 1 ? ',' : ''}
          </div>
        ))}
        {pad}{'}'}
      </>
    );
  }
  return <span>{String(value)}</span>;
}

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ code }: { code: number }) {
  const color =
    code >= 200 && code < 300 ? '#16a34a' :
    code >= 300 && code < 400 ? '#d97706' :
    '#dc2626';
  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 8px',
      borderRadius: 4,
      fontSize: 12,
      fontWeight: 700,
      color: '#fff',
      backgroundColor: color,
      marginRight: 8,
    }}>
      {code}
    </span>
  );
}

// ── Method badge ──────────────────────────────────────────────────────────────

const METHOD_COLORS: Record<HttpMethod, string> = {
  GET:    '#2563eb',
  POST:   '#16a34a',
  PATCH:  '#d97706',
  DELETE: '#dc2626',
};

function MethodBadge({ method }: { method: HttpMethod }) {
  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 6px',
      borderRadius: 3,
      fontSize: 10,
      fontWeight: 700,
      color: '#fff',
      backgroundColor: METHOD_COLORS[method] || '#6b7280',
      marginRight: 6,
      minWidth: 48,
      textAlign: 'center',
    }}>
      {method}
    </span>
  );
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function GraphExplorerView() {
  const [method, setMethod]   = useState<HttpMethod>('GET');
  const [url, setUrl]         = useState('/api/graph/v1.0/');
  const [body, setBody]       = useState('{\n  \n}');
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState<QueryResult | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [copyMsg, setCopyMsg] = useState<'url' | 'body' | null>(null);
  const urlRef = useRef<HTMLInputElement>(null);

  // Persist history to localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem('graph_explorer_history');
      if (stored) setHistory(JSON.parse(stored));
    } catch { /* ignore */ }
  }, []);

  const persistHistory = (entries: HistoryEntry[]) => {
    try { localStorage.setItem('graph_explorer_history', JSON.stringify(entries)); } catch { /* ignore */ }
  };

  const runQuery = useCallback(async () => {
    if (!url.trim() || loading) return;
    setLoading(true);
    const start = performance.now();

    try {
      const opts: RequestInit = {
        method,
        headers: { 'Content-Type': 'application/json' },
      };
      if ((method === 'POST' || method === 'PATCH') && body.trim()) {
        opts.body = body;
      }

      const res = await fetch(url, opts);
      const durationMs = Math.round(performance.now() - start);
      let parsed: unknown;
      try { parsed = await res.json(); } catch { parsed = await res.text(); }

      const qr: QueryResult = { statusCode: res.status, durationMs, body: parsed };
      setResult(qr);

      const entry: HistoryEntry = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        method,
        url,
        body: (method === 'POST' || method === 'PATCH') ? body : undefined,
        timestamp: Date.now(),
        statusCode: res.status,
      };
      setHistory(prev => {
        const next = [entry, ...prev].slice(0, 20);
        persistHistory(next);
        return next;
      });
    } catch (err) {
      const durationMs = Math.round(performance.now() - start);
      setResult({
        statusCode: 0,
        durationMs,
        body: { error: 'Network error', message: String(err) },
      });
    } finally {
      setLoading(false);
    }
  }, [method, url, body, loading]);

  const loadFromHistory = (entry: HistoryEntry) => {
    setMethod(entry.method);
    setUrl(entry.url);
    if (entry.body) setBody(entry.body);
  };

  const loadShortcut = (s: typeof SHORTCUTS[0]) => {
    setMethod(s.method);
    setUrl(s.url);
    if (s.body) setBody(s.body);
  };

  const copyText = (text: string, which: 'url' | 'body') => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopyMsg(which);
    setTimeout(() => setCopyMsg(null), 1500);
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem('graph_explorer_history');
  };

  const showBody = method === 'POST' || method === 'PATCH';

  return (
    <div style={{ display: 'flex', height: '100%', minHeight: 0, fontFamily: 'system-ui, sans-serif' }}>

      {/* ── Left sidebar: history + shortcuts ───────────────────────────── */}
      <div style={{
        width: 220,
        minWidth: 220,
        borderRight: '1px solid #e5e7eb',
        background: '#fff',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
      }}>
        {/* Quick access shortcuts */}
        <div style={{ padding: '12px 12px 6px', borderBottom: '1px solid #f3f4f6' }}>
          <p style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#9ca3af', marginBottom: 8 }}>
            Quick Access
          </p>
          {SHORTCUTS.map(s => (
            <button
              key={s.label}
              onClick={() => loadShortcut(s)}
              style={{
                display: 'flex',
                alignItems: 'center',
                width: '100%',
                padding: '6px 8px',
                marginBottom: 2,
                border: 'none',
                borderRadius: 6,
                background: 'none',
                cursor: 'pointer',
                textAlign: 'left',
                fontSize: 12,
                color: '#374151',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = '#f0f7ff')}
              onMouseLeave={e => (e.currentTarget.style.background = 'none')}
            >
              <ChevronRightIcon style={{ width: 12, height: 12, marginRight: 6, color: '#0066CC' }} />
              {s.label}
            </button>
          ))}
        </div>

        {/* History */}
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px 4px' }}>
            <p style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#9ca3af' }}>
              History
            </p>
            {history.length > 0 && (
              <button
                onClick={clearHistory}
                title="Clear history"
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2 }}
              >
                <TrashIcon style={{ width: 12, height: 12, color: '#9ca3af' }} />
              </button>
            )}
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '0 8px 8px' }}>
            {history.length === 0 && (
              <p style={{ fontSize: 11, color: '#9ca3af', padding: '8px 4px' }}>No history yet</p>
            )}
            {history.map(entry => (
              <button
                key={entry.id}
                onClick={() => loadFromHistory(entry)}
                style={{
                  display: 'block',
                  width: '100%',
                  padding: '6px 8px',
                  marginBottom: 2,
                  border: 'none',
                  borderRadius: 6,
                  background: 'none',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'background 0.1s',
                }}
                onMouseEnter={e => (e.currentTarget.style.background = '#f9fafb')}
                onMouseLeave={e => (e.currentTarget.style.background = 'none')}
              >
                <div style={{ display: 'flex', alignItems: 'center', marginBottom: 2 }}>
                  <MethodBadge method={entry.method} />
                  {entry.statusCode != null && entry.statusCode > 0 && (
                    <span style={{
                      fontSize: 10,
                      fontWeight: 600,
                      color: entry.statusCode < 300 ? '#16a34a' : '#dc2626',
                    }}>
                      {entry.statusCode}
                    </span>
                  )}
                </div>
                <div style={{
                  fontSize: 11,
                  color: '#374151',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: 180,
                }}>
                  {entry.url}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 3, marginTop: 1 }}>
                  <ClockIcon style={{ width: 10, height: 10, color: '#d1d5db' }} />
                  <span style={{ fontSize: 9, color: '#9ca3af' }}>
                    {new Date(entry.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ── Main panel ──────────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, background: '#f9fafb' }}>

        {/* Header */}
        <div style={{ background: '#fff', borderBottom: '1px solid #e5e7eb', padding: '16px 20px' }}>
          <h1 style={{ fontSize: 18, fontWeight: 600, color: '#111827', marginBottom: 2 }}>Graph Explorer</h1>
          <p style={{ fontSize: 12, color: '#6b7280' }}>Microsoft Graph-compatible API explorer</p>
        </div>

        {/* URL bar */}
        <div style={{ background: '#fff', borderBottom: '1px solid #e5e7eb', padding: '12px 20px' }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {/* Method dropdown */}
            <select
              value={method}
              onChange={e => setMethod(e.target.value as HttpMethod)}
              style={{
                padding: '8px 10px',
                border: '1px solid #d1d5db',
                borderRadius: 6,
                fontSize: 13,
                fontWeight: 600,
                color: METHOD_COLORS[method],
                background: '#fff',
                cursor: 'pointer',
                outline: 'none',
                minWidth: 90,
              }}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
            </select>

            {/* URL input */}
            <div style={{ flex: 1, position: 'relative' }}>
              <input
                ref={urlRef}
                value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') runQuery(); }}
                placeholder="/api/graph/v1.0/..."
                style={{
                  width: '100%',
                  padding: '8px 36px 8px 12px',
                  border: '1px solid #d1d5db',
                  borderRadius: 6,
                  fontSize: 13,
                  fontFamily: 'monospace',
                  color: '#111827',
                  background: '#fff',
                  outline: 'none',
                  boxSizing: 'border-box',
                }}
              />
              <button
                onClick={() => copyText(url, 'url')}
                title="Copy URL"
                style={{
                  position: 'absolute',
                  right: 6,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  padding: 4,
                  color: copyMsg === 'url' ? '#16a34a' : '#9ca3af',
                }}
              >
                <ClipboardDocumentIcon style={{ width: 14, height: 14 }} />
              </button>
            </div>

            {/* Run button */}
            <button
              onClick={runQuery}
              disabled={loading || !url.trim()}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '8px 16px',
                background: loading ? '#93c5fd' : '#0066CC',
                color: '#fff',
                border: 'none',
                borderRadius: 6,
                fontSize: 13,
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              <PlayIcon style={{ width: 14, height: 14 }} />
              {loading ? 'Running...' : 'Run'}
            </button>
          </div>
        </div>

        {/* Request body (POST/PATCH only) */}
        {showBody && (
          <div style={{ background: '#fff', borderBottom: '1px solid #e5e7eb', padding: '0 20px 12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0 6px' }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Request Body
              </span>
            </div>
            <textarea
              value={body}
              onChange={e => setBody(e.target.value)}
              rows={5}
              style={{
                width: '100%',
                padding: '10px 12px',
                background: '#1e2432',
                color: '#e5e7eb',
                border: '1px solid #374151',
                borderRadius: 6,
                fontFamily: 'monospace',
                fontSize: 12,
                resize: 'vertical',
                outline: 'none',
                boxSizing: 'border-box',
              }}
              placeholder='{\n  "key": "value"\n}'
            />
          </div>
        )}

        {/* Response panel */}
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', padding: '12px 20px 20px' }}>
          {result == null ? (
            <div style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#9ca3af',
              fontSize: 14,
              flexDirection: 'column',
              gap: 8,
            }}>
              <PlayIcon style={{ width: 32, height: 32, color: '#d1d5db' }} />
              <span>Run a query to see the response</span>
            </div>
          ) : (
            <>
              {/* Response meta bar */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '8px 12px',
                background: '#fff',
                border: '1px solid #e5e7eb',
                borderRadius: '6px 6px 0 0',
                borderBottom: 'none',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <StatusBadge code={result.statusCode} />
                  <span style={{ fontSize: 12, color: '#6b7280' }}>{result.durationMs} ms</span>
                </div>
                <button
                  onClick={() => copyText(JSON.stringify(result.body, null, 2), 'body')}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                    padding: '4px 10px',
                    background: 'none',
                    border: '1px solid #e5e7eb',
                    borderRadius: 4,
                    fontSize: 11,
                    cursor: 'pointer',
                    color: copyMsg === 'body' ? '#16a34a' : '#6b7280',
                  }}
                >
                  <ClipboardDocumentIcon style={{ width: 12, height: 12 }} />
                  {copyMsg === 'body' ? 'Copied!' : 'Copy Response'}
                </button>
              </div>

              {/* Response body */}
              <div style={{
                flex: 1,
                overflowY: 'auto',
                background: '#1e2432',
                border: '1px solid #374151',
                borderRadius: '0 0 6px 6px',
                padding: '12px 16px',
              }}>
                <pre style={{
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: '#e5e7eb',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  margin: 0,
                }}>
                  {highlightJson(result.body)}
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
