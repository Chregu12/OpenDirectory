'use client';

import React, { useState, useCallback } from 'react';

// ── Types ──────────────────────────────────────────────────────────────────────

type ActionType = 'read' | 'write' | 'delete' | 'execute' | 'admin';

interface MatchedPolicy {
  name: string;
  effect: 'Allow' | 'Deny';
  priority?: number;
}

interface EvaluatedCondition {
  name: string;
  met: boolean;
  description?: string;
}

interface SimulateResponse {
  allowed: boolean;
  matchedPolicies: MatchedPolicy[];
  reason: string;
  conditions?: EvaluatedCondition[];
}

interface HistoryEntry {
  id: string;
  userId: string;
  deviceId: string;
  resource: string;
  action: ActionType;
  result: 'ALLOWED' | 'DENIED';
  timestamp: number;
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function PolicySimulatorView() {
  const [userId, setUserId]       = useState('');
  const [deviceId, setDeviceId]   = useState('');
  const [resource, setResource]   = useState('');
  const [action, setAction]       = useState<ActionType>('read');
  const [loading, setLoading]     = useState(false);
  const [result, setResult]       = useState<SimulateResponse | null>(null);
  const [serviceError, setServiceError] = useState(false);
  const [history, setHistory]     = useState<HistoryEntry[]>([]);

  const simulate = useCallback(async () => {
    if (!userId.trim() || !resource.trim() || loading) return;

    setLoading(true);
    setServiceError(false);
    setResult(null);

    try {
      const res = await fetch('/api/simulator/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          policyId: 'what-if',
          changes: {
            userId: userId.trim(),
            deviceId: deviceId.trim() || undefined,
            resource: resource.trim(),
            action,
          },
          scope: {},
        }),
      });

      let parsed: SimulateResponse;
      try {
        parsed = await res.json();
      } catch {
        // Service returned non-JSON — treat as unavailable
        setServiceError(true);
        return;
      }

      // Normalize response — the simulator backend may return a
      // richer "simulation result" object; we extract the top-level
      // allowed / matchedPolicies / reason fields.
      const normalised: SimulateResponse = {
        allowed:         typeof parsed.allowed === 'boolean' ? parsed.allowed : false,
        matchedPolicies: Array.isArray(parsed.matchedPolicies) ? parsed.matchedPolicies : [],
        reason:          typeof parsed.reason === 'string' ? parsed.reason : 'No reason provided.',
        conditions:      Array.isArray(parsed.conditions) ? parsed.conditions : [],
      };

      setResult(normalised);

      const entry: HistoryEntry = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
        userId:   userId.trim(),
        deviceId: deviceId.trim(),
        resource: resource.trim(),
        action,
        result: normalised.allowed ? 'ALLOWED' : 'DENIED',
        timestamp: Date.now(),
      };
      setHistory(prev => [entry, ...prev].slice(0, 10));
    } catch {
      setServiceError(true);
    } finally {
      setLoading(false);
    }
  }, [userId, deviceId, resource, action, loading]);

  const loadFromHistory = (entry: HistoryEntry) => {
    setUserId(entry.userId);
    setDeviceId(entry.deviceId);
    setResource(entry.resource);
    setAction(entry.action);
    setResult(null);
  };

  // ── Input style shared ────────────────────────────────────────────────────
  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '8px 12px',
    border: '1px solid #d1d5db',
    borderRadius: 6,
    fontSize: 13,
    color: '#111827',
    background: '#fff',
    outline: 'none',
    boxSizing: 'border-box',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: 11,
    fontWeight: 600,
    color: '#6b7280',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    marginBottom: 4,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', fontFamily: 'system-ui, sans-serif' }}>

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div style={{ background: '#fff', borderBottom: '1px solid #e5e7eb', padding: '16px 24px', flexShrink: 0 }}>
        <h1 style={{ fontSize: 18, fontWeight: 600, color: '#111827', marginBottom: 2 }}>
          What-If Analysis
        </h1>
        <p style={{ fontSize: 12, color: '#6b7280' }}>
          Simulate access decisions against your active policies before applying changes
        </p>
      </div>

      {/* ── Service unavailable banner ───────────────────────────────────── */}
      {serviceError && (
        <div style={{
          margin: '12px 24px 0',
          padding: '12px 16px',
          background: '#fef3c7',
          border: '1px solid #fcd34d',
          borderRadius: 8,
          fontSize: 13,
          color: '#92400e',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          flexShrink: 0,
        }}>
          <span style={{ fontSize: 18 }}>⚠</span>
          <span>
            <strong>Policy Simulator service not available.</strong> The simulator backend could not be reached.
            Results shown are unavailable until the service is restored.
          </span>
        </div>
      )}

      {/* ── Main body ───────────────────────────────────────────────────── */}
      <div style={{
        flex: 1,
        display: 'flex',
        gap: 16,
        padding: '16px 24px',
        minHeight: 0,
        overflow: 'auto',
      }}>

        {/* ── Form panel ────────────────────────────────────────────────── */}
        <div style={{
          width: 350,
          minWidth: 300,
          background: '#fff',
          border: '1px solid #e5e7eb',
          borderRadius: 10,
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
          alignSelf: 'flex-start',
        }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, color: '#374151', marginBottom: 4 }}>
            Simulation Parameters
          </h2>

          {/* User */}
          <div>
            <label style={labelStyle}>User <span style={{ color: '#dc2626' }}>*</span></label>
            <input
              value={userId}
              onChange={e => setUserId(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') simulate(); }}
              placeholder="user@example.com or userId"
              style={inputStyle}
            />
          </div>

          {/* Device */}
          <div>
            <label style={labelStyle}>Device <span style={{ color: '#9ca3af', fontWeight: 400 }}>(optional)</span></label>
            <input
              value={deviceId}
              onChange={e => setDeviceId(e.target.value)}
              placeholder="device-id or hostname"
              style={inputStyle}
            />
          </div>

          {/* Resource */}
          <div>
            <label style={labelStyle}>Resource <span style={{ color: '#dc2626' }}>*</span></label>
            <input
              value={resource}
              onChange={e => setResource(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') simulate(); }}
              placeholder="URL, resource name, or path"
              style={inputStyle}
            />
          </div>

          {/* Action */}
          <div>
            <label style={labelStyle}>Action</label>
            <select
              value={action}
              onChange={e => setAction(e.target.value as ActionType)}
              style={inputStyle}
            >
              <option value="read">Read</option>
              <option value="write">Write</option>
              <option value="delete">Delete</option>
              <option value="execute">Execute</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          {/* Simulate button */}
          <button
            onClick={simulate}
            disabled={loading || !userId.trim() || !resource.trim()}
            style={{
              padding: '10px 20px',
              background: loading || !userId.trim() || !resource.trim() ? '#93c5fd' : '#0066CC',
              color: '#fff',
              border: 'none',
              borderRadius: 7,
              fontSize: 14,
              fontWeight: 600,
              cursor: loading || !userId.trim() || !resource.trim() ? 'not-allowed' : 'pointer',
              marginTop: 4,
            }}
          >
            {loading ? 'Simulating…' : 'Simulate'}
          </button>
        </div>

        {/* ── Result panel ──────────────────────────────────────────────── */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12, minWidth: 0 }}>

          {result == null && !loading ? (
            <div style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexDirection: 'column',
              gap: 10,
              color: '#9ca3af',
              fontSize: 14,
              background: '#fff',
              border: '1px solid #e5e7eb',
              borderRadius: 10,
              minHeight: 200,
            }}>
              <svg width="40" height="40" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} style={{ color: '#d1d5db' }}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span>Fill in the form and click Simulate to see results</span>
            </div>
          ) : loading ? (
            <div style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: '#fff',
              border: '1px solid #e5e7eb',
              borderRadius: 10,
              minHeight: 200,
              color: '#6b7280',
              fontSize: 14,
            }}>
              Running simulation…
            </div>
          ) : result && (
            <>
              {/* ── Verdict badge ───────────────────────────────────────── */}
              <div style={{
                background: '#fff',
                border: '1px solid #e5e7eb',
                borderRadius: 10,
                padding: '24px',
                display: 'flex',
                alignItems: 'center',
                gap: 20,
              }}>
                <div style={{
                  padding: '12px 28px',
                  borderRadius: 10,
                  fontSize: 22,
                  fontWeight: 800,
                  letterSpacing: '0.05em',
                  color: '#fff',
                  background: result.allowed ? '#16a34a' : '#dc2626',
                  flexShrink: 0,
                }}>
                  {result.allowed ? 'ALLOWED' : 'DENIED'}
                </div>
                <div>
                  <p style={{ fontSize: 13, color: '#374151', fontWeight: 500, marginBottom: 4 }}>
                    Access Decision
                  </p>
                  <p style={{ fontSize: 13, color: '#6b7280' }}>
                    {result.reason}
                  </p>
                </div>
              </div>

              {/* ── Matched policies ──────────────────────────────────── */}
              <div style={{
                background: '#fff',
                border: '1px solid #e5e7eb',
                borderRadius: 10,
                padding: '16px 20px',
              }}>
                <h3 style={{ fontSize: 13, fontWeight: 600, color: '#374151', marginBottom: 12 }}>
                  Matched Policies
                </h3>
                {result.matchedPolicies.length === 0 ? (
                  <p style={{ fontSize: 12, color: '#9ca3af' }}>No policies matched this request.</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {result.matchedPolicies.map((p, i) => (
                      <div key={i} style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 12px',
                        background: '#f9fafb',
                        borderRadius: 6,
                        border: '1px solid #f3f4f6',
                      }}>
                        <span style={{ fontSize: 13, color: '#374151', fontWeight: 500 }}>{p.name}</span>
                        <span style={{
                          fontSize: 11,
                          fontWeight: 700,
                          padding: '2px 10px',
                          borderRadius: 4,
                          color: '#fff',
                          background: p.effect === 'Allow' ? '#16a34a' : '#dc2626',
                        }}>
                          {p.effect.toUpperCase()}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* ── Applicable conditions ─────────────────────────────── */}
              {result.conditions && result.conditions.length > 0 && (
                <div style={{
                  background: '#fff',
                  border: '1px solid #e5e7eb',
                  borderRadius: 10,
                  padding: '16px 20px',
                }}>
                  <h3 style={{ fontSize: 13, fontWeight: 600, color: '#374151', marginBottom: 12 }}>
                    Applicable Conditions
                  </h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {result.conditions.map((c, i) => (
                      <div key={i} style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        padding: '8px 12px',
                        background: '#f9fafb',
                        borderRadius: 6,
                        border: '1px solid #f3f4f6',
                      }}>
                        <span style={{
                          fontSize: 16,
                          color: c.met ? '#16a34a' : '#dc2626',
                          flexShrink: 0,
                        }}>
                          {c.met ? '✓' : '✗'}
                        </span>
                        <div style={{ minWidth: 0 }}>
                          <p style={{ fontSize: 13, color: '#374151', fontWeight: 500 }}>{c.name}</p>
                          {c.description && (
                            <p style={{ fontSize: 11, color: '#9ca3af', marginTop: 1 }}>{c.description}</p>
                          )}
                        </div>
                        <span style={{
                          marginLeft: 'auto',
                          fontSize: 11,
                          fontWeight: 600,
                          color: c.met ? '#16a34a' : '#9ca3af',
                          flexShrink: 0,
                        }}>
                          {c.met ? 'Met' : 'Not Met'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* ── Simulation History ───────────────────────────────────────────── */}
      {history.length > 0 && (
        <div style={{
          background: '#fff',
          borderTop: '1px solid #e5e7eb',
          padding: '12px 24px 16px',
          flexShrink: 0,
        }}>
          <h3 style={{ fontSize: 12, fontWeight: 700, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
            Simulation History
          </h3>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
                  {['User', 'Resource', 'Action', 'Result', 'Timestamp'].map(h => (
                    <th key={h} style={{ padding: '4px 12px', textAlign: 'left', color: '#9ca3af', fontWeight: 600, whiteSpace: 'nowrap' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map(entry => (
                  <tr
                    key={entry.id}
                    onClick={() => loadFromHistory(entry)}
                    style={{ borderBottom: '1px solid #f3f4f6', cursor: 'pointer' }}
                    onMouseEnter={e => (e.currentTarget.style.background = '#f9fafb')}
                    onMouseLeave={e => (e.currentTarget.style.background = '')}
                  >
                    <td style={{ padding: '6px 12px', color: '#374151' }}>{entry.userId}</td>
                    <td style={{ padding: '6px 12px', color: '#6b7280', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {entry.resource}
                    </td>
                    <td style={{ padding: '6px 12px', color: '#6b7280', textTransform: 'capitalize' }}>{entry.action}</td>
                    <td style={{ padding: '6px 12px' }}>
                      <span style={{
                        fontSize: 11,
                        fontWeight: 700,
                        padding: '2px 8px',
                        borderRadius: 4,
                        color: '#fff',
                        background: entry.result === 'ALLOWED' ? '#16a34a' : '#dc2626',
                      }}>
                        {entry.result}
                      </span>
                    </td>
                    <td style={{ padding: '6px 12px', color: '#9ca3af', whiteSpace: 'nowrap' }}>
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
