'use client';

import React from 'react';

export default function LocationsView() {
  return (
    <div style={{ padding: '24px 28px', background: 'var(--bg-base)', color: 'var(--text-primary)' }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Standorte</h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: 14 }}>Unternehmensstandorte und Niederlassungen</p>
      <section role="status" aria-labelledby="locations-status" style={{
        marginTop: 24, padding: 24, border: '1px solid var(--border)', borderRadius: 12, background: 'var(--bg-surface)',
      }}>
        <h2 id="locations-status" style={{ fontSize: 16, marginTop: 0 }}>Standortverwaltung noch nicht verfügbar</h2>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Es wurden keine echten Standortdaten geladen. Das Speichern von Standorten und die Veröffentlichung
          bei externen Anbietern sind noch nicht angebunden.
        </p>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 0 }}>
          Es werden keine Beispieldaten, erfundenen Gerätezahlen oder simulierten Speicherbestätigungen angezeigt.
        </p>
      </section>
    </div>
  );
}
