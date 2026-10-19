'use client';

import React, { useState } from 'react';
import { directoryUsers, DirectoryUser, UserProfile, directoryError } from '@/lib/directoryUsers';

export default function DirectoryUserEditor({ user, onSaved, onClose }: { user?: DirectoryUser; onSaved: (user: DirectoryUser) => void; onClose: () => void }) {
  const [profile, setProfile] = useState<UserProfile>({ username: user?.username || '', email: user?.email || '', displayName: user?.displayName || '', department: user?.department || '', title: user?.title || '' });
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const [needsReload, setNeedsReload] = useState(false);
  const labels: Record<keyof UserProfile, string> = { username: 'Benutzername', email: 'E-Mail', displayName: 'Anzeigename', department: 'Abteilung', title: 'Position' };
  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-5" role="dialog" aria-modal="true" aria-label={user ? 'Verzeichniseintrag bearbeiten' : 'Verzeichniseintrag erstellen'}>
    <form className="max-w-lg w-full rounded-xl p-6 space-y-4" style={{ background: 'var(--bg-surface, #161b22)', color: 'var(--text-primary, #e4e6ea)' }} onSubmit={async event => {
      event.preventDefault(); if (busy || needsReload) return; setBusy(true); setError('');
      try { onSaved(user ? await directoryUsers.update(user, profile) : await directoryUsers.create(profile)); }
      catch (failure: any) { setError(directoryError(failure)); setNeedsReload(failure?.response?.status !== 400); }
      finally { setBusy(false); }
    }}>
      <h2 className="text-lg font-semibold">{user ? 'Verzeichniseintrag bearbeiten' : 'Verzeichniseintrag erstellen'}</h2>
      {!user && <p className="text-sm">Der Eintrag startet gesperrt. Zugangsdaten, Rollen, MFA und die explizite Anmelde-Verknüpfung werden nicht automatisch provisioniert.</p>}
      {(Object.keys(labels) as Array<keyof UserProfile>).map(field => <label key={field} className="block text-sm">{labels[field]}
        <input className="mt-1 w-full rounded border p-2 bg-transparent" name={field} type={field === 'email' ? 'email' : 'text'} maxLength={255} required={field === 'username' || field === 'email'} disabled={busy || needsReload}
          value={profile[field]} onChange={event => setProfile(previous => ({ ...previous, [field]: event.target.value }))} />
      </label>)}
      {error && <p role="alert">{error}</p>}
      <div className="flex gap-3 justify-end"><button type="button" disabled={busy} onClick={onClose}>Abbrechen</button><button className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50" type="submit" disabled={busy || needsReload}>{busy ? 'Wird gespeichert …' : 'Speichern'}</button></div>
    </form>
  </div>;
}
