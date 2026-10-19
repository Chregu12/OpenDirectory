'use client';

import React, { useState } from 'react';
import toast from 'react-hot-toast';
import { DirectoryUser, directoryUsers, directoryError, userName } from '@/lib/directoryUsers';
import { ensureSession } from '@/lib/auth';
import DirectoryUserEditor from './DirectoryUserEditor';

export function DirectoryConfirmation({ title, children, busy, error, onConfirm, onClose }: { title: string; children: React.ReactNode; busy: boolean; error: string; onConfirm: () => void; onClose: () => void }) {
  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-5" role="alertdialog" aria-modal="true" aria-label={title}>
    <div className="rounded-xl p-6 max-w-lg space-y-4" style={{ background: 'var(--bg-surface, #161b22)', color: 'var(--text-primary, #e4e6ea)' }}>
      <h2 className="text-lg font-semibold">{title}</h2><div>{children}</div>{error && <p role="alert">{error}</p>}
      <div className="flex justify-end gap-4"><button autoFocus disabled={busy} onClick={onClose}>Abbrechen</button><button className="rounded bg-red-700 px-4 py-2 text-white" disabled={busy || !!error} onClick={onConfirm}>{busy ? 'Wird ausgeführt …' : 'Bestätigen'}</button></div>
    </div>
  </div>;
}

export default function UserDetailPanel({ user, permissions, actorUserId, onChanged, onReload, onDenied }: {
  user: DirectoryUser | null; permissions: string[]; actorUserId: string | null;
  onChanged: (user: DirectoryUser | null, expectedId: string) => void; onReload: () => void; onDenied: () => void;
}) {
  const [editing, setEditing] = useState(false); const [action, setAction] = useState<'status' | 'reset' | 'delete' | null>(null);
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const can = (permission: string) => permissions.includes(permission);
  if (!user) return <p className="p-8" role="status">Wähle einen Verzeichniseintrag.</p>;
  const title = action === 'delete' ? 'Verzeichniseintrag löschen' : action === 'reset' ? 'Sicherheitsreset' : user.enabled ? 'Konto sperren' : 'Konto freigeben';
  const allowed = action === 'delete' ? can('users.delete') : action === 'reset' ? can('users.sessions.invalidate') : can('users.update') && can('users.status.manage');
  const begin = (next: typeof action) => { setAction(next); setError(''); };
  const checkSelf = () => { if (user.id === actorUserId) void ensureSession(true).catch(() => {}); };
  return <article className="flex-1 overflow-y-auto p-8 space-y-6" aria-label="Benutzerdetails" style={{ background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)' }}>
    <div><h1 className="text-2xl font-semibold">{userName(user)}</h1><p>{user.email}</p><p className="mt-2 font-semibold">{user.enabled ? 'Freigegeben' : 'Gesperrt'}</p></div>
    <div className="flex flex-wrap gap-3 [&>button]:rounded [&>button]:border [&>button]:border-white/20 [&>button]:px-3 [&>button]:py-2 [&>button]:text-sm">
      {can('users.update') && <button onClick={() => setEditing(true)}>Profil bearbeiten</button>}
      {can('users.update') && can('users.status.manage') && <button onClick={() => begin('status')}>{user.enabled ? 'Konto sperren' : 'Konto freigeben'}</button>}
      {can('users.update') && can('users.status.manage') && user.id !== actorUserId && <a className="rounded border border-white/20 px-3 py-2 text-sm" href={`/applications?offboard=${user.id}#company-offboarding`}>Mitarbeiter-Offboarding</a>}
      {can('users.sessions.invalidate') && <button onClick={() => begin('reset')}>Sicherheitsreset</button>}
      {can('users.delete') && <button className="text-red-500" onClick={() => begin('delete')}>Eintrag löschen</button>}
      <button onClick={onReload}>Details neu laden</button>
    </div>
    <dl className="grid grid-cols-1 md:grid-cols-2 gap-5">
      {Object.entries({ 'Verzeichnis-ID': user.id, Benutzername: user.username, Anzeigename: user.displayName || '—', Abteilung: user.department || '—', Position: user.title || '—', Datensatzversion: user.revision }).map(([label, value]) =>
        <div key={label}><dt className="text-xs opacity-70">{label}</dt><dd className="break-all">{value}</dd></div>)}
    </dl>
    <p className="text-sm">Diese Ansicht verwaltet den kanonischen Verzeichniseintrag. Zugangsdaten, Rollen, MFA, Geräte und Anmelde-Verknüpfungen werden hier nicht erfunden oder automatisch eingerichtet.</p>
    <p className="text-sm">Der Benutzername ist ein Verzeichnisattribut; die separate Anmeldekennung wird durch eine Profiländerung nicht geändert.</p>
    <p className="text-sm">Sperren blockieren neue Zugriffe an den angebundenen APIs. Reaktivierung stellt alte Sitzungen oder Lizenzen nicht automatisch wieder her.</p>
    {editing && can('users.update') && <DirectoryUserEditor user={user} onClose={() => setEditing(false)} onSaved={updated => { setEditing(false); onChanged(updated, user.id); toast.success('Profil gespeichert.'); }} />}
    {action && allowed && <DirectoryConfirmation title={title} busy={busy} error={error} onClose={() => { setAction(null); if (error) onReload(); }} onConfirm={async () => {
      if (busy || error || !allowed) return; setBusy(true);
      try {
        if (action === 'delete') { await directoryUsers.remove(user); onChanged(null, user.id); }
        else if (action === 'reset') { await directoryUsers.invalidate(user.id); onReload(); }
        else { onChanged(await directoryUsers.update(user, { enabled: !user.enabled }), user.id); }
        toast.success(action === 'reset' ? 'Sicherheitsreset bestätigt. Alte Zugriffe bleiben ungültig.' : 'Verzeichnisänderung bestätigt.');
        if (action !== 'status' || user.enabled) checkSelf();
        setAction(null);
      } catch (failure: any) { setError(directoryError(failure)); if ([401, 403].includes(failure?.response?.status)) onDenied(); }
      finally { setBusy(false); }
    }}>
      <p>{userName(user)} · <span className="break-all">{user.id}</span></p>
      {user.id === actorUserId && <p className="mt-3 text-amber-400">Dies ist dein eigener Eintrag. Sperre, Löschung oder Sicherheitsreset machen deine Sitzung ungültig. Stelle einen unabhängigen Wiederherstellungsweg sicher.</p>}
      <p className="mt-3">{action === 'delete' ? 'Der kanonische Eintrag wird gelöscht. Der Bezeichner kann nicht wiederverwendet werden; externe Konten werden dadurch nicht gelöscht.' :
        action === 'reset' ? 'Bestehende Anmelde- und Refresh-Berechtigungen dieses Benutzers werden ungültig. Dies ändert kein Passwort und keine Rolle.' :
          user.enabled ? 'Der kanonische Zugang wird gesperrt. Andere Credential-Stores und Lizenzanbieter werden nicht automatisch geändert.' : 'Nur der kanonische Eintrag wird freigegeben. Bestehende ungültige Sitzungen und entfernte Lizenzen bleiben unverändert.'}</p>
    </DirectoryConfirmation>}
  </article>;
}
