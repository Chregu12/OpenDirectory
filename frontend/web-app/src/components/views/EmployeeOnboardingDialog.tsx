'use client';

import { Dialog } from '@headlessui/react';
import React, { useEffect, useRef, useState } from 'react';
import { directoryUsers, DirectoryUser, directoryError, UserProfile } from '@/lib/directoryUsers';
import { directoryGroups, DirectoryGroup } from '@/lib/directoryGroups';
import { employeeInvitationManagement, employeeInvitationManagementError, EmployeeInvitationRecord } from '@/lib/employeeInvitationManagement';
import { createEmployeeInvitationWithGroups, EmployeeInvitationActionError } from '@/lib/employeeOnboarding';
import EmployeeGroupSelection from './EmployeeGroupSelection';

type Review = { profile: UserProfile; groups: DirectoryGroup[]; loginName: string; durationHours: number; reason: string };
type Result = { invitation: EmployeeInvitationRecord; link: string; message: string; pendingReviews: number };
const field = 'mt-1 w-full rounded border p-2 bg-transparent';

export default function EmployeeOnboardingDialog({ actorUserId, user, onCreated, onInvited, onClose }: {
  actorUserId: string; user?: DirectoryUser; onCreated?: (user: DirectoryUser) => void; onInvited?: () => void; onClose: () => void;
}) {
  const [profile, setProfile] = useState<UserProfile>({ username: user?.username || '', email: user?.email || '', displayName: user?.displayName || '', department: user?.department || '', title: user?.title || '' });
  const [usernameEdited, setUsernameEdited] = useState(!!user);
  const [loginName, setLoginName] = useState(user?.username || '');
  const [groups, setGroups] = useState<DirectoryGroup[]>([]); const [selected, setSelected] = useState<string[]>([]);
  const [groupsLoading, setGroupsLoading] = useState(true); const [groupError, setGroupError] = useState('');
  const [duration, setDuration] = useState(72); const [reason, setReason] = useState('');
  const [review, setReview] = useState<Review | null>(null); const [confirmed, setConfirmed] = useState(false);
  const [createdUser, setCreatedUser] = useState<DirectoryUser | null>(user || null);
  const [invitationId, setInvitationId] = useState(''); const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false); const [progress, setProgress] = useState(''); const [error, setError] = useState('');
  const [needsCheck, setNeedsCheck] = useState(false); const [creationUnknown, setCreationUnknown] = useState(false); const [invalid, setInvalid] = useState(false);
  const lifetime = useRef<AbortController | null>(null); const submitting = useRef(false); const originalOwner = useRef(actorUserId);
  const invalidContext = invalid || originalOwner.current !== actorUserId;

  useEffect(() => {
    const controller = new AbortController(); lifetime.current = controller;
    const invalidate = () => {
      controller.abort(); setInvalid(true); setBusy(false); setProgress(''); setResult(null); setReview(null); setCreatedUser(null); setGroups([]); setSelected([]); setLoginName(''); setReason(''); setInvitationId('');
      setProfile({ username: '', email: '', displayName: '', department: '', title: '' }); setError('Die Sitzung oder Berechtigung wurde geändert. Bitte den aktuellen Stand neu öffnen.');
    };
    window.addEventListener('od:session-error', invalidate); window.addEventListener('od:directory-access-changed', invalidate);
    if (originalOwner.current !== actorUserId) invalidate();
    else directoryGroups.list().then(value => { if (!controller.signal.aborted) setGroups(value.groups); })
      .catch(() => { if (!controller.signal.aborted) setGroupError('Gruppen konnten nicht geladen werden. Eine Einladung ohne zusätzliche Gruppen ist möglich.'); })
      .finally(() => { if (!controller.signal.aborted) setGroupsLoading(false); });
    return () => { controller.abort(); window.removeEventListener('od:session-error', invalidate); window.removeEventListener('od:directory-access-changed', invalidate); };
  }, [actorUserId]);

  async function requireOwner() {
    const current = await directoryUsers.access();
    if (lifetime.current?.signal.aborted || current.userId !== originalOwner.current || current.userId !== actorUserId || current.companyOwner !== true || current.demoMode) throw new Error('Ursprünglicher Firmeninhaber nicht bestätigt.');
    return current;
  }
  function finish(invitation: EmployeeInvitationRecord, link: string, message: string, pendingReviews = 0) {
    setResult({ invitation, link, message, pendingReviews }); setError(''); onInvited?.();
  }
  async function start() {
    if (!review || !confirmed || submitting.current || invalid || error || needsCheck || creationUnknown) return;
    const signal = lifetime.current?.signal; if (!signal || signal.aborted) return;
    submitting.current = true; setBusy(true); setError('');
    let person = createdUser; let creating = false;
    try {
      const current = await requireOwner(); if (signal.aborted) return;
      if (!person) {
        if (!current.permissions.includes('users.create')) throw new Error('Berechtigung zum Anlegen des Benutzers fehlt.');
        setProgress('Einladungsberechtigung wird geprüft …');
        await employeeInvitationManagement.list(1); if (signal.aborted) return;
        creating = true; setProgress('Person wird angelegt …');
        person = await directoryUsers.create(review.profile);
        if (signal.aborted) return;
        if (person.username !== review.profile.username || person.email !== review.profile.email || person.displayName !== review.profile.displayName) throw new Error('Erstellte Person nicht bestätigt.');
        creating = false; setCreatedUser(person); onCreated?.(person);
      }
      setProgress('Einladungsziel wird geprüft …');
      const target = await employeeInvitationManagement.target(person.id, actorUserId); if (signal.aborted) return;
      if (target.revision !== person.revision || target.username !== person.username || target.email !== person.email) throw Object.assign(new Error('Person wurde geändert.'), { response: { status: 412 } });
      const id = invitationId || crypto.randomUUID(); setInvitationId(id);
      setProgress('Gruppen und Einladung werden vorbereitet …');
      const value = await createEmployeeInvitationWithGroups({ id, userId: target.id, userRevision: target.revision, loginName: review.loginName, durationHours: review.durationHours, reason: review.reason, confirm: true }, review.groups, signal);
      if (signal.aborted) return;
      let link = '';
      if (value.created && value.invitationToken) { const url = new URL('/employees/accept', window.location.origin); url.hash = value.invitationToken; link = url.href; }
      const message = !value.created ? 'Die Einladung ist bereits vorhanden. Der Einmal-Link wird nicht erneut ausgegeben. Verwalte die bestehende Einladung bei Bedarf in der Einladungsliste.'
        : value.mailStatus === 'sent' ? 'Microsoft Graph hat den Versandauftrag angenommen. Die Zustellung ist noch nicht bestätigt.'
        : value.mailStatus === 'not_configured' ? 'E-Mail-Versand ist nicht eingerichtet. Teile den Einmal-Link vertraulich mit der eingeladenen Person.'
        : 'Der E-Mail-Versand ist nicht bestätigt. Prüfe den Status und teile den Einmal-Link bei Bedarf vertraulich.';
      finish(value.invitation, link, message, value.pendingReviews);
    } catch (failure: any) {
      if (signal.aborted) return;
      if (creating && failure?.response?.status !== 400) setCreationUnknown(true);
      if (failure instanceof EmployeeInvitationActionError) setNeedsCheck(failure.uncertain || !failure.rollbackComplete);
      setError(failure instanceof EmployeeInvitationActionError ? failure.message : creating ? directoryError(failure) : failure?.response ? employeeInvitationManagementError(failure) : failure.message || 'Aufnahme nicht bestätigt.');
    } finally { submitting.current = false; if (!signal.aborted) { setBusy(false); setProgress(''); } }
  }
  async function prepareAgain() {
    if (submitting.current || needsCheck || creationUnknown || invalid) return;
    setBusy(true);
    try {
      await requireOwner();
      const person = createdUser ? await directoryUsers.get(createdUser.id) : null;
      const available = await directoryGroups.list(); if (lifetime.current?.signal.aborted) return;
      if (person) {
        if (person.enabled) throw new Error('Die Person ist inzwischen aktiv. Bitte ihren aktuellen Stand in der Benutzerverwaltung prüfen.');
        setCreatedUser(person); setProfile({ username: person.username, email: person.email, displayName: person.displayName || '', department: person.department || '', title: person.title || '' });
      }
      setGroups(available.groups); setSelected(ids => ids.filter(id => available.groups.some(group => group.id === id))); setGroupError('');
      setReview(null); setConfirmed(false); setError('');
    } catch (failure: any) { if (!lifetime.current?.signal.aborted) setError(failure?.response ? employeeInvitationManagementError(failure) : failure.message); }
    finally { if (!lifetime.current?.signal.aborted) setBusy(false); }
  }
  async function checkInvitation() {
    if (!invitationId || !createdUser || busy || invalid) return;
    setBusy(true);
    try {
      await requireOwner(); const value = await employeeInvitationManagement.get(invitationId); if (lifetime.current?.signal.aborted) return;
      if (value.userId !== createdUser.id) throw new Error('Einladung gehört nicht zur bestätigten Person.');
      finish(value, '', 'Die ursprüngliche Einladung ist vorhanden. Ihr Einmal-Link wird nicht erneut ausgegeben. Prüfe auch die Gruppenmitgliedschaften und verwalte die Einladung bei Bedarf in der Einladungsliste.');
    } catch (failure: any) { if (!lifetime.current?.signal.aborted) setError(failure?.response?.status === 404 ? 'Noch keine Einladung bestätigt. Ein offener Vorgang oder Gruppenänderungen können trotzdem bestehen. Prüfe Benutzer und Gruppen vor einer neuen Aufnahme.' : employeeInvitationManagementError(failure)); }
    finally { if (!lifetime.current?.signal.aborted) setBusy(false); }
  }
  const patch = (key: keyof UserProfile, value: string) => setProfile(previous => ({ ...previous, [key]: value }));

  return <Dialog open onClose={() => { if (!busy) onClose(); }} className="od-modal-frame" aria-label="Mitarbeiter aufnehmen">
    <Dialog.Panel className="od-modal-panel max-w-xl space-y-5" style={{ background: 'var(--bg-surface)', color: 'var(--text-primary)' }}>
      <Dialog.Title className="text-lg font-semibold">{result ? 'Einladung vorbereitet' : 'Mitarbeiter aufnehmen'}</Dialog.Title>
      {(error || invalidContext) && <p role="alert" className="border rounded p-3">{invalidContext ? 'Die Sitzung oder Berechtigung wurde geändert. Bitte den aktuellen Stand neu öffnen.' : error}</p>}
      {!invalidContext && createdUser && !result && <p role="status">{createdUser.displayName || createdUser.username} ist als Verzeichniseintrag vorhanden. Die Einladung wird für genau diese Person fortgesetzt.</p>}
      {busy && <p role="status">{progress || 'Aktueller Stand wird geprüft …'}</p>}
      {invalidContext ? <button type="button" onClick={onClose}>Schliessen</button> : result ? <section className="space-y-4">
        <p className="break-words"><strong>{createdUser?.displayName || result.invitation.loginName}</strong> · {createdUser?.email}</p>
        <ol aria-label="Aufnahmefortschritt" className="list-decimal pl-5 space-y-2"><li>Person im Verzeichnis vorhanden.</li><li>Einladung {({ pending: 'erstellt', credential_pending: 'in Annahme', accepted: 'angenommen', revoked: 'widerrufen' })[result.invitation.status]}.</li><li>Passwort und gegebenenfalls MFA richtet die eingeladene Person selbst ein.</li></ol>
        <p role="status">{result.message}</p>
        {result.pendingReviews > 0 && <p>{result.pendingReviews} Gruppenmitgliedschaft(en) warten auf eine unabhängige Prüfung.</p>}
        <p>Vorhandene Gruppen- und Lizenzregeln greifen nach Aktivierung und dem jeweiligen Abgleich. Herstellerlizenzen oder ein Postfach werden damit nicht bestätigt.</p>
        {result.link && <div className="space-y-2"><label className="block">Einmaliger Einladungslink<input className={field} value={result.link} readOnly /></label><button type="button" className="border rounded px-3 py-2" onClick={async () => { try { await navigator.clipboard.writeText(result.link); } catch { setError('Bitte den Link markieren und manuell kopieren.'); } }}>Link kopieren</button><p className="text-sm">Der vertrauliche Link wird nach dem Schliessen nicht erneut angezeigt.</p></div>}
        <div className="flex flex-wrap gap-3"><a href="/employee-invitations" className="underline">Einladungen verwalten</a><button type="button" onClick={onClose}>Schliessen</button></div>
      </section> : !review ? <form className="space-y-4" onSubmit={event => {
        event.preventDefault(); if (busy || invalid || creationUnknown) return;
        const values = { username: profile.username.trim(), email: profile.email.trim(), displayName: profile.displayName?.trim() || '', department: profile.department?.trim() || '', title: profile.title?.trim() || '' };
        if (!values.displayName && !createdUser) { setError('Bitte den Namen der Person angeben.'); return; }
        setReview({ profile: values, groups: groups.filter(group => selected.includes(group.id)), loginName: (loginName || values.username).trim(), durationHours: duration, reason: reason.trim() || `Mitarbeiteraufnahme für ${values.displayName || values.username}` }); setConfirmed(false); setError('');
      }}>
        <p>Person einmal erfassen, Gruppen auswählen und die Aufnahme gemeinsam bestätigen.</p>
        <fieldset disabled={busy || invalid || !!createdUser} className="space-y-3">
          <label className="block">Name<input className={field} required maxLength={255} value={profile.displayName} onChange={event => patch('displayName', event.target.value)} /></label>
          <label className="block">E-Mail<input className={field} type="email" required maxLength={255} value={profile.email} onChange={event => { const value = event.target.value; setProfile(previous => ({ ...previous, email: value, ...(!usernameEdited ? { username: value.split('@')[0] } : {}) })); }} /></label>
          <label className="block">Benutzername<input className={field} required minLength={3} maxLength={254} pattern="[A-Za-z0-9][A-Za-z0-9._@+\-]*" value={profile.username} onChange={event => { setUsernameEdited(true); patch('username', event.target.value); }} /></label>
        </fieldset>
        <EmployeeGroupSelection groups={groups} selected={selected} onChange={setSelected} loading={groupsLoading} error={groupError} disabled={busy || invalid} userId={createdUser?.id} />
        <details><summary className="cursor-pointer">Weitere Angaben</summary><div className="space-y-3 pt-3">
          <label className="block">Abteilung<input className={field} maxLength={255} disabled={busy || !!createdUser} value={profile.department} onChange={event => patch('department', event.target.value)} /></label>
          <label className="block">Position<input className={field} maxLength={255} disabled={busy || !!createdUser} value={profile.title} onChange={event => patch('title', event.target.value)} /></label>
          <label className="block">Anmeldename<input className={field} minLength={3} maxLength={254} pattern="[A-Za-z0-9][A-Za-z0-9._@+\-]*" disabled={busy} placeholder={profile.username} value={loginName} onChange={event => setLoginName(event.target.value)} /></label>
          <label className="block">Gültigkeit<select className={field} disabled={busy} value={duration} onChange={event => setDuration(Number(event.target.value))}>{[1, 4, 12, 24, 48, 72].map(hours => <option key={hours} value={hours}>{hours === 72 ? '3 Tage' : `${hours} Stunden`}</option>)}</select></label>
          <label className="block">Grund<input className={field} minLength={10} maxLength={500} disabled={busy} value={reason} placeholder="Mitarbeiteraufnahme" onChange={event => setReason(event.target.value)} /></label>
        </div></details>
        <div className="flex justify-end gap-3"><button type="button" disabled={busy} onClick={onClose}>Abbrechen</button><button type="submit" className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50" disabled={busy || invalid || groupsLoading}>Aufnahme prüfen</button></div>
      </form> : <section className="space-y-4" aria-label="Aufnahme prüfen">
        <dl className="space-y-2 break-words"><div><dt className="font-medium">Person</dt><dd>{review.profile.displayName} · {review.profile.email}</dd></div><div><dt className="font-medium">Anmeldename</dt><dd>{review.loginName}</dd></div><div><dt className="font-medium">Gruppen</dt><dd>{review.groups.map(group => group.name).join(', ') || 'Keine zusätzlichen Gruppen'}</dd></div><div><dt className="font-medium">Einladung gültig</dt><dd>{review.durationHours} Stunden</dd></div><div><dt className="font-medium">Grund</dt><dd>{review.reason}</dd></div></dl>
        <p>Der Eintrag bleibt bis zur selbstständigen Passwortvergabe gesperrt. Die Einladung wird erstellt und bei eingerichteter Mail-Anbindung zum Versand übergeben.</p>
        {!needsCheck && !creationUnknown && <label className="flex gap-3"><input type="checkbox" checked={confirmed} disabled={busy || invalid} onChange={event => setConfirmed(event.target.checked)} /><span>Ich bestätige die Aufnahme und die ausgewählten Gruppenmitgliedschaften.</span></label>}
        <div className="flex flex-wrap justify-end gap-3">
          <button type="button" disabled={busy} onClick={onClose}>{createdUser || creationUnknown ? 'Schliessen' : 'Abbrechen'}</button>
          {!needsCheck && !creationUnknown && !invalid && <><button type="button" disabled={busy} onClick={() => { if (createdUser) void prepareAgain(); else { setReview(null); setError(''); setConfirmed(false); } }}>Angaben bearbeiten</button><button type="button" className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50" disabled={busy || !confirmed || !!error} onClick={() => void start()}>Aufnahme starten</button></>}
          {needsCheck && invitationId && !invalid && <button type="button" disabled={busy} onClick={() => void checkInvitation()}>Einladungsstatus prüfen</button>}
          {(needsCheck || creationUnknown) && <a className="underline" href="/users">Benutzer und Gruppen prüfen</a>}
        </div>
      </section>}
    </Dialog.Panel>
  </Dialog>;
}
