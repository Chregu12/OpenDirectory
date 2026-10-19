'use client';

import React, { useEffect, useRef, useState } from 'react';
import { DirectoryAccess } from '@/lib/directoryUsers';
import { DirectoryOu, directoryOus, ouError, parseOus } from '@/lib/directoryOus';
import { DirectoryConfirmation } from '@/components/views/UserDetailPanel';
import OrganizationUnitMembers from '@/components/OrganizationUnitMembers';

export default function OrganizationUnits({ access }: { access: DirectoryAccess }) {
  const [units, setUnits] = useState<DirectoryOu[]>([]); const [loading, setLoading] = useState(true); const [busy, setBusy] = useState(false);
  const [error, setError] = useState(''); const [notice, setNotice] = useState(''); const [name, setName] = useState('');
  const [description, setDescription] = useState(''); const [parentId, setParentId] = useState(''); const sequence = useRef(0);
  const [editing, setEditing] = useState<DirectoryOu | null>(null); const [removing, setRemoving] = useState<DirectoryOu | null>(null);
  const [membershipId, setMembershipId] = useState<string | null>(null);
  const supported = !access.demoMode && !!access.userId && access.directoryReadProtocol === 1 && access.permissions.includes('ous.read');
  const canCreate = supported && access.directoryCreationProtocol === 1 && access.permissions.includes('ous.create');
  const canMutate = supported && access.directoryOuMutationProtocol === 1;
  function clearForm() { setEditing(null); setName(''); setDescription(''); setParentId(''); }
  async function load(signal?: AbortSignal) {
    const epoch = ++sequence.current; setMembershipId(null); setLoading(true); setUnits([]); setError(''); setNotice(''); setBusy(false); clearForm(); setRemoving(null);
    try { const result = await directoryOus.list(signal); if (epoch === sequence.current) setUnits(result); }
    catch (failure) { if (epoch === sequence.current) setError(ouError(failure)); }
    finally { if (epoch === sequence.current) setLoading(false); }
  }
  useEffect(() => {
    const controller = new AbortController(); if (supported) void load(controller.signal); else { sequence.current++; setMembershipId(null); setUnits([]); clearForm(); setRemoving(null); setNotice(''); setLoading(false); }
    const invalid = () => { sequence.current++; controller.abort(); setMembershipId(null); setUnits([]); clearForm(); setRemoving(null); setBusy(false); setLoading(false); setNotice(''); setError('Die Sitzung hat sich geändert. Bitte erneut anmelden und neu laden.'); };
    window.addEventListener('od:session-error', invalid);
    return () => { sequence.current++; controller.abort(); window.removeEventListener('od:session-error', invalid); };
  }, [access, supported]);
  async function save(event: React.FormEvent) {
    event.preventDefault(); if (busy || error || loading || (editing ? !canMutate || !access.permissions.includes('ous.update') : !canCreate)) return;
    const epoch = sequence.current; setBusy(true); setNotice('');
    try {
      const profile = { name: name.trim(), description: description.trim() || null, parentId: parentId || null };
      const unit = editing ? await directoryOus.update(editing, profile) : await directoryOus.create(profile);
      if (epoch !== sequence.current) return;
      const next = editing ? units.map(current => current.id === unit.id ? unit : current) : [...units, unit];
      setUnits(parseOus({ ous: next, total: next.length })); clearForm(); setNotice(`Organisationseinheit „${unit.name}“ bestätigt.`);
    } catch (failure) { if (epoch === sequence.current) { setUnits([]); clearForm(); setError(ouError(failure)); } }
    finally { if (epoch === sequence.current) setBusy(false); }
  }
  async function remove() {
    if (!removing || busy || error || !canMutate || !access.permissions.includes('ous.delete')) return;
    const unit = removing; const epoch = sequence.current; setBusy(true); setNotice('');
    try {
      await directoryOus.remove(unit); if (epoch !== sequence.current) return;
      setUnits(previous => previous.filter(current => current.id !== unit.id)); setRemoving(null); clearForm(); setNotice(`Organisationseinheit „${unit.name}“ gelöscht.`);
    } catch (failure) { if (epoch === sequence.current) { setUnits([]); clearForm(); setRemoving(null); setError(ouError(failure)); } }
    finally { if (epoch === sequence.current) setBusy(false); }
  }
  if (membershipId && supported) return <OrganizationUnitMembers ouId={membershipId} access={access} onClose={() => void load()} />;
  const byParent = new Map<string | undefined, DirectoryOu[]>();
  for (const unit of units) { if (!byParent.has(unit.parentId)) byParent.set(unit.parentId, []); byParent.get(unit.parentId)!.push(unit); }
  const byId = new Map(units.map(unit => [unit.id, unit]));
  const parents = units.filter(unit => { let candidate: DirectoryOu | undefined = unit; while (candidate) { if (candidate.id === editing?.id) return false; candidate = candidate.parentId ? byId.get(candidate.parentId) : undefined; } return true; });
  const children = (parent?: string): React.ReactNode => <ul className="ml-4 space-y-2">{(byParent.get(parent) || []).map(unit => <li key={unit.id}>
    <strong>{unit.name}</strong>{unit.description && <p>{unit.description}</p>}<p className="text-xs break-all">{unit.id}{unit.revision && ` · Version ${unit.revision}`}</p>
    <div className="flex flex-wrap gap-3 mt-2">
      {access.directoryOuMembershipProtocol === 1 && <button type="button" className="border rounded px-3 py-1 disabled:opacity-40" disabled={busy} aria-label={`Organisationseinheit ${unit.name} Mitglieder`} onClick={() => { clearForm(); setMembershipId(unit.id); }}>Mitglieder{unit.memberCount !== undefined && ` (${unit.memberCount})`}</button>}
      {access.permissions.includes('ous.update') && <button type="button" className="border rounded px-3 py-1 disabled:opacity-40" disabled={!canMutate || !unit.revision || busy} aria-label={`Organisationseinheit ${unit.name} bearbeiten`} onClick={() => { setEditing(unit); setRemoving(null); setName(unit.name); setDescription(unit.description || ''); setParentId(unit.parentId || ''); setNotice(''); }}>Bearbeiten / Verschieben</button>}
      {access.permissions.includes('ous.delete') && <button type="button" className="border rounded px-3 py-1 disabled:opacity-40" disabled={!canMutate || !unit.revision || busy || !!byParent.get(unit.id)?.length || !!unit.memberCount} title={byParent.get(unit.id)?.length || unit.memberCount ? 'Zuerst untergeordnete Einheiten und Benutzerzuordnungen kontrolliert entfernen.' : undefined} aria-label={`Organisationseinheit ${unit.name} löschen`} onClick={() => { setRemoving(unit); setNotice(''); }}>Löschen</button>}
    </div>{children(unit.id)}
  </li>)}</ul>;
  return <section aria-label="Organisationsstruktur" className="space-y-4 border-t border-white/20 pt-6">
    <h2 className="text-xl font-semibold">Organisationsstruktur</h2>
    <p>Einheiten des eigenen Mandanten. Änderungen binden die angezeigte Version. Kinder und Benutzerzuordnungen verhindern die Löschung; Mitgliedschaften vergeben keine automatischen Rollen oder Lizenzen.</p>
    {!supported && <p role="alert">Der mandantengebundene Verzeichnisdienst ist nicht verfügbar.</p>}
    {loading && <p role="status">Organisationseinheiten werden geladen …</p>}{error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    {supported && !canMutate && (access.permissions.includes('ous.update') || access.permissions.includes('ous.delete')) && <p role="status">Mandantengebundene OU-Änderungen sind auf diesem Server noch nicht bestätigt. Schreibaktionen bleiben gesperrt.</p>}
    {supported && <button type="button" className="border rounded px-4 py-2" disabled={loading || busy} onClick={() => void load()}>Organisationsstruktur neu laden</button>}
    {supported && !loading && !error && <>{units.length ? children() : <p>Noch keine Organisationseinheiten vorhanden.</p>}
      {(canCreate || editing) && <form onSubmit={save} className="space-y-3">
        {editing && <h3 className="font-semibold">Organisationseinheit bearbeiten · Version {editing.revision}</h3>}
        <label htmlFor="organization-unit-name" className="block">Name der Organisationseinheit<input id="organization-unit-name" required maxLength={255} value={name} onChange={event => setName(event.target.value)} disabled={busy} className="block w-full border rounded p-2 bg-transparent" /></label>
        <label htmlFor="organization-unit-description" className="block">Beschreibung der Organisationseinheit<textarea id="organization-unit-description" maxLength={2000} value={description} onChange={event => setDescription(event.target.value)} disabled={busy} className="block w-full border rounded p-2 bg-transparent" /></label>
        <label htmlFor="organization-unit-parent" className="block">Übergeordnete Einheit</label><select id="organization-unit-parent" value={parentId} onChange={event => setParentId(event.target.value)} disabled={busy} className="block w-full border rounded p-2 bg-transparent"><option value="">Keine (oberste Ebene)</option>{parents.map(unit => <option key={unit.id} value={unit.id}>{unit.name}</option>)}</select>
        <button disabled={busy || !name.trim()} className="border rounded px-4 py-2">{busy ? 'Wird bestätigt …' : editing ? 'Organisationseinheit speichern' : 'Organisationseinheit erstellen'}</button>
        {editing && <button type="button" className="border rounded px-4 py-2 ml-3" disabled={busy} onClick={clearForm}>Bearbeitung abbrechen</button>}
      </form>}
    </>}
    {supported && canMutate && access.permissions.includes('ous.delete') && removing && <DirectoryConfirmation title="Organisationseinheit löschen" busy={busy} error={error} onClose={() => { if (!busy) setRemoving(null); }} onConfirm={() => void remove()}>
      <p>{removing.name} · Version {removing.revision}</p><p className="break-all">{removing.id}</p><p>Nur diese Einheit wird entfernt. Bestehende Abhängigkeiten verhindern die Löschung; Kinder werden nicht automatisch umgehängt.</p>
    </DirectoryConfirmation>}
  </section>;
}
