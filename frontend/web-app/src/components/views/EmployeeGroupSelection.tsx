'use client';

import React, { useState } from 'react';
import { DirectoryGroup } from '@/lib/directoryGroups';

export default function EmployeeGroupSelection({ groups, selected, onChange, loading, error, disabled, userId }: {
  groups: DirectoryGroup[]; selected: string[]; onChange: (ids: string[]) => void; loading: boolean; error: string; disabled?: boolean; userId?: string;
}) {
  const [search, setSearch] = useState('');
  const matches = groups.filter(group => group.name.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase()));
  return <fieldset className="space-y-2" disabled={disabled}>
    <legend className="font-medium">Gruppen für den Eintritt (optional)</legend>
    <p className="text-sm text-[var(--text-secondary)]">Vorhandene Gruppenregeln können Apps freigeben und nach Aktivierung lokale Lizenzplätze zuweisen. Erforderliche Mitgliedschaftsprüfungen bleiben bestehen.</p>
    <label className="block">Gruppen suchen<input className="block border rounded p-2 w-full" value={search} onChange={event => setSearch(event.target.value)} /></label>
    {loading && <p role="status">Eigene Gruppen werden geladen …</p>}
    {error && <p role="alert">{error}</p>}
    {!loading && !error && matches.slice(0, 100).map(group => <label key={group.id} className="flex gap-2 items-start"><input type="checkbox" checked={selected.includes(group.id)} onChange={event => onChange(event.target.checked ? [...selected, group.id] : selected.filter(id => id !== group.id))} /><span>{group.name}{userId && group.members.includes(userId) ? ' · bereits Mitglied' : ''}</span></label>)}
    {!loading && !error && groups.length === 0 && <p>Keine eigenen Gruppen verfügbar.</p>}
    {!loading && !error && groups.length > 0 && matches.length === 0 && <p>Keine passende Gruppe gefunden.</p>}
    {!error && matches.length > 100 && <p className="text-sm">Bitte die Suche weiter eingrenzen (maximal 100 Treffer werden angezeigt).</p>}
  </fieldset>;
}
