'use client';

import React from 'react';
import { DirectoryUser, userName } from '@/lib/directoryUsers';
export type { DirectoryUser } from '@/lib/directoryUsers';

interface Props {
  users: DirectoryUser[];
  total: number;
  page: number;
  selectedId: string | null;
  loading: boolean;
  error: string;
  search: string;
  enabled: string;
  onSelect: (id: string) => void;
  onSearch: (value: string) => void;
  onFilter: (value: string) => void;
  onPage: (page: number) => void;
  onReload: () => void;
  onCreateNew?: () => void;
}

export default function UserListColumn(props: Props) {
  return <section className="h-full flex flex-col" aria-label="Kanonische Benutzerliste" style={{ background: 'var(--bg-surface, #161b22)', color: 'var(--text-primary, #e4e6ea)' }}>
    <div className="p-4 space-y-3 border-b border-white/10">
      <div className="flex justify-between items-center"><h2 className="font-semibold">Benutzer</h2>
        {props.onCreateNew && <button onClick={props.onCreateNew} className="rounded bg-blue-600 px-3 py-1 text-white" aria-label="Verzeichniseintrag erstellen">Neu</button>}
      </div>
      <label className="block text-xs">Suche<input className="mt-1 w-full rounded border p-2 bg-transparent" value={props.search} maxLength={255} onChange={event => props.onSearch(event.target.value)} placeholder="Name, Benutzername oder E-Mail" /></label>
      <label className="block text-xs">Kontostatus<select className="mt-1 w-full rounded border p-2 bg-transparent" value={props.enabled} onChange={event => props.onFilter(event.target.value)}>
        <option value="">Alle</option><option value="true">Freigegeben</option><option value="false">Gesperrt</option>
      </select></label>
      <button onClick={props.onReload} disabled={props.loading}>Neu laden</button>
    </div>
    <div className="flex-1 overflow-y-auto">
      {props.loading ? <p className="p-4" role="status">Benutzer werden geladen …</p> : props.error ? <p className="p-4" role="alert">{props.error}</p> :
        props.users.length === 0 ? <p className="p-4" role="status">Keine Benutzer gefunden.</p> :
          props.users.map(user => <button key={user.id} aria-label={`Benutzer ${user.username}`} aria-pressed={props.selectedId === user.id} onClick={() => props.onSelect(user.id)}
            className={`w-full text-left p-4 border-b border-white/10 ${props.selectedId === user.id ? 'bg-blue-600 text-white' : ''}`}>
            <span className="block font-semibold">{userName(user)}</span><span className="block text-xs">{user.email}</span>
            <span className="block text-xs mt-1">{user.enabled ? 'Freigegeben' : 'Gesperrt'}</span>
          </button>)}
    </div>
    <div className="p-3 border-t border-white/10 flex flex-wrap items-center gap-3 text-sm">
      <button disabled={props.loading || props.page <= 1} onClick={() => props.onPage(props.page - 1)}>Zurück</button>
      <span>{props.loading || props.error ? '…' : `${props.total} Einträge · Seite ${props.page}`}</span>
      <button disabled={props.loading || !!props.error || props.page * 25 >= props.total} onClick={() => props.onPage(props.page + 1)}>Weiter</button>
    </div>
  </section>;
}
