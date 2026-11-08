'use client';

import { useEffect, useRef, useState } from 'react';
import { Dialog } from '@headlessui/react';
import { MagnifyingGlassIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useRouter } from 'next/navigation';
import { directoryUsers } from '@/lib/directoryUsers';
import { DeviceInventoryClient, deviceInventoryError } from '@/lib/deviceInventory';
import type { ViewDefinition } from '@/lib/views';

type Result = { id: string; name: string; kind: string; href: string };
const pages = (views: ViewDefinition[], query: string): Result[] => views
  .filter(view => [view.name, ...view.keywords].some(word => word.toLocaleLowerCase('de').includes(query.toLocaleLowerCase('de'))))
  .map(view => ({ id: view.id, name: view.name, kind: 'Seite', href: '/' + view.id }));

export default function GlobalSearch({ views }: { views: ViewDefinition[] }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Result[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [active, setActive] = useState(-1);
  const input = useRef<HTMLInputElement>(null);
  const version = useRef(0);
  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setOpen(value => !value); }
    };
    window.addEventListener('keydown', shortcut);
    return () => window.removeEventListener('keydown', shortcut);
  }, []);
  useEffect(() => {
    const generation = ++version.current;
    const controller = new AbortController();
    const devices = new DeviceInventoryClient();
    setActive(-1); setErrors([]); setResults(pages(views, query.trim()));
    if (!open || !query.trim()) { setLoading(false); devices.dispose(); return; }
    setLoading(true);
    const timer = window.setTimeout(async () => {
      const available = (id: string) => views.some(view => view.id === id);
      const [users, inventory] = await Promise.allSettled([
        available('users') ? directoryUsers.access().then(access => {
          if (!access.userId || access.demoMode || access.directoryReadProtocol !== 1 || !access.permissions.includes('users.read')) return null;
          return directoryUsers.list(1, query.trim(), '', controller.signal);
        }) : Promise.resolve(null),
        available('devices') ? devices.reload(controller.signal).then(access => access.permissions.includes('devices.inventory.read') ? devices.list(1, query.trim(), controller.signal) : null) : Promise.resolve(null),
      ]);
      if (generation !== version.current || controller.signal.aborted) return;
      const found = pages(views, query.trim()); const failures: string[] = [];
      if (users.status === 'fulfilled') users.value?.users.forEach(user => found.push({ id: 'user-' + user.id, name: user.displayName || user.username, kind: 'Person', href: '/users?selected=' + encodeURIComponent(user.id) }));
      else failures.push('Personensuche nicht verfügbar. Seiten können weiterhin geöffnet werden.');
      if (inventory.status === 'fulfilled') inventory.value?.devices.forEach(device => found.push({ id: 'device-' + device.id, name: device.assetId + ' · ' + device.model, kind: 'Gerät', href: '/devices?selected=' + encodeURIComponent(device.id) }));
      else failures.push('Gerätesuche: ' + deviceInventoryError(inventory.reason));
      setResults(found); setErrors(failures); setLoading(false);
    }, 250);
    return () => { ++version.current; window.clearTimeout(timer); controller.abort(); devices.dispose(); };
  }, [query, open, views]);
  useEffect(() => { if (active >= 0) document.getElementById('global-result-' + active)?.scrollIntoView?.({ block: 'nearest' }); }, [active]);
  const navigate = (result: Result) => { setOpen(false); setQuery(''); router.push(result.href); };
  return <>
    <button type="button" className="od-search-trigger" onClick={() => setOpen(true)} aria-label="Globale Suche öffnen" aria-keyshortcuts="Control+k Meta+k">
      <MagnifyingGlassIcon className="h-5 w-5 shrink-0" /><span className="hidden sm:inline">Suchen …</span><kbd className="hidden md:inline ml-auto">⌘K</kbd>
    </button>
    <Dialog open={open} onClose={setOpen} initialFocus={input} className="relative z-[80]">
      <div className="fixed inset-0 bg-black/60" aria-hidden="true" />
      <div className="fixed inset-0 overflow-y-auto p-4 pt-[10vh]">
        <Dialog.Panel className="od-search-dialog mx-auto w-full max-w-xl">
          <Dialog.Title className="sr-only">Seiten und Objekte suchen</Dialog.Title>
          <div className="flex items-center gap-3 border-b p-4" style={{ borderColor: 'var(--border)' }}>
            <MagnifyingGlassIcon className="h-5 w-5 shrink-0" aria-hidden="true" />
            <input ref={input} aria-label="Suchbegriff" role="combobox" aria-autocomplete="list" aria-expanded="true" aria-controls="global-search-results"
              aria-activedescendant={active >= 0 ? 'global-result-' + active : undefined} maxLength={200}
              value={query} onChange={event => setQuery(event.target.value)} placeholder="Seiten, Personen oder Geräte"
              className="min-w-0 flex-1 bg-transparent border-0 p-0" onKeyDown={event => {
                if (!results.length) return;
                if (event.key === 'ArrowDown') { event.preventDefault(); setActive(value => Math.min(value + 1, results.length - 1)); }
                if (event.key === 'ArrowUp') { event.preventDefault(); setActive(value => Math.max(value - 1, 0)); }
                if (event.key === 'Enter' && results[active]) { event.preventDefault(); navigate(results[active]); }
              }} />
            <button type="button" aria-label="Suche schliessen" onClick={() => setOpen(false)}><XMarkIcon className="h-5 w-5" /></button>
          </div>
          <div role="status" aria-live="polite" className="px-4 pt-3 text-sm" style={{ color: 'var(--text-secondary)' }}>
            {loading ? 'Objekte werden gesucht …' : `${results.length} Treffer${query.trim() ? ' · Objektsuche auf der ersten Ergebnisseite' : ''}`}
          </div>
          {errors.map(error => <p role="status" key={error} className="m-3 p-3 rounded text-sm" style={{ background: 'var(--warning-light)', color: 'var(--warning)' }}>{error}</p>)}
          <ul id="global-search-results" role="listbox" aria-label="Suchergebnisse" className="max-h-[50vh] overflow-y-auto py-2">
            {results.map((result, index) => <li key={result.id} id={'global-result-' + index} role="option" aria-selected={active === index} className="od-search-result cursor-pointer"
              style={{ background: active === index ? 'var(--accent-light)' : undefined }} onMouseEnter={() => setActive(index)} onClick={() => navigate(result)}>
                <span className="od-badge shrink-0">{result.kind}</span><span className="break-words min-w-0">{result.name}</span>
            </li>)}
          </ul>
          {!loading && !results.length && <p className="p-4">Keine bestätigten Treffer. Suchbegriff anpassen.</p>}
          <p className="p-4 text-sm border-t" style={{ color: 'var(--text-secondary)', borderColor: 'var(--border)' }}>↑ ↓ auswählen · Eingabe öffnen · Escape schliessen</p>
        </Dialog.Panel>
      </div>
    </Dialog>
  </>;
}
