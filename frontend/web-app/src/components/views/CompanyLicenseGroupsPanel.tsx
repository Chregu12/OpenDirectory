'use client';
import React, { useEffect, useRef, useState } from 'react';
import { CompanyApplicationsClient, CompanyPool } from '@/lib/companyApplications';
import { companyLicenseGroups, CompanyLicenseGroup, LicenseGroupContext, LicenseGroupResult } from '@/lib/companyLicenseGroups';
import { DirectoryGroup } from '@/lib/directoryGroups';
const button = 'rounded border border-white/20 px-3 py-2 disabled:opacity-40';
function summary(results: LicenseGroupResult[]) {
  const count = (status: string) => results.filter(row => row.status === status).length;
  return `${count('assigned')} zugewiesen, ${count('removed')} entfernt, ${count('retained')} beibehalten, ${count('blocked')} blockiert. Lokale Pool-Zuweisung; Herstellerfreischaltung separat prüfen.`;
}
export default function CompanyLicenseGroupsPanel({ group, actorUserId }: { group: DirectoryGroup; actorUserId: string }) {
  const [rules, setRules] = useState<CompanyLicenseGroup[]>([]); const [pools, setPools] = useState<CompanyPool[]>([]); const [poolId, setPoolId] = useState('');
  const [context, setContext] = useState<LicenseGroupContext | null>(null); const [reason, setReason] = useState(''); const [busy, setBusy] = useState(false);
  const [error, setError] = useState(''); const [message, setMessage] = useState(''); const [truncated, setTruncated] = useState(false);
  const [confirmation, setConfirmation] = useState<CompanyLicenseGroup | null>(null); const [page, setPage] = useState(1); const [total, setTotal] = useState(0);
  const epoch = useRef(0); const previous = useRef({ id: '', revision: '' });
  useEffect(() => {
    const version = ++epoch.current; const client = new CompanyApplicationsClient(); const controller = new AbortController();
    const changed = previous.current.id === group.id && previous.current.revision !== group.revision; previous.current = { id: group.id, revision: group.revision };
    setBusy(true); setError(''); setMessage(''); setContext(null); setRules([]); setPools([]); setPoolId(''); setConfirmation(null);
    (async () => {
      const own = await client.reload(controller.signal); const list = await companyLicenseGroups.list(group.id, actorUserId, controller.signal);
      if (own.actorUserId !== actorUserId || own.tenantId !== list.tenantId || list.truncated) throw new Error('Vollständige eigene Lizenzgruppen nicht bestätigt.');
      const catalog = await client.list(page, '', controller.signal); if (version !== epoch.current) return;
      setContext(list); setRules(list.rules); setTruncated(list.truncated); setPools(catalog.pools); setTotal(catalog.total);
      if (changed) {
        const results: LicenseGroupResult[] = [];
        for (const rule of list.rules) results.push(...await companyLicenseGroups.sync(rule, 'Lizenzabgleich nach bestätigter Gruppenänderung', list, () => version === epoch.current));
        const refreshed = await client.list(page, '', controller.signal);
        if (version === epoch.current) { setPools(refreshed.pools); setTotal(refreshed.total); if (list.rules.length) setMessage(summary(results)); }
      }
    })().catch(() => { if (version === epoch.current) setError('Lizenzgruppen nicht vollständig bestätigt. Firmen-Lizenzrechte und aktuelle MFA prüfen. Frühere Zuweisungen können bereits gespeichert sein.'); })
      .finally(() => { if (version === epoch.current) setBusy(false); });
    return () => { epoch.current++; controller.abort(); client.dispose(); };
  }, [group.id, group.revision, actorUserId, page]);
  async function run(rule?: CompanyLicenseGroup, unlink = false) {
    if (!context || busy || truncated) return; const version = epoch.current; setBusy(true); setError(''); setMessage('');
    try {
      let selected = rule;
      if (unlink && rule) selected = await companyLicenseGroups.unlink(rule, reason, context);
      else if (!rule) selected = await companyLicenseGroups.link(group.id, poolId, reason, context);
      if (!selected || version !== epoch.current) return;
      setRules(previous => previous.some(row => row.id === selected!.id) ? previous.map(row => row.id === selected!.id ? selected! : row) : [...previous, selected!]);
      const results = await companyLicenseGroups.sync(selected, reason, context, () => version === epoch.current);
      const current = await companyLicenseGroups.list(group.id, actorUserId);
      if (version !== epoch.current || current.tenantId !== context.tenantId) return;
      setRules(current.rules); setConfirmation(null); setMessage(summary(results));
      const catalog = new CompanyApplicationsClient();
      try {
        const own = await catalog.reload(); if (own.actorUserId !== actorUserId || own.tenantId !== context.tenantId) throw new Error('Aktueller Poolstand nicht bestätigt.');
        const refreshed = await catalog.list(page, ''); if (version === epoch.current) { setPools(refreshed.pools); setTotal(refreshed.total); }
      } finally { catalog.dispose(); }
    } catch (failure) { if (version === epoch.current) setError(failure instanceof Error ? failure.message : 'Ausgang unklar. Gruppe und Pool prüfen; nicht blind wiederholen.'); }
    finally { if (version === epoch.current) setBusy(false); }
  }
  return <section aria-label="Lizenzgruppen und Pool-Verknüpfungen" className="rounded border border-white/20 p-4 space-y-3">
    <h3 className="font-semibold">Lizenzgruppe</h3><p>Ein verknüpfter Pool macht diese normale Verzeichnisgruppe zur Lizenzgruppe. Pro Benutzer und Pool wird ein Platz belegt; andere gültige Zuweisungsquellen bleiben erhalten.</p>
    <p>Änderungen an Mitgliedern lösen in dieser Ansicht den Abgleich aus. Für andere Integrationen steht ein Skript-/API-Abgleich bereit.</p>
    {busy && <p role="status">Gruppen und Lizenzplätze werden geprüft …</p>}{error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    {context && <><label className="block">Lizenzpool<select aria-label="Lizenzpool" className={button} value={poolId} onChange={event => setPoolId(event.target.value)} disabled={busy}>
      <option value="">Pool wählen</option>{pools.map(pool => <option key={pool.id} value={pool.id}>{pool.name} · {pool.availableSeats}/{pool.totalSeats} frei</option>)}</select></label>
      <div className="flex gap-2"><button className={button} disabled={busy || page === 1} onClick={() => setPage(value => value - 1)}>Vorherige Pools</button><span>Pool-Seite {page}</span><button className={button} disabled={busy || page * 25 >= total} onClick={() => setPage(value => value + 1)}>Weitere Pools</button></div>
      <label className="block">Begründung<input aria-label="Begründung der Lizenzgruppenänderung" className={button} value={reason} maxLength={500} onChange={event => setReason(event.target.value)} disabled={busy}/></label>
      <button className={button} disabled={busy || !poolId || reason.trim().length < 10 || rules.some(rule => rule.poolId === poolId && rule.status === 'active')} onClick={() => void run()}>Pool verknüpfen und Mitglieder zuweisen</button>
      {!rules.length && <p>Normale Gruppe: kein Lizenzpool verknüpft.</p>}
      {rules.map(rule => <article key={rule.id} className="rounded border border-white/10 p-3"><p>Pool {pools.find(pool => pool.id === rule.poolId)?.name || rule.poolId} · {rule.status === 'active' ? 'Verknüpft' : 'Verknüpfung beendet'}</p>
        <p><a className="underline" href={'/automation?licenseRule=' + encodeURIComponent(rule.id)}>Automatischen Abgleich einrichten</a></p>
        <button className={button} disabled={busy || reason.trim().length < 10} onClick={() => void run(rule)}>Mitglieder abgleichen</button>
        {rule.status === 'active' && <button className={button} disabled={busy || reason.trim().length < 10} onClick={() => setConfirmation(rule)}>Pool-Verknüpfung entfernen</button>}
      </article>)}
    </>}
    {confirmation && <div role="dialog" aria-label="Lizenzgruppen-Verknüpfung entfernen" className="border border-amber-400 p-3"><p>Diese Gruppenquelle entfernen und die betroffenen Mitglieder abgleichen? Andere Gruppen- und direkte Quellen bleiben bestehen.</p><button className={button} disabled={busy} onClick={() => void run(confirmation, true)}>Verknüpfung verbindlich entfernen</button><button className={button} disabled={busy} onClick={() => setConfirmation(null)}>Abbrechen</button></div>}
  </section>;
}
