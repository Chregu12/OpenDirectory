'use client';
import React, { useEffect, useRef, useState } from 'react';
import { companyGroupRules, groupRuleAttributes, groupRuleOperators, CompanyGroupRuleDraft, CompanyGroupRulePage, CompanyGroupRulePreview, CompanyGroupRuleResult, CompanyGroupRuleHistory } from '@/lib/companyGroupRules';
import { DirectoryGroup, directoryGroups } from '@/lib/directoryGroups';
const button = 'rounded border border-white/20 px-3 py-2 disabled:opacity-40'; const field = { background: 'var(--bg-input)', color: 'var(--text-primary)' };
const attributeNames = { department: 'Abteilung', title: 'Funktion', email: 'E-Mail', username: 'Benutzername', displayName: 'Anzeigename' };
const operatorNames = { equals: 'ist gleich', startsWith: 'beginnt mit', endsWith: 'endet mit' };
const statuses = { added: 'Verknüpft', retained: 'Regelquelle beibehalten', 'manual-retained': 'Manuelle Verknüpfung beibehalten', removed: 'Regelquelle entfernt', 'awaiting-review': 'Unabhängige Freigabe ausstehend', blocked: 'Blockiert' };
type Condition = { attribute: typeof groupRuleAttributes[number]; operator: typeof groupRuleOperators[number]; value: string };
export default function CompanyGroupRulesPanel({ group, groups, actorUserId, onChanged }: { group: DirectoryGroup; groups: DirectoryGroup[]; actorUserId: string; onChanged: (group: DirectoryGroup) => void }) {
 const [page, setPage] = useState<CompanyGroupRulePage | null>(null); const [preview, setPreview] = useState<CompanyGroupRulePreview | null>(null); const [results, setResults] = useState<CompanyGroupRuleResult[]>([]);
 const [history, setHistory] = useState<CompanyGroupRuleHistory | null>(null);
 const [conditions, setConditions] = useState<Condition[]>([{ attribute: 'department', operator: 'equals', value: '' }]); const [dynamic, setDynamic] = useState(false); const [children, setChildren] = useState<string[]>([]); const [excluded, setExcluded] = useState(''); const [enabled, setEnabled] = useState(true); const [reason, setReason] = useState('');
 const [loading, setLoading] = useState(true); const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [message, setMessage] = useState(''); const [reload, setReload] = useState(0); const [confirm, setConfirm] = useState<'save'|'sync'|null>(null); const [resultPage, setResultPage] = useState(1); const epoch = useRef(0);
 useEffect(() => { const version = ++epoch.current; setLoading(true); setError(''); setPage(null); setPreview(null); setResults([]); setConfirm(null); setHistory(null);
  companyGroupRules.get(group.id, actorUserId).then(value => { if (version !== epoch.current) return; setPage(value); const saved = value.rule; setEnabled(saved?.enabled ?? true); setDynamic(!!saved?.draft.dynamic); setConditions(saved?.draft.dynamic?.all || [{ attribute: 'department', operator: 'equals', value: '' }]); setChildren(saved?.draft.childGroupIds || []); setExcluded((saved?.draft.excludedUserIds || []).join('\n')); })
   .catch(() => { if (version === epoch.current) setError('Gruppenregeln nicht bestätigt. Aktuelle Eigentümerrechte, MFA und Serverstand prüfen.'); }).finally(() => { if (version === epoch.current) setLoading(false); });
  return () => { epoch.current++; };
 }, [group.id, actorUserId, reload]);
 const draft: CompanyGroupRuleDraft = { dynamic: dynamic ? { all: conditions } : null, childGroupIds: children, excludedUserIds: excluded.split(/\s+/).filter(Boolean) };
 const normalized = { ...draft, childGroupIds: [...children].sort(), excludedUserIds: [...draft.excludedUserIds].sort() };
 const dirty = !page?.rule || page.rule.enabled !== enabled || JSON.stringify(page.rule.draft) !== JSON.stringify(normalized);
 const disabled = loading || busy || !!error || !page || page.groupId !== group.id || page.actorUserId !== actorUserId; const childOptions = [...groups.filter(row => row.id !== group.id), ...children.filter(id => !groups.some(row => row.id === id)).map(id => ({ id, name: 'Nicht mehr in der Gruppenliste: ' + id }))];
 async function perform(action: 'save'|'preview'|'sync') {
  if (!page || disabled) return; const version = epoch.current; setBusy(true); setMessage('');
  try {
   if (action === 'save') { await companyGroupRules.save(page, draft, enabled, reason); if (version === epoch.current) { setMessage('Regelkonfiguration gespeichert. Vorschau prüfen und Mitglieder abgleichen.'); setReload(value => value + 1); } }
   else if (action === 'preview') { const value = await companyGroupRules.preview(page); if (version === epoch.current) { setPreview(value); setResults([]); } }
   else if (preview) { const value = await companyGroupRules.sync(preview, reason, count => { if (version === epoch.current) setMessage(`${count} Mitgliedsschritte bestätigt.`); }); const current = await directoryGroups.get(group.id); if (version === epoch.current) { setResults(value); setResultPage(1); setMessage('Abgleich bestätigt. Ausstehende unabhängige Freigaben und blockierte Mitglieder beachten. Lizenzpools werden separat abgeglichen.'); onChanged(current); } }
  } catch (failure) { if (version === epoch.current) setError(failure instanceof Error ? failure.message : 'Ausgang nicht bestätigt. Frühere Mitgliedsschritte können bereits gespeichert sein.'); }
  finally { if (version === epoch.current) { setBusy(false); setConfirm(null); } }
 }
 function editCondition(index: number, changes: Partial<Condition>) { setConditions(previous => previous.map((value, position) => position === index ? { ...value, ...changes } : value)); setPreview(null); }
 async function loadHistory(number = 1) { if (!page || disabled) return; const version = epoch.current; setBusy(true);
  try { const value = await companyGroupRules.history(page, number); if (version === epoch.current) setHistory(value); } catch { if (version === epoch.current) setError('Gruppenregel-Historie nicht bestätigt. Neu laden.'); } finally { if (version === epoch.current) setBusy(false); }
 }
 return <section aria-label="Dynamische und verschachtelte Gruppenregeln" className="space-y-3 rounded border border-white/20 p-4"><h3 className="font-semibold">Dynamische und verschachtelte Gruppen</h3>
  <p>Attributbedingungen gelten gemeinsam. Effektive Mitglieder der Untergruppen werden zusätzlich übernommen. Ausnahmen betreffen nur die Regelquelle; manuelle Verknüpfungen bleiben erhalten.</p>
  <p>Der Abgleich wird hier ausdrücklich gestartet. Neue Verknüpfungen bleiben bei einer Gruppenprüfung bis zur unabhängigen Freigabe unwirksam. Für unbeaufsichtigte Abgleiche eine eigene App unter Automationen ausdrücklich für Gruppenregeln freigeben und einen Zeitplan anlegen. <a className="underline" href={"/automation?groupRule="+group.id}>Gruppenregel-Automation einrichten</a></p>
  <button className={button} disabled={busy} onClick={() => setReload(value => value + 1)}>Gruppenregel neu laden</button>
  {loading && <p role="status">Gruppenregel wird geprüft …</p>}{error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
  {page && <><label className="block"><input type="checkbox" checked={enabled} disabled={disabled} onChange={event => { setEnabled(event.target.checked); setPreview(null); }}/>Regel aktiv</label>
   <label className="block"><input type="checkbox" checked={dynamic} disabled={disabled} onChange={event => { setDynamic(event.target.checked); setPreview(null); }}/>Attributbedingungen verwenden</label>
   {dynamic && <fieldset disabled={disabled} className="space-y-2"><legend>Alle Bedingungen müssen zutreffen; Gross-/Kleinschreibung wird ignoriert.</legend>{conditions.map((condition,index) => <div key={index} className="flex flex-wrap gap-2">
    <select aria-label={`Attribut ${index+1}`} className={button} style={field} value={condition.attribute} onChange={event => editCondition(index,{ attribute: event.target.value as Condition['attribute'] })}>{groupRuleAttributes.map(value => <option key={value} value={value}>{attributeNames[value]}</option>)}</select>
    <select aria-label={`Vergleich ${index+1}`} className={button} style={field} value={condition.operator} onChange={event => editCondition(index,{ operator: event.target.value as Condition['operator'] })}>{groupRuleOperators.map(value => <option key={value} value={value}>{operatorNames[value]}</option>)}</select>
    <input aria-label={`Bedingungswert ${index+1}`} className={button} style={field} value={condition.value} maxLength={160} onChange={event => editCondition(index,{ value: event.target.value })}/>
    <button className={button} disabled={conditions.length===1} onClick={() => { setConditions(previous => previous.filter((_,position)=>position!==index)); setPreview(null); }}>Bedingung entfernen</button>
   </div>)}<button className={button} disabled={conditions.length>=8} onClick={() => setConditions(previous => [...previous,{attribute:'department',operator:'equals',value:''}])}>Weitere Bedingung</button></fieldset>}
   <label className="block">Untergruppen auswählen<select multiple aria-label="Untergruppen auswählen" className={'block w-full '+button} style={field} disabled={disabled} value={children} onChange={event => { setChildren(Array.from(event.target.selectedOptions, option=>option.value)); setPreview(null); }}>{childOptions.map(row => <option key={row.id} value={row.id}>{row.name}</option>)}</select></label>
   <label className="block">Ausgenommene Benutzer-IDs, eine pro Zeile<textarea aria-label="Ausgenommene Benutzer-IDs" className={'block w-full '+button} style={field} disabled={disabled} value={excluded} maxLength={400000} onChange={event => { setExcluded(event.target.value); setPreview(null); }}/></label>
   <label className="block">Begründung<input aria-label="Gruppenregel begründen" className={'block w-full '+button} style={field} disabled={disabled} value={reason} maxLength={500} onChange={event => setReason(event.target.value)}/></label>
   <button className={button} disabled={disabled || reason.trim().length<10 || !dynamic&&!children.length} onClick={()=>setConfirm('save')}>Gruppenregel speichern</button>
   <button className={button} disabled={disabled || !page.rule || dirty} onClick={()=>void perform('preview')}>Gespeicherte Regelvorschau prüfen</button>
   <button className={button} disabled={disabled || !page.rule} onClick={()=>void loadHistory()}>Gruppenregel-Historie</button>
   {dirty && page.rule && <p>Geänderte Bedingungen zuerst speichern, danach die gespeicherte Regel prüfen.</p>}
   {preview && <div className="space-y-2"><p>{preview.desired.length} gewünschte Mitglieder · {preview.additions} neue Verknüpfungen · gespeicherte Regelversion {preview.ruleRevision}</p><button className={button} disabled={disabled || reason.trim().length<10} onClick={()=>setConfirm('sync')}>Regelmitglieder abgleichen</button></div>}
   {!!results.length && <div><ul aria-label="Bestätigte Gruppenregelergebnisse">{results.slice((resultPage-1)*25,resultPage*25).map(row => <li key={row.userId}>{row.userId} · {statuses[row.status]}{row.code ? ` · Code ${row.code}` : ''}</li>)}</ul>
    <button className={button} disabled={resultPage===1} onClick={()=>setResultPage(value=>value-1)}>Vorherige Regelergebnisse</button><span>Seite {resultPage} · {results.length} Ergebnisse</span><button className={button} disabled={resultPage*25>=results.length} onClick={()=>setResultPage(value=>value+1)}>Weitere Regelergebnisse</button></div>}
  </>}
  {history && <aside aria-label="Gruppenregel-Historie" className="space-y-2"><h4>Ursprüngliche Regel- und Mitgliedschaftsbelege</h4><ol>{history.events.map(event => <li key={event.id}>{new Date(event.createdAt).toLocaleString()} · {event.action==='configured'?'Regel konfiguriert':event.action==='member-add'?'Regelmitglied hinzugefügt':'Regelmitglied entfernt'} · Version {event.ruleRevision} · {event.userId || ''} · {event.application ? 'App '+event.application.clientId : event.actorUserId} · {event.reason}</li>)}</ol>
   <button className={button} disabled={disabled || history.page===1} onClick={()=>void loadHistory(history.page-1)}>Vorherige Regelhistorie</button><span>Seite {history.page} · {history.total} Belege</span><button className={button} disabled={disabled || history.page*25>=history.total} onClick={()=>void loadHistory(history.page+1)}>Weitere Regelhistorie</button>
  </aside>}
  {confirm && <div role="dialog" aria-modal="true" aria-label={confirm==='save'?'Gruppenregel bestätigen':'Gruppenabgleich bestätigen'} className="rounded border border-amber-500 p-3 space-y-2"><p>{group.name} · {confirm==='save'?'Regelkonfiguration verbindlich speichern? Eine spätere Änderung erfordert einen erneuten Abgleich.':'Die erfassten Regelmitglieder über die kanonische Gruppenverwaltung hinzufügen oder entfernen? Bereits bestätigte Einzelschritte bleiben bei späteren Fehlern gespeichert.'}</p>
   <button className={button} disabled={disabled} onClick={()=>void perform(confirm)}>Verbindlich bestätigen</button><button className={button} disabled={busy} onClick={()=>setConfirm(null)}>Abbrechen</button>
  </div>}
 </section>;
}
