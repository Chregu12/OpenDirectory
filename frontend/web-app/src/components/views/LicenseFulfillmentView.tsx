'use client';

import React,{ useEffect,useRef,useState } from 'react';
import { FulfillmentState,fulfillmentError,fulfillmentId,licenseFulfillment } from '@/lib/licenseFulfillment';
import LicenseCapacityView from './LicenseCapacityView';
const field='w-full border border-[var(--border)] rounded bg-transparent p-2'; const button='border border-[var(--border)] rounded px-3 py-2 disabled:opacity-40';
const names={ pending:'Auftrag vorgemerkt',checking:'Prüfung läuft',in_flight:'Änderung versendet, Ergebnis noch nicht bestätigt',verifying:'Provider-Bestätigung ausstehend',confirmed:'Zuletzt beobachteter Sollstand bestätigt',unknown:'Ergebnis unklar – keine automatische Wiederholung',conflict:'Abweichung oder fremd verwaltete Lizenz',failed:'Bereitstellung nicht bestätigt' };
export default function LicenseFulfillmentView({ permissions,subject }:{ permissions:string[];subject:string|null }) {
  const readable=permissions.includes('licenses.fulfillment.read'); const retry=permissions.includes('licenses.fulfillment.retry'); const adopt=permissions.includes('licenses.fulfillment.adopt');
  const [license,setLicense]=useState(''); const [user,setUser]=useState(''); const [target,setTarget]=useState<{ license:string;user:string }|null>(null);
  const [page,setPage]=useState<FulfillmentState|null>(null); const [attempt,setAttempt]=useState(0); const [error,setError]=useState(''); const [busy,setBusy]=useState(false);
  const [action,setAction]=useState<'retry'|'adopt'|null>(null); const [reason,setReason]=useState(''); const [acknowledged,setAcknowledged]=useState(false); const [mutationError,setMutationError]=useState(''); const [notice,setNotice]=useState('');
  const context=`${subject}:${target?.license}:${target?.user}:${readable}:${retry}:${adopt}`; const current=useRef(context); current.current=context;
  useEffect(()=>{
    setPage(null); setAction(null); setError(''); setMutationError(''); setAcknowledged(false); setReason(''); if (!readable || !target) return;
    let active=true; const controller=new AbortController();
    licenseFulfillment.get(target.license,target.user,controller.signal).then(value=>{ if (active) setPage(value); }).catch(failure=>{ if (active) setError(fulfillmentError(failure)); });
    return ()=>{ active=false; controller.abort(); };
  },[readable,retry,adopt,subject,target,attempt]);
  if (!readable) return null;
  async function save() {
    if (!page || !action || busy || !acknowledged || reason.trim().length<10 || mutationError || action==='retry' && (!retry || !page.canRetry) || action==='adopt' && (!adopt || !page.canAdopt)) return;
    const before=page; const operation=action; const operationContext=context; setBusy(true);
    try {
      const result=await licenseFulfillment.resolve(before,operation,reason.trim());
      setNotice(`Prüfentscheidung für Lizenz ${before.licenseId} und Benutzer ${before.userId} gespeichert. Dies bestätigt keine externe Bereitstellung.`);
      if (current.current===operationContext) { setPage(result); setAction(null); setAcknowledged(false); setReason(''); }
    } catch (failure) { if (current.current===operationContext) setMutationError(fulfillmentError(failure)); }
    finally { setBusy(false); }
  }
  return <section aria-label="Externe Lizenzbereitstellung" className="border border-[var(--border)] rounded p-4 space-y-4">
    <h2 className="text-lg font-semibold">Microsoft-365-Bereitstellung</h2>
    <p>Lokale Zuweisung und externe Bereitstellung sind getrennte Zustände. Nur ausdrücklich konfigurierte Tenant-, SKU- und Benutzer-Verknüpfungen werden verarbeitet. Keine Benutzerliste, kein automatischer Abgleich nach E-Mail und keine Zugangsdaten im Browser.</p>
    <LicenseCapacityView readable={readable} subject={subject}/>
    <form className="grid gap-3 md:grid-cols-2" onSubmit={event=>{ event.preventDefault(); try { setTarget({ license:fulfillmentId(license.trim()),user:fulfillmentId(user.trim()) }); setAttempt(value=>value+1); } catch (failure) { setError(fulfillmentError(failure)); } }}>
      <label>Lokale Lizenz-ID für Provider-Status<input className={field} required disabled={busy} value={license} onChange={event=>setLicense(event.target.value)} /></label>
      <label>Verzeichnis-ID für Provider-Status<input className={field} required disabled={busy} value={user} onChange={event=>setUser(event.target.value)} /></label>
      <button className={button} disabled={busy}>Provider-Status prüfen</button>
    </form>
    {notice && <p role="status">{notice}</p>}{error && <p role="alert">{error}</p>}
    {page && <div className="space-y-2"><p className="break-all">Lokale Lizenz: {page.licenseId} · Benutzer: {page.userId}</p><p>Version {page.version} · Lokale Zuweisung {page.localDesired?'vorhanden':'nicht vorhanden'} · Externer Sollstand {page.desired?'zuweisen':'nicht zugewiesen'}</p>
      <p role="status">{page.paused?'Provider-Verarbeitung pausiert. Der letzte beobachtete Stand wird nicht als aktueller Erfolg zugesichert.':names[page.status]}</p>
      {page.eligibilityBlocked && <p>Die aktuelle Verzeichnis-Identität oder die Herkunft der lokalen Zuweisung sperrt externe Rechte. Lokale Berechtigung unabhängig prüfen und gegebenenfalls neu genehmigen.</p>}
      <p>Zuletzt beim Provider beobachtet: {page.checkedAt||'noch nicht bestätigt'}</p><p>Direkte Zuordnung in eigener Verwaltung: {page.owned?'ja':'nein'}</p>
      {page.observation && <p>Lizenz beim Provider {page.observation.present?'vorhanden':'nicht vorhanden'}{page.observation.inherited?' · zusätzliche Gruppenquelle außerhalb dieser Verwaltung':''}.</p>}
      {page.error && <p role="alert">Provider-Status: {page.error}</p>}
      {!action && <div className="flex gap-3">{retry && page.canRetry && <button className={button} onClick={()=>{ setAction('retry'); setMutationError(''); }}>Erneute Prüfung vorbereiten</button>}
        {adopt && page.canAdopt && <button className={button} onClick={()=>{ setAction('adopt'); setMutationError(''); }}>{page.adoptionPurpose==='cleanup'?'Übernahme zur Bereinigung vorbereiten':'Vorhandene Direktzuweisung übernehmen'}</button>}</div>}
    </div>}
    {page && action && <form role="alertdialog" aria-label="Provider-Prüfentscheidung bestätigen" className="space-y-3 border rounded p-3" onSubmit={event=>{ event.preventDefault(); void save(); }}>
      <p>{action==='adopt'?page.adoptionPurpose==='cleanup'?'Eine frühere unklare Zuweisung trotz inzwischen entzogener lokaler Rechte zur Bereinigung übernehmen. Nach Prüfung entfernt der Worker diese direkte Lizenz; es wird kein neuer Zugriff erteilt.':'Vorhandene direkte Lizenz ausdrücklich zur exklusiven Verwaltung übernehmen. Eine spätere lokale Aufhebung kann diese direkte Vendor-Lizenz entfernen.':'Ein früherer Auftrag kann bereits extern gewirkt haben. Unklare Ergebnisse unabhängig prüfen; eine Wiederholung ist keine Rücknahme.'}</p>
      <label>Begründung der Provider-Prüfentscheidung<textarea className={field} required minLength={10} maxLength={500} disabled={busy} value={reason} onChange={event=>setReason(event.target.value)} /></label>
      <label><input type="checkbox" required disabled={busy} checked={acknowledged} onChange={event=>setAcknowledged(event.target.checked)} /> Ziel, exklusiven Verwaltungsumfang und mögliche bereits erfolgte Änderungen unabhängig geprüft</label>
      {mutationError && <p role="alert">{mutationError}</p>}<button className={button} disabled={busy||!acknowledged||!!mutationError}>Provider-Prüfentscheidung speichern</button>
      <button className={button} type="button" disabled={busy} onClick={()=>{ setAction(null); setAttempt(value=>value+1); }}>Schließen und Provider-Stand prüfen</button>
    </form>}
  </section>;
}
