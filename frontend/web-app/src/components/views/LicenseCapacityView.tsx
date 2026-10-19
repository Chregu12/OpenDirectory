'use client';
import React,{useEffect,useRef,useState} from 'react';
import {CapacityReport,licenseCapacity} from '@/lib/licenseCapacity';
import {fulfillmentId} from '@/lib/licenseFulfillment';
export default function LicenseCapacityView({readable,subject}:{readable:boolean;subject:string|null}){
 const[id,setId]=useState('');const[report,setReport]=useState<CapacityReport|null>(null);const[pending,setPending]=useState(false);const[error,setError]=useState('');const[expired,setExpired]=useState(false);const epoch=useRef(0);const controller=useRef<AbortController|null>(null);
 useEffect(()=>{epoch.current++;controller.current?.abort();setReport(null);setError('');setId('');setPending(false);return()=>{epoch.current++;controller.current?.abort();};},[subject,readable]);
 useEffect(()=>{setExpired(false);if(!report?.observation?.current)return;const until=Date.parse(report.observation.validUntil)-Date.now();if(until<=0){setExpired(true);return;}const timer=setTimeout(()=>setExpired(true),until+1);return()=>clearTimeout(timer);},[report]);
 if(!readable)return null;
 const load=async()=>{const generation=++epoch.current;controller.current?.abort();controller.current=new AbortController();setPending(true);setReport(null);setError('');try{const current=await licenseCapacity.get(fulfillmentId(id.trim()),controller.current.signal);if(generation===epoch.current)setReport(current);}catch{if(generation===epoch.current)setError('Herstellerbeobachtung nicht bestätigt. Keine Nullkapazität oder freien Plätze annehmen.');}finally{if(generation===epoch.current)setPending(false);}};
 const fresh=report?.observation?.current===true&&!expired;
 return <section aria-label="Hersteller-Lizenzkapazität" className="border border-[var(--border)] rounded p-4 space-y-3">
  <h3>Microsoft-Lizenzkapazität · nur lesend</h3><p>Lokale Poolgrößen sind keine gekauften Herstellerplätze. Beobachtungen ändern keine Rechte, kaufen keine Lizenzen und bestätigen keine Bereitstellung. Andere Anwendungen können dieselben Herstellerplätze beanspruchen.</p>
  <form onSubmit={event=>{event.preventDefault();void load();}} className="space-y-2"><label className="block">Connector-ID für Kapazitätsvergleich<input className="block w-full border rounded bg-transparent p-2" value={id} disabled={pending} onChange={event=>setId(event.target.value)} /></label><button disabled={pending||!id.trim()} className="border rounded px-3 py-2 disabled:opacity-40">Gespeicherte Herstellerkapazität prüfen</button></form>
  {pending&&<p role="status">Gespeicherte Herstellerbeobachtung wird geprüft …</p>}{error&&<p role="alert">{error}</p>}
  {report&&<div className="space-y-3"><p className="text-xs break-all">Connector {report.connectorId} · Microsoft-Tenant {report.tenantId}</p><p role="status">{fresh?'Zum Abrufzeitpunkt bestätigte Beobachtung, keine Reservierung.':'Keine aktuelle vollständige Herstellerbeobachtung. Freie Plätze bleiben unbekannt.'}</p>
   {report.observation&&<p className="text-xs">Beobachtet ab {report.observation.startedAt} · gültig bis {report.observation.validUntil} · Zustand {report.observation.status}{report.observation.error?` · ${report.observation.error}`:''}</p>}
   {!report.source&&<p>Kein aktivierter, separat provisionierter Kapazitätssammler.</p>}
   {report.products.length===0&&<p>Keine konfigurierten Produktverknüpfungen für diesen Connector. Dies ist kein Nachweis fehlender Herstellerabonnements.</p>}
   {report.products.map(product=><article key={product.productId} className="border-t border-[var(--border)] pt-3 space-y-2"><h4>{product.name}</h4><p className="text-xs break-all">SKU {product.skuId} · lokale Lizenz {product.licenseId}</p>
    <p>Lokale Poolgröße: {product.local.unlimited?'unbegrenzt':product.local.configuredSeats} · nicht abgelaufene lokale Zuweisungszeilen: {product.local.unexpiredAssignments} (keine erneute Verzeichnisprüfung).</p>
    {product.vendor?<p>Zuletzt beobachtet: aktiv {product.vendor.prepaidUnits.enabled} · Warnstatus {product.vendor.prepaidUnits.warning} · ausgesetzt {product.vendor.prepaidUnits.suspended} · gesperrt {product.vendor.prepaidUnits.lockedOut} · beim Hersteller zugewiesen {product.vendor.consumedUnits} · {product.vendor.capabilityStatus} / {product.vendor.appliesTo}</p>:<p>Diese SKU wurde nicht vollständig bestätigt; fehlend ist nicht gleich null.</p>}
    <p>Beobachtete unzugewiesene aktive Einheiten: {fresh&&product.conservativeHeadroom!==null?product.conservativeHeadroom:'unbekannt'}. Keine Zuweisungsgarantie.</p>{product.issues.length>0&&<p className="text-xs">Prüfhinweise: {product.issues.join(', ')}</p>}
    {product.admission?<><p>Lokales Freigabekontingent: {product.admission.reviewedUnits} · belastete Versuche: {product.admission.chargedUnits} · Restkontingent: {product.admission.remainingUnits}. Keine Herstellerreservierung.</p>
     {(!fresh||!product.admission.generationCurrent||product.admission.remainingUnits===0)&&<p>Neue externe Zuweisungen sind ohne aktuelle Bestands- und Budgetfreigabe gesperrt.</p>}</>:<p>Kein geprüftes Freigabekontingent: Neue externe Zuweisungen gesperrt.</p>}
   </article>)}
  </div>}
 </section>;
}
