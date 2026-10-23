'use client';
import React,{useEffect,useRef,useState} from 'react';
import {directoryUsers} from '@/lib/directoryUsers';
import {companyApps,CompanyApp,CompanyAppHistory,CompanyAppPrincipal} from '@/lib/companyApps';
import {companyWorkflowError} from '@/lib/companyAssignmentProtocol';
const button='rounded border border-white/20 px-3 py-2 disabled:opacity-40';
const field='w-full rounded border border-white/20 bg-[var(--bg-input)] px-3 py-2';
type Form={target:CompanyApp|null;requestId:string;name:string;enabled:boolean;purpose:'none'|'company-automation';reason:string;confirm:boolean};
export default function CompanyAppsView(){
 const [principal,setPrincipal]=useState<CompanyAppPrincipal|null>(null);const [clients,setClients]=useState<CompanyApp[]>([]);const [page,setPage]=useState(1);const [hasMore,setHasMore]=useState(false);
 const [status,setStatus]=useState<'active'|'deleted'>('active');
 const [reload,setReload]=useState(0);const [busy,setBusy]=useState(false);const [loading,setLoading]=useState(true);const [error,setError]=useState('');const [message,setMessage]=useState('');
 const [form,setForm]=useState<Form|null>(null);const [action,setAction]=useState<{kind:'rotate'|'delete';target:CompanyApp}|null>(null);const [reason,setReason]=useState('');
 const [secret,setSecret]=useState<{clientId:string;value:string}|null>(null);const [history,setHistory]=useState<CompanyAppHistory|null>(null);const epoch=useRef(0);const context=useRef('');
 useEffect(()=>{const version=++epoch.current;setLoading(true);setError('');setPrincipal(null);setClients([]);setSecret(null);setHistory(null);setAction(null);
  (async()=>{const access=await directoryUsers.access();if(!access.userId||access.demoMode||!access.companyOwner)throw new Error('Aktueller Firmeninhaberzugriff mit frischer MFA erforderlich.');
   const value=await companyApps.list(access.userId,page,status);if(version!==epoch.current)return;const key=value.actorUserId+':'+value.tenant.id;if(context.current&&context.current!==key)setForm(null);context.current=key;
   setPrincipal({actorUserId:value.actorUserId,tenantId:value.tenant.id});setClients(value.clients);setHasMore(value.hasMore);
  })().catch(failure=>{if(version===epoch.current)setError(failure instanceof Error?failure.message:'Firmen-App-Register nicht verfügbar.');}).finally(()=>{if(version===epoch.current)setLoading(false);});return()=>{epoch.current++;};
 },[reload,page,status]);
 const refresh=()=>{setForm(current=>current?.target?null:current);setReload(value=>value+1);};
 async function perform(operation:()=>Promise<void>){if(busy||loading||!principal)return;const version=epoch.current;setBusy(true);setMessage('');setSecret(null);
  try{await operation();}catch(failure){if(version===epoch.current)setError(companyWorkflowError(failure));}finally{setBusy(false);}
 }
 async function save(event:React.FormEvent){event.preventDefault();if(!form||!principal||!form.confirm)return;const current=form;const who=principal;
  await perform(async()=>{const input={name:current.name,purpose:current.purpose,reason:current.reason,confirm:true as const};const result=current.target?await companyApps.update(current.target,{...input,enabled:current.enabled},who):await companyApps.create({...input,requestId:current.requestId},who);
   setClients(rows=>[result.client,...rows.filter(row=>row.clientId!==result.client.clientId)].slice(0,25));setForm(null);setError('');if('clientSecret' in result&&typeof result.clientSecret==='string')setSecret({clientId:result.client.clientId,value:result.clientSecret});
   setMessage('created' in result&&!result.created?'Originalauftrag wiedergefunden. Das ursprüngliche Secret wird nicht erneut ausgegeben; bei Verlust rotieren.':'Firmen-App gespeichert. Änderungen beenden die vorherige Clientgeneration.');
  });
 }
 async function confirmAction(){if(!action||!principal)return;const selected=action;const who=principal;await perform(async()=>{
  const result=selected.kind==='rotate'?await companyApps.rotate(selected.target,reason,who):await companyApps.remove(selected.target,reason,who);
  setClients(rows=>selected.kind==='delete'?rows.filter(row=>row.clientId!==selected.target.clientId):rows.map(row=>row.clientId===result.client.clientId?result.client:row));setAction(null);setError('');
  if('clientSecret' in result&&typeof result.clientSecret==='string')setSecret({clientId:result.client.clientId,value:result.clientSecret});setMessage(selected.kind==='rotate'?'Secret rotiert. Alte Zugangsdaten und Clientgeneration sind ungültig.':'Firmen-App gelöscht und deaktiviert. Ursprüngliche Belege bleiben erhalten.');
 });}
 const disabled=busy||loading||!principal;
 return <section aria-label="Eigene Firmen-Apps" className="h-full overflow-auto p-6 space-y-5" style={{colorScheme:'dark'}}>
  <header className="flex flex-wrap items-center justify-between gap-3"><div><h1 className="text-2xl font-semibold">Firmen-Apps</h1><p>Eigene App-Konten mit Client-ID und Secret für deine Skripte.</p></div><button className={button} disabled={busy} onClick={refresh}>Firmen-App-Register neu laden</button></header>
  <p>Neue Konten starten deaktiviert. Der Automationszweck erlaubt eine App-Anmeldung; konkrete Daten- und Schreibrechte genehmigst du separat unter <a className="underline" href="/automation">Automationen</a>. Eine Appregistrierung richtet kein Postfach ein.</p>
  {loading&&<p role="status">Firmenzugriff wird geprüft …</p>}{error&&<p role="alert">{error}</p>}{message&&<p role="status">{message}</p>}
  {principal&&<><button className={button} disabled={disabled||!!error||!!form||!!action||status==='deleted'} onClick={()=>{setSecret(null);setForm({target:null,requestId:crypto.randomUUID(),name:'',enabled:false,purpose:'none',reason:'',confirm:false});}}>Eigenes App-Konto erstellen</button>
   <div><label htmlFor="company-app-status">Registeransicht</label><select id="company-app-status" className={field} disabled={disabled||!!form||!!action} value={status} onChange={event=>{setPage(1);setStatus(event.target.value as 'active'|'deleted');}}><option value="active">Aktive und deaktivierte Apps</option><option value="deleted">Gelöschte Apps und Historie</option></select></div>
   <div className="space-y-3" aria-label="Gespeicherte Firmen-Apps">{clients.map(row=><article key={row.clientId} className="rounded border border-white/20 p-4 space-y-2">
    <h2 className="font-semibold">{row.name}</h2><p>Client-ID: <code>{row.clientId}</code> · Version {row.version} · {row.deletedAt?'Gelöscht':row.enabled?'Aktiv':'Deaktiviert'}</p><p>{row.purpose==='none'?'Keine App-Berechtigungen':'Zweck: Firmenautomationen, separate Freigabe erforderlich'}</p>
    <div className="flex flex-wrap gap-2"><button className={button} disabled={disabled||!!error||!!form||!!action||row.deletedAt!==null} onClick={()=>{setSecret(null);setForm({target:row,requestId:'',name:row.name,enabled:row.enabled,purpose:row.purpose,reason:'',confirm:false});}}>App bearbeiten</button>
     <button className={button} disabled={disabled||!!error||!!form||!!action||row.deletedAt!==null} onClick={()=>{setSecret(null);setReason('');setAction({kind:'rotate',target:row});}}>Secret rotieren</button>
     <button className={button} disabled={disabled||!!error||!!form||!!action||row.deletedAt!==null} onClick={()=>{setSecret(null);setReason('');setAction({kind:'delete',target:row});}}>App löschen</button>
     <button className={button} disabled={disabled} onClick={()=>perform(async()=>setHistory(await companyApps.history(row,principal)))}>App-Historie</button></div>
   </article>)}</div>{!loading&&clients.length===0&&<p>Keine eigenen App-Konten auf dieser Seite.</p>}
   <nav aria-label="Firmen-App-Seiten" className="flex gap-3"><button className={button} disabled={disabled||page===1||!!form||!!action} onClick={()=>setPage(value=>value-1)}>Vorherige Apps</button><span>Seite {page}</span><button className={button} disabled={disabled||!hasMore||!!form||!!action} onClick={()=>setPage(value=>value+1)}>Weitere Apps</button></nav>
  </>}
  {principal&&form&&<form role="dialog" aria-label={form.target?'Firmen-App bearbeiten':'Eigenes App-Konto anlegen'} onSubmit={save} className="rounded border border-white/20 p-4 space-y-3">
   <h2>{form.target?'Firmen-App bearbeiten':'Eigenes App-Konto anlegen'}</h2>{!form.target&&<p>Originalauftrag: {form.requestId}. Nach unklarem Ergebnis denselben Auftrag prüfen; keinen zweiten erstellen.</p>}
   <label className="block">App-Name<input className={field} maxLength={160} required disabled={busy||!!error&&!form.target} value={form.name} onChange={event=>setForm({...form,name:event.target.value})}/></label>
   <div><label htmlFor="company-app-purpose">App-Zweck</label><select id="company-app-purpose" className={field} disabled={busy||!!error&&!form.target} value={form.purpose} onChange={event=>setForm({...form,purpose:event.target.value as Form['purpose']})}><option value="none">Keine Berechtigungen</option><option value="company-automation">Firmenautomationen</option></select></div>
   {form.target&&<label className="block"><input type="checkbox" checked={form.enabled} disabled={busy} onChange={event=>setForm({...form,enabled:event.target.checked})}/> App aktivieren</label>}
   <label className="block">App-Änderung begründen<textarea className={field} required minLength={10} maxLength={500} disabled={busy||!!error&&!form.target} value={form.reason} onChange={event=>setForm({...form,reason:event.target.value})}/></label>
   <label className="block"><input type="checkbox" checked={form.confirm} disabled={busy} onChange={event=>setForm({...form,confirm:event.target.checked})}/> Eigenes App-Konto und gewählten Zweck bestätigen</label>
   <div className="flex gap-2"><button className={button} disabled={disabled||!form.confirm||form.reason.trim().length<10||!form.name.trim()} type="submit">{error&&!form.target?'Originalauftrag erneut prüfen':'Firmen-App speichern'}</button><button className={button} disabled={busy} type="button" onClick={()=>setForm(null)}>Schliessen</button></div>
  </form>}
  {principal&&action&&<section role="dialog" aria-label="Firmen-App-Aktion bestätigen" className="rounded border border-white/20 p-4 space-y-3"><h2>{action.kind==='rotate'?'Secret rotieren':'App löschen'}: {action.target.name}</h2><p>Client {action.target.clientId}, Version {action.target.version}. Die bisherige Clientgeneration wird ungültig; bestehende Automationsfreigaben werden nicht auf eine neue Generation übertragen.</p>
   <label className="block">App-Aktion begründen<textarea className={field} minLength={10} maxLength={500} disabled={busy} value={reason} onChange={event=>setReason(event.target.value)}/></label><button className={button} disabled={disabled||reason.trim().length<10} onClick={confirmAction}>{action.kind==='rotate'?'Secret verbindlich rotieren':'App verbindlich löschen'}</button><button className={button} disabled={busy} onClick={()=>setAction(null)}>Abbrechen</button></section>}
  {secret&&<section aria-label="Einmaliges Firmen-App-Secret" className="rounded border border-white/20 p-4 space-y-2"><h2>Secret jetzt sicher übernehmen</h2><p>Client-ID: {secret.clientId}. Dieses Secret wird nur einmal angezeigt. Nach Verlust muss es rotiert werden.</p><code data-testid="company-app-secret" className="block break-all">{secret.value}</code><button className={button} onClick={()=>setSecret(null)}>Secret ausblenden</button></section>}
  {history&&<aside aria-label="Firmen-App-Historie" className="rounded border border-white/20 p-4"><h2>Ursprüngliche App-Belege</h2>{history.events.map(row=><p key={row.revision}>Version {row.revision} · {row.action} · {new Date(row.createdAt).toLocaleString()} · {row.actorUserId} · {row.reason}</p>)}<div className="flex gap-2"><button className={button} disabled={disabled||history.page===1} onClick={()=>perform(async()=>{const row=clients.find(client=>client.clientId===history.clientId);if(row&&principal)setHistory(await companyApps.history(row,principal,history.page-1));})}>Vorherige App-Belege</button><button className={button} disabled={disabled||!history.hasMore} onClick={()=>perform(async()=>{const row=clients.find(client=>client.clientId===history.clientId);if(row&&principal)setHistory(await companyApps.history(row,principal,history.page+1));})}>Weitere App-Belege</button></div></aside>}
 </section>;
}
