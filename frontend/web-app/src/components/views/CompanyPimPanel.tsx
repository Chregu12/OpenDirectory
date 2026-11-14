'use client';
import React,{useEffect,useRef,useState} from 'react';
import {useIdentityAccess} from '@/hooks/useIdentityAccess';
import {companyPim,CompanyPimState,CompanyPimItem} from '@/lib/companyPim';
import {directoryError} from '@/lib/directoryUsers';
import {DirectoryConfirmation} from './UserDetailPanel';
const date=(value:string)=>new Date(value).toLocaleString('de-CH');
const labels={active:'Aktiv',invalid:'Nicht mehr wirksam',expired:'Abgelaufen',ended:'Beendet'};
export default function CompanyPimPanel({management=false}:{management?:boolean}){
 const {access,can}=useIdentityAccess();const actor=access?.userId||'',supported=access?.companyPimProtocol===1;
 const original=useRef(actor);original.current=actor;const generation=useRef(0),command=useRef<AbortController|null>(null);
 const [state,setState]=useState<CompanyPimState|null>(null),[tab,setTab]=useState<'eligible'|'active'|'history'>('eligible'),[page,setPage]=useState(1),[search,setSearch]=useState(''),[draft,setDraft]=useState(''),[reload,setReload]=useState(0),[error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false);
 const [history,setHistory]=useState<Awaited<ReturnType<typeof companyPim.history>>|null>(null),[action,setAction]=useState<{kind:'activate'|'end';item:CompanyPimItem;actor:string}|null>(null),[minutes,setMinutes]=useState(60),[reason,setReason]=useState('');
 const invalidate=(failure:unknown)=>{generation.current++;command.current?.abort();setState(null);setHistory(null);setAction(null);setBusy(false);setNotice('');setError(directoryError(failure));};
 useEffect(()=>{const expected=++generation.current,controller=new AbortController();setState(null);setHistory(null);setAction(null);setBusy(false);setError('');
  const invalid=()=>{generation.current++;controller.abort();command.current?.abort();setState(null);setHistory(null);setAction(null);setBusy(false);setNotice('');setError('Die ursprüngliche Sitzung ist nicht mehr gültig. Bitte erneut anmelden.');};window.addEventListener('od:session-error',invalid);
  if(supported&&actor){const request=tab==='history'?companyPim.history(actor,page,controller.signal):companyPim.self(actor,tab,page,search,controller.signal);request.then(value=>{if(expected!==generation.current||controller.signal.aborted)return;if('items' in value)setState(value);else setHistory(value);}).catch(failure=>{if(expected===generation.current&&!controller.signal.aborted)invalidate(failure);});}
  return()=>{generation.current++;controller.abort();command.current?.abort();window.removeEventListener('od:session-error',invalid);};
 },[actor,supported,tab,page,search,reload]);
 useEffect(()=>{if(busy||action||!supported)return;const timer=window.setInterval(()=>setReload(value=>value+1),30000);return()=>window.clearInterval(timer);},[busy,action,supported]);
 const nextExpiry=Math.min(Infinity,...(state?.items.flatMap(item=>item.activation?.status==='active'?[Date.parse(item.activation.expiresAt)]:[])||[]));
 useEffect(()=>{if(!Number.isFinite(nextExpiry))return;const timer=window.setTimeout(()=>{setReload(value=>value+1);window.dispatchEvent(new Event('od:directory-access-changed'));},Math.max(0,nextExpiry-Date.now()));return()=>window.clearTimeout(timer);},[nextExpiry]);
 const open=(kind:'activate'|'end',item:CompanyPimItem)=>{setAction({kind,item,actor});setMinutes(Math.min(60,Math.floor(item.maximumDurationSeconds/60)));setReason('');setNotice('');};
 const confirm=async()=>{if(!action||!state||busy||action.actor!==actor||Array.from(reason.trim()).length<10)return;
  const current=action,expected=generation.current,controller=new AbortController();command.current=controller;setBusy(true);setError('');
  try{if(current.kind==='activate')await companyPim.activate(actor,state.tenantId,current.item.eligibility,minutes*60,reason,controller.signal);else await companyPim.end(actor,state.tenantId,current.item.activation!,reason,controller.signal);
   if(expected!==generation.current||original.current!==current.actor||controller.signal.aborted)return;setAction(null);setNotice(current.kind==='activate'?'Firmenrolle aktiviert und protokolliert.':'Aktivierung beendet und protokolliert.');setReload(value=>value+1);window.dispatchEvent(new Event('od:directory-access-changed'));
  }catch(failure){if(expected===generation.current&&!controller.signal.aborted)invalidate(failure);}finally{if(expected===generation.current)setBusy(false);}
 };
 if(!supported)return null;
 const total=state?.total??history?.total??0;
 return <section className="od-pim mt-6" aria-label="Eigene Firmenrollen aktivieren">
  <div className="od-pim-heading"><div><h2>Firmenrollen</h2><p>Aktiviere deine zugewiesenen Verzeichnisaufgaben für die benötigte Dauer.</p></div>{can('company.roles.read')&&<a className="od-text-action" href="/company-roles">Zuweisungen verwalten</a>}</div>
  {notice&&<p role="status" className="od-pim-message">{notice}</p>}
  {error&&<div role="alert" className="od-pim-message od-pim-error"><p>{error}</p><a className="od-text-action" href={'/api/auth/oidc/login?returnTo='+encodeURIComponent(management?'/pim':'/dashboard')}>Erneut anmelden</a></div>}
  <nav className="od-pim-tabs" aria-label="Firmenrollenansichten">{(['eligible','active','history'] as const).map(value=><button className="fluent-btn-ghost" key={value} aria-current={tab===value?'page':undefined} disabled={busy} onClick={()=>{setTab(value);setPage(1);setAction(null);setNotice('');}}>{{eligible:'Berechtigt',active:'Aktiv',history:'Mein Protokoll'}[value]}</button>)}</nav>
  <form className="od-pim-toolbar" onSubmit={event=>{event.preventDefault();setPage(1);setSearch(draft.trim());setReload(value=>value+1);}}>{tab!=='history'&&<><label className="od-pim-search"><span className="sr-only">Firmenrollen suchen</span><input maxLength={255} placeholder="Firmenrollen suchen" value={draft} disabled={busy} onChange={event=>setDraft(event.target.value)}/></label><button className="fluent-btn-secondary" disabled={busy}>Suchen</button></>}<button className="fluent-btn-ghost" type="button" disabled={busy} onClick={()=>setReload(value=>value+1)}>Aktualisieren</button></form>
  {!state&&!history&&!error&&<p role="status" className="od-pim-empty">Firmenrollen werden geladen …</p>}
  {state&&<><div className="od-pim-table-scroll"><table className="od-pim-table"><thead><tr><th>Rolle / Bereich</th><th>Status</th><th>Dauer / Ablauf</th><th>Aktion</th></tr></thead><tbody>{state.items.map(item=>{
   const active=item.activation?.status==='active',status=item.activation?labels[item.activation.status]:'Berechtigt';return <tr key={tab==='active'?item.activation!.id:item.eligibility.id}>
    <td><strong>{item.role.name}</strong><span>{item.eligibility.scopeType==='tenant'?'Eigene Firma':(item.ouName||item.eligibility.ouId)+' mit Untereinheiten'}{item.groupName?' · '+item.groupName:''}</span><span className="od-pim-mobile-meta">{status}{active?' · bis '+date(item.activation!.expiresAt):''}</span></td><td><span className={active?'od-pim-active-status':''}>{status}</span></td><td>{active?'Bis '+date(item.activation!.expiresAt):'Max. '+Math.floor(item.maximumDurationSeconds/60)+' Minuten'}</td>
    <td><div className="od-pim-actions">{tab==='eligible'&&!active&&<button className="fluent-btn-primary" disabled={busy||!state.canActivate||item.maximumDurationSeconds<60} onClick={()=>open('activate',item)}>Aktivieren</button>}{item.activation&&!item.activation.endedAt&&<button className="fluent-btn-secondary" disabled={busy} onClick={()=>open('end',item)}>Beenden</button>}</div></td></tr>;
   })}</tbody></table></div>{!state.items.length&&<p className="od-pim-empty">{tab==='active'?'Keine laufenden Firmenrollen-Aktivierungen.':'Keine berechtigten Firmenrollen zugewiesen.'}</p>}{!state.canActivate&&tab==='eligible'&&state.items.length>0&&<p className="od-pim-message">Zum Aktivieren ist eine höchstens fünf Minuten alte MFA-Anmeldung erforderlich. <a className="od-text-action" href={'/api/auth/oidc/login?returnTo='+encodeURIComponent(management?'/pim':'/dashboard')}>Erneut anmelden</a></p>}</>}
  {history&&<ol className="space-y-3 p-4 text-sm">{history.events.map(event=><li key={event.id}><p>{event.action==='activation-create'?'Aktiviert':event.action==='activation-cancel'?'Selbst beendet':'Durch Rollenverwaltung entzogen'} · {date(event.createdAt)}</p><p>{event.reason}</p><p className="break-all">Benutzer: {event.actorUserId} · Aktivierung: {event.resourceId}</p><p>Ereigniszustellung ausstehend</p></li>)}{!history.events.length&&<li>Keine eigenen Aktivierungen protokolliert.</li>}</ol>}
  {(state||history)&&<nav className="od-pim-pagination" aria-label="Firmenrollen-Seiten"><button className="fluent-btn-secondary" disabled={busy||page<=1} onClick={()=>setPage(value=>value-1)}>Zurück</button><span>Seite {page} von {Math.max(1,Math.ceil(total/25))} · {total} Einträge</span><button className="fluent-btn-secondary" disabled={busy||page*25>=total} onClick={()=>setPage(value=>value+1)}>Weiter</button></nav>}
  {action&&state&&<DirectoryConfirmation title={action.kind==='activate'?'Firmenrolle aktivieren':'Firmenrolle beenden'} busy={busy} error="" onClose={()=>setAction(null)} onConfirm={()=>void confirm()} confirmDisabled={Array.from(reason.trim()).length<10||Array.from(reason.trim()).length>500||action.kind==='activate'&&(!Number.isInteger(minutes*60)||minutes<1||minutes*60>action.item.maximumDurationSeconds)}>
   <p>{action.item.role.name} · {action.item.eligibility.scopeType==='tenant'?'Eigene Firma':action.item.ouName||action.item.eligibility.ouId}</p>
   {action.kind==='activate'&&<><p className="mt-3 text-sm">Die Aktivierung gilt nur für diese Zuweisung. Ablauf, Entzug oder Änderungen der zugrunde liegenden Rolle beenden ihre Wirkung. Die Anmelderichtlinie bleibt verbindlich.</p><label className="block mt-3">Dauer (Minuten)<input className="input-apple" type="number" min={1} max={Math.floor(action.item.maximumDurationSeconds/60)} value={minutes} disabled={busy} onChange={event=>setMinutes(Number(event.target.value))}/></label></>}
   <label className="block mt-3">Begründung<input className="input-apple" maxLength={500} value={reason} disabled={busy} onChange={event=>setReason(event.target.value)}/></label>
  </DirectoryConfirmation>}
 </section>;
}
