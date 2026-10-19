'use client';

import React,{useEffect,useRef,useState} from 'react';
import toast from 'react-hot-toast';
import {directoryGroups,DirectoryGroup,GroupProfile} from '@/lib/directoryGroups';
import {directoryError,DirectoryAccess} from '@/lib/directoryUsers';
import {ensureSession} from '@/lib/auth';
import {DirectoryConfirmation} from './UserDetailPanel';

type Editor='create'|'edit'|'member'|null;
type Confirmation={kind:'delete'|'remove';group:DirectoryGroup;userId?:string}|null;
const panel={background:'var(--bg-surface, #161b22)',color:'var(--text-primary, #e4e6ea)'};
const control='rounded border border-white/20 px-3 py-2 disabled:opacity-40';

export default function UserGroupsView(){
 const [access,setAccess]=useState<DirectoryAccess|null>(null);const [groups,setGroups]=useState<DirectoryGroup[]>([]);const [selected,setSelected]=useState<DirectoryGroup|null>(null);
 const [loading,setLoading]=useState(true);const [error,setError]=useState('');const [search,setSearch]=useState('');const [busy,setBusy]=useState(false);
 const [editor,setEditor]=useState<Editor>(null);const [confirmation,setConfirmation]=useState<Confirmation>(null);const [operationError,setOperationError]=useState('');
 const [name,setName]=useState('');const [description,setDescription]=useState('');const [member,setMember]=useState('');const [notice,setNotice]=useState('');const sequence=useRef(0);
 const can=(permission:string)=>!!access?.permissions.includes(permission);
 const bound=!!access&&access.userId!==null&&!access.demoMode;
 const canCreate=bound&&access.directoryCreationProtocol===1&&can('groups.create');
 const canMutate=bound&&access.directoryGroupMutationProtocol===1;
 async function load(){
  const current=++sequence.current;setLoading(true);setError('');setGroups([]);setSelected(null);setAccess(null);setNotice('');
  try{const verified=await directoryGroups.access();if(current!==sequence.current)return;setAccess(verified);
   if(verified.permissions.includes('groups.read')){const result=await directoryGroups.list();if(current===sequence.current)setGroups(result.groups);}
  }catch(failure){if(current===sequence.current)setError(directoryError(failure));}finally{if(current===sequence.current)setLoading(false);}
 }
 useEffect(()=>{void load();return()=>{sequence.current++;};},[]);
 function update(group:DirectoryGroup){setSelected(group);setGroups(previous=>previous.some(row=>row.id===group.id)?previous.map(row=>row.id===group.id?group:row):[...previous,group]);}
 function open(next:Editor){setOperationError('');setNotice('');setName(next==='edit'?selected?.name||'':'');setDescription(next==='edit'?selected?.description||'':'');setMember('');setEditor(next);}
 function close(){if(busy)return;const uncertain=!!operationError;setEditor(null);setConfirmation(null);setOperationError('');if(uncertain)void load();}
 function selfCheck(group:DirectoryGroup,userId?:string){if(userId===access?.userId||!userId&&!!access?.userId&&group.members.includes(access.userId))void ensureSession(true).catch(()=>{});}
 async function save(event:React.FormEvent){
  event.preventDefault();if(busy||operationError||!editor)return;const action=editor;const original=selected;
  if(action==='create'?!canCreate:!canMutate||!original||!can(action==='edit'?'groups.update':'groups.members.manage'))return;
  setBusy(true);try{
   if(action==='member'&&original){const result=await directoryGroups.add(original,member.trim().toLowerCase());update(result);setNotice(result.membershipReview?.required&&!result.membershipReview.effective?'Verknüpfung bestätigt. Die unabhängige Gruppenfreigabe ist noch ausstehend.':'Verknüpfung bestätigt. Effektive App- und Lizenzfreigaben werden separat bewertet.');}
   else{const profile:GroupProfile={name:name.trim(),description:description.trim()||null};update(action==='create'?await directoryGroups.create(profile):await directoryGroups.update(original!,profile));setNotice(action==='create'?'Neue leere Verzeichnisgruppe bestätigt.':'Gruppenprofil bestätigt.');}
   setEditor(null);toast.success('Verzeichnisaktion bestätigt.');
  }catch(failure){setOperationError(directoryError(failure));}finally{setBusy(false);}
 }
 async function confirm(){
  if(!confirmation||busy||operationError||!canMutate||!can(confirmation.kind==='delete'?'groups.delete':'groups.members.manage'))return;const action=confirmation;setBusy(true);
  try{if(action.kind==='delete'){await directoryGroups.remove(action.group);setGroups(previous=>previous.filter(group=>group.id!==action.group.id));setSelected(null);setNotice('Kanonische Gruppe gelöscht. Externe Wirkungen sind separat zu prüfen.');}
   else{update(await directoryGroups.removeMember(action.group,action.userId!));setNotice('Entfernung der aktuellen Verknüpfung bestätigt. Externe Lizenzentfernung ist damit nicht bestätigt.');}
   selfCheck(action.group,action.userId);setConfirmation(null);toast.success('Verzeichnisaktion bestätigt.');
  }catch(failure){setOperationError(directoryError(failure));}finally{setBusy(false);}
 }
 const filtered=groups.filter(group=>[group.name,group.description||'',group.id].join(' ').toLowerCase().includes(search.toLowerCase()));
 return <section className="h-full overflow-auto p-6 space-y-5" style={{background:'var(--bg-base, #0e1115)',color:'var(--text-primary, #e4e6ea)'}} aria-label="Kanonische Gruppenverwaltung">
  <header className="flex flex-wrap items-center justify-between gap-3"><div><h1 className="text-2xl font-semibold">Verzeichnisgruppen</h1><p className="text-sm opacity-75">Echte Gruppen des angemeldeten Mandanten. Keine Beispieldaten.</p></div><div className="flex gap-3">
   <button className={control} disabled={loading||busy||!!editor||!!confirmation} onClick={()=>void load()}>Gruppen neu laden</button>
   {can('groups.create')&&<button className={control} disabled={!canCreate||loading||busy} onClick={()=>open('create')}>Gruppe erstellen</button>}
  </div></header>
  <p className="text-sm">Unterstützt werden flache kanonische Verzeichnisgruppen. Verschachtelte oder dynamische Gruppen und AD-Verteiler werden hier nicht vorgetäuscht. Verknüpfung bedeutet nicht automatisch wirksamen App- oder Lizenzzugriff.</p>
  {!loading&&bound&&!canMutate&&(can('groups.update')||can('groups.delete')||can('groups.members.manage'))&&<p role="status" className="rounded border border-amber-500/40 p-3">Mandantengebundene Änderungen an bestehenden Gruppen sind auf diesem Server noch nicht bestätigt. Die Schreibaktionen bleiben gesperrt.</p>}
  {loading&&<p role="status">Gruppen werden geprüft …</p>}{error&&<p role="alert">{error}</p>}{notice&&<p role="status">{notice}</p>}
  {!loading&&access&&!can('groups.read')&&<p>Keine Berechtigung zum Lesen der Gruppenliste.</p>}
  {!loading&&!error&&can('groups.read')&&<div className="grid gap-5 lg:grid-cols-[minmax(240px,1fr)_2fr]">
   <section aria-label="Kanonische Gruppenliste" className="rounded-xl border border-white/10 p-4 space-y-3"><label className="block">Gruppen suchen<input className={'mt-2 block w-full bg-transparent '+control} value={search} onChange={event=>setSearch(event.target.value)}/></label>
    <p>{groups.length} bestätigte Gruppen</p>{!groups.length?<p>Keine kanonischen Gruppen vorhanden.</p>:!filtered.length?<p>Keine passenden Gruppen.</p>:<ul className="space-y-2">{filtered.map(group=><li key={group.id}><button className={'w-full text-left '+control} disabled={busy} onClick={()=>{setSelected(group);setNotice('');}} aria-label={'Gruppe '+group.name} aria-pressed={selected?.id===group.id}><span className="block font-semibold">{group.name}</span><span className="text-xs break-all">{group.id}</span></button></li>)}</ul>}
   </section>
   {selected?<article aria-label="Gruppendetails" className="rounded-xl border border-white/10 p-5 space-y-4"><h2 className="text-xl font-semibold">{selected.name}</h2><p>{selected.description||'Keine Beschreibung hinterlegt.'}</p><dl className="space-y-2"><div><dt>Gruppen-ID</dt><dd className="break-all">{selected.id}</dd></div><div><dt>Datensatzversion</dt><dd>{selected.revision}</dd></div></dl>
    <div className="flex flex-wrap gap-3">{can('groups.update')&&<button className={control} disabled={!canMutate||busy} onClick={()=>open('edit')}>Gruppenprofil bearbeiten</button>}{can('groups.members.manage')&&<button className={control} disabled={!canMutate||busy} onClick={()=>open('member')}>Mitglied verknüpfen</button>}{can('groups.delete')&&<button className={control} disabled={!canMutate||busy} onClick={()=>{setOperationError('');setConfirmation({kind:'delete',group:selected});}}>Gruppe löschen</button>}</div>
    <h3 className="font-semibold">Verknüpfte Benutzer-IDs</h3>{!selected.members.length?<p>Keine Benutzer verknüpft.</p>:<ul className="space-y-2">{selected.members.map(userId=><li key={userId} className="flex flex-wrap items-center justify-between gap-2"><span className="break-all">{userId}</span>{can('groups.members.manage')&&<button className={control} disabled={!canMutate||busy} aria-label={'Verknüpfung '+userId+' entfernen'} onClick={()=>{setOperationError('');setConfirmation({kind:'remove',group:selected,userId});}}>Verknüpfung entfernen</button>}</li>)}</ul>}
    <p className="text-sm">Angezeigt werden kanonische Verknüpfungen, keine behaupteten effektiven Berechtigungen. Unabhängige Freigaben und Fristen findest du unter <a className="underline" href="/roles">Rollen &amp; Rechte</a>. Benutzerprofile werden für diese Ansicht nicht abgerufen.</p>
   </article>:<p>Wähle eine kanonische Gruppe.</p>}
  </div>}
  {!loading&&!can('groups.read')&&selected&&<p role="status">Bestätigte Gruppe: {selected.name} · {selected.id}</p>}
  {editor&&<div role="dialog" aria-modal="true" aria-label={editor==='create'?'Gruppe erstellen':editor==='edit'?'Gruppenprofil bearbeiten':'Mitglied verknüpfen'} className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-5"><form onSubmit={save} className="w-full max-w-lg rounded-xl p-6 space-y-4" style={panel}>
   <h2 className="text-xl font-semibold">{editor==='create'?'Neue leere Gruppe':editor==='edit'?'Kanonisches Gruppenprofil':'Benutzer-ID verknüpfen'}</h2>
   {editor==='member'?<><label className="block">Kanonische Benutzer-ID<input className={'mt-2 w-full bg-transparent '+control} required maxLength={36} value={member} disabled={busy||!!operationError} onChange={event=>setMember(event.target.value)}/></label><p className="text-sm">Nur eine bekannte ID desselben Mandanten. Dies richtet weder ein Konto noch eine sofortige Lizenz- oder App-Freigabe ein.</p></>:<><label className="block">Gruppenname<input className={'mt-2 w-full bg-transparent '+control} required maxLength={255} value={name} disabled={busy||!!operationError} onChange={event=>setName(event.target.value)}/></label><label className="block">Gruppenbeschreibung<textarea className={'mt-2 w-full bg-transparent '+control} maxLength={2000} value={description} disabled={busy||!!operationError} onChange={event=>setDescription(event.target.value)}/></label></>}
   {operationError&&<p role="alert">{operationError}</p>}<div className="flex justify-end gap-3"><button type="button" className={control} disabled={busy} onClick={close}>Abbrechen</button><button type="submit" className={control} disabled={busy||!!operationError}>{busy?'Wird bestätigt …':'Verbindlich speichern'}</button></div>
  </form></div>}
  {confirmation&&<DirectoryConfirmation title={confirmation.kind==='delete'?'Kanonische Gruppe löschen':'Aktuelle Verknüpfung entfernen'} busy={busy} error={operationError} onClose={close} onConfirm={()=>void confirm()}><p>{confirmation.group.name} · <span className="break-all">{confirmation.group.id}</span></p>{confirmation.userId&&<p className="break-all">Benutzer-ID: {confirmation.userId}</p>}
   <p className="mt-3">Die Aktion bindet die angezeigte Gruppenversion. Entfernte App-/Lizenzquellen und externe Konten müssen separat bewertet werden; ein lokaler Beleg bestätigt keine Microsoft-Provisionierung.</p>
   {(confirmation.userId===access?.userId||confirmation.kind==='delete'&&!!access?.userId&&confirmation.group.members.includes(access.userId))&&<p className="mt-3 text-amber-400">Dein eigener Zugriff kann damit enden. Stelle einen unabhängigen Wiederherstellungsweg sicher.</p>}
  </DirectoryConfirmation>}
 </section>;
}
