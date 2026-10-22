'use client';
import React, { useEffect, useRef, useState } from 'react';
import { directoryUsers } from '@/lib/directoryUsers';
import { companyAutomation, automationActions, licenseAutomationAction, AutomationEnrollment, AutomationGrant, AutomationJob, AutomationPrincipal, AutomationSchedule, AutomationHistory, AutomationLicenseReport } from '@/lib/companyAutomation';
import { companyLicenseGroups } from '@/lib/companyLicenseGroups';
const button = 'rounded border border-white/20 px-3 py-2 disabled:opacity-40';
const inputStyle: React.CSSProperties = { background: 'var(--bg-input)', color: 'var(--text-primary)', maxWidth: '100%' };
const names: Record<string, string> = { 'directory.users.export': 'Benutzer exportieren', 'directory.groups.export': 'Gruppen exportieren', 'directory.ous.export': 'Organisationseinheiten exportieren', 'licenses.groups.reconcile': 'Gruppenlizenzen zuweisen und entziehen' };
const statuses: Record<string, string> = { queued: 'Eingereiht', running: 'Läuft', retry_wait: 'Wartet auf Wiederholung', succeeded: 'Abgeschlossen', partial: 'Teilweise abgeschlossen – Mitglieder blockiert', failed: 'Fehlgeschlagen – Prüfung erforderlich', cancelled: 'Abgebrochen' };
export default function CompanyAutomationView() {
  const [principal, setPrincipal] = useState<AutomationPrincipal | null>(null); const [grants, setGrants] = useState<AutomationGrant[]>([]); const [selected, setSelected] = useState('');
  const [grantPage, setGrantPage] = useState(1); const [grantTotal, setGrantTotal] = useState(0);
  const [enrollmentId, setEnrollmentId] = useState(''); const [enrollment, setEnrollment] = useState<AutomationEnrollment | null>(null);
  const [actions, setActions] = useState<string[]>([]); const [hours, setHours] = useState(24); const [reason, setReason] = useState('');
  const [jobs, setJobs] = useState<AutomationJob[]>([]); const [schedules, setSchedules] = useState<AutomationSchedule[]>([]);
  const [history, setHistory] = useState<AutomationHistory | null>(null);
  const [ruleId, setRuleId] = useState(''); const [rule, setRule] = useState<Awaited<ReturnType<typeof companyLicenseGroups.inspect>> | null>(null);
  const [report, setReport] = useState<AutomationLicenseReport | null>(null); const [reportPage, setReportPage] = useState(1);
  const [jobPage, setJobPage] = useState(1); const [schedulePage, setSchedulePage] = useState(1); const [jobTotal, setJobTotal] = useState(0); const [scheduleTotal, setScheduleTotal] = useState(0);
  const [action, setAction] = useState(''); const [format, setFormat] = useState<'json' | 'csv'>('json'); const [minutes, setMinutes] = useState(60);
  const [loading, setLoading] = useState(true); const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [message, setMessage] = useState(''); const [reload, setReload] = useState(0);
  const [confirmation, setConfirmation] = useState<'approve' | 'revoke' | null>(null); const epoch = useRef(0); const grant = grants.find(row => row.id === selected);
  useEffect(() => { const id = new URLSearchParams(window.location.search).get('licenseRule'); if (id && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id)) setRuleId(id); }, []);
  useEffect(() => {
    const version = ++epoch.current; setLoading(true); setError(''); setPrincipal(null); setGrants([]); setJobs([]); setSchedules([]); setHistory(null); setReport(null); setRule(null); setEnrollment(null); setConfirmation(null);
    (async () => {
      const access = await directoryUsers.access(); if (!access.userId || access.demoMode || !access.companyOwner) throw new Error('Aktueller Firmeninhaberzugriff erforderlich.');
      const current = await companyAutomation.grants(access.userId, grantPage);
      if (version !== epoch.current) return; setPrincipal(current.principal); setGrants(current.grants); setGrantTotal(current.total); setJobPage(1); setSchedulePage(1); setAction(''); setSelected(previous => current.grants.some(row => row.id === previous) ? previous : current.grants[0]?.id || '');
    })().catch(failure => { if (version === epoch.current) setError(failure instanceof Error ? failure.message : 'Automationszugriff nicht bestätigt. Aktuelle Eigentümerrechte und MFA prüfen.'); })
      .finally(() => { if (version === epoch.current) setLoading(false); });
    return () => { epoch.current++; };
  }, [reload, grantPage]);
  useEffect(() => {
    if (!principal || !grant) return; let alive = true; const version = epoch.current; setJobs([]); setSchedules([]); setHistory(null); setReport(null);
    Promise.all([companyAutomation.jobs(grant, principal, jobPage), companyAutomation.schedules(grant, principal, schedulePage)]).then(([work, plans]) => {
      if (!alive || version !== epoch.current) return; setJobs(work.jobs); setJobTotal(work.total); setSchedules(plans.schedules); setScheduleTotal(plans.total);
    }).catch(() => { if (alive && version === epoch.current) setError('Jobs und Zeitpläne nicht vollständig bestätigt. Stand ausdrücklich neu laden.'); });
    return () => { alive = false; };
  }, [principal, grant, jobPage, schedulePage]);
  async function perform(operation: () => Promise<unknown>, success: string, refresh = true) {
    if (busy || loading || !principal || error) return; const version = epoch.current; setBusy(true); setMessage('');
    try { await operation(); if (version !== epoch.current) return; setMessage(success); setConfirmation(null); if (refresh) setReload(value => value + 1); }
    catch (failure) { if (version === epoch.current) setError(failure instanceof Error ? failure.message : 'Ausgang nicht bestätigt. Gespeicherten Stand vor Wiederholung prüfen.'); }
    finally { if (version === epoch.current) setBusy(false); }
  }
  async function inspect() {
    if (!principal) return; const current = principal; const version = epoch.current;
    await perform(async () => { const value = await companyAutomation.enrollment(enrollmentId.trim(), current); if (version === epoch.current) { setEnrollment(value); setActions([]); } }, 'Aktuelle App-Anmeldung gefunden. Rechte und Laufzeit ausdrücklich auswählen.', false);
  }
  async function download(job: AutomationJob) {
    if (!principal) return; const current = principal; const version = epoch.current;
    await perform(async () => {
      const artifact = await companyAutomation.artifact(job, current); if (version !== epoch.current) return;
      const url = URL.createObjectURL(new Blob([artifact.content], { type: artifact.contentType })); const link = document.createElement('a'); link.href = url; link.download = artifact.filename;
      document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
    }, 'Geprüfte Datei heruntergeladen.', false);
  }
  const disabled = loading || busy || !!error; const licensing = action === licenseAutomationAction;
  const validRule = !!rule && rule.rule.id === ruleId.trim() && rule.rule.tenantId === principal?.tenantId;
  return <section className="h-full overflow-auto p-6 space-y-5" style={{ colorScheme: 'dark' }} aria-label="Firmenautomationen">
    <header className="flex flex-wrap items-center justify-between gap-3"><div><h1 className="text-2xl font-semibold">Automationen</h1><p>App-Freigaben, dauerhafte Jobs und Zeitpläne des eigenen Unternehmens.</p></div><button className={button} disabled={busy} onClick={() => setReload(value => value + 1)}>Automationen neu laden</button></header>
    <p>Ein App-Konto meldet sich über <code>node scripts/od.mjs automation enroll "Name"</code> an. Du genehmigst konkrete Aktionen und eine Laufzeit. Der Lizenzabgleich darf eigene Pool-Sitze anhand bestehender Gruppenverknüpfungen zuweisen und entziehen; Herstellerfreischaltung und Mailbereitstellung sind separate Schritte.</p>
    {loading && <p role="status">Eigene Automationsrechte werden geprüft …</p>}{error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    {principal && <>
      <section className="space-y-3 rounded border border-white/20 p-4" aria-label="App-Automation freigeben"><h2 className="font-semibold">App-Automation freigeben</h2>
        <label className="block">Anmeldungs-ID<input aria-label="App-Anmeldungs-ID" className={button} style={inputStyle} value={enrollmentId} disabled={disabled} maxLength={36} onChange={event => { setEnrollmentId(event.target.value); setEnrollment(null); }}/></label>
        <button className={button} disabled={disabled || !enrollmentId} onClick={() => void inspect()}>App-Anmeldung prüfen</button>
        {enrollment && <><p>Von der App angegebener Name: {enrollment.name}</p><p>Client: <code>{enrollment.clientId}</code> · Generation {enrollment.clientRevision} · Anmeldung gültig bis {new Date(enrollment.expiresAt).toLocaleString()}</p>
          <fieldset disabled={disabled}><legend>Erlaubte Aktionen</legend>{automationActions.map(item => <label key={item} className="block"><input type="checkbox" checked={actions.includes(item)} onChange={event => setActions(previous => event.target.checked ? [...previous, item] : previous.filter(value => value !== item))}/>{names[item]}</label>)}</fieldset>
          <label className="block">Laufzeit in Stunden<input aria-label="Freigabe-Laufzeit in Stunden" className={button} style={inputStyle} type="number" min={1} max={720} value={hours} disabled={disabled} onChange={event => setHours(Number(event.target.value))}/></label>
          <label className="block">Begründung<input aria-label="Automationsfreigabe begründen" className={button} style={inputStyle} maxLength={500} value={reason} disabled={disabled} onChange={event => setReason(event.target.value)}/></label>
          <button className={button} disabled={disabled || !actions.length || reason.trim().length < 10 || !Number.isInteger(hours) || hours < 1 || hours > 720} onClick={() => setConfirmation('approve')}>Ausgewählte App-Rechte bestätigen</button>
        </>}
      </section>
      <section className="space-y-3 rounded border border-white/20 p-4" aria-label="Eigene App-Freigaben"><h2 className="font-semibold">Eigene App-Freigaben</h2>
        <div className="flex gap-2"><button className={button} disabled={disabled || grantPage === 1} onClick={() => setGrantPage(value => value - 1)}>Vorherige Freigaben</button><span>Seite {grantPage} · {grantTotal} Freigaben</span><button className={button} disabled={disabled || grantPage * 25 >= grantTotal} onClick={() => setGrantPage(value => value + 1)}>Weitere Freigaben</button></div>
        {!grants.length ? <p>Noch keine App-Freigabe erteilt.</p> : <label className="block">Freigabe<select aria-label="Automationsfreigabe auswählen" className={button} style={inputStyle} value={selected} disabled={disabled} onChange={event => { setSelected(event.target.value); setJobPage(1); setSchedulePage(1); setAction(''); }}>{grants.map(row => <option key={row.id} value={row.id}>{row.clientId} · Generation {row.clientRevision} · {row.status === 'revoked' ? 'Widerrufen' : Date.parse(row.expiresAt) <= Date.now() ? 'Abgelaufen' : 'Freigegeben'} · {row.id}</option>)}</select></label>}
        {grant && <><p>Erlaubt: {grant.actions.map(value => names[value]).join(', ')}. Gültig bis {new Date(grant.expiresAt).toLocaleString()}.</p><p>Worker auf deinem Runner starten: <code>node scripts/od.mjs automation worker {grant.id}</code>. Er verwendet das genehmigte App-Konto und kann nach Neustart gespeicherte Jobs weiterbearbeiten.</p>
          {grant.status === 'active' && <button className={button} disabled={disabled} onClick={() => setConfirmation('revoke')}>App-Freigabe widerrufen</button>}
          <label className="block">Aktion<select aria-label="Automationsaktion" className={button} style={inputStyle} disabled={disabled} value={action} onChange={event => { setAction(event.target.value); if (event.target.value === licenseAutomationAction) { setFormat('json'); setMinutes(1); } }}><option value="">Aktion wählen</option>{grant.actions.map(value => <option key={value} value={value}>{names[value]}</option>)}</select></label>
          {licensing && <div className="space-y-2"><label className="block">Lizenzgruppen-Verknüpfung<input aria-label="Lizenzgruppen-Verknüpfungs-ID" className={button} style={inputStyle} disabled={disabled} value={ruleId} maxLength={36} onChange={event => { setRuleId(event.target.value); setRule(null); }}/></label>
            <button className={button} disabled={disabled || !ruleId} onClick={() => { const current = epoch.current; void perform(async () => { const value = await companyLicenseGroups.inspect(ruleId.trim(), { actorUserId: principal.userId, tenantId: principal.tenantId }); if (epoch.current === current) setRule(value); }, 'Eigene Lizenzgruppen-Verknüpfung geprüft.', false); }}>Lizenzgruppe prüfen</button>
            {rule && <p>Gruppe: {rule.groupName || rule.rule.groupId} · Pool: {rule.rule.poolId} · {rule.rule.status === 'active' ? `${rule.eligibleMembers} berechtigte Mitglieder` : 'Verknüpfung beendet: nur diese Gruppenquelle wird zurückgegeben.'}</p>}
          </div>}
          {!licensing && <label className="block">Exportformat<select aria-label="Exportformat" className={button} style={inputStyle} value={format} disabled={disabled} onChange={event => setFormat(event.target.value as 'json' | 'csv')}><option value="json">JSON</option><option value="csv">CSV</option></select></label>}
          <button className={button} disabled={disabled || !action || licensing && !validRule || grant.status !== 'active' || Date.parse(grant.expiresAt) <= Date.now()} onClick={() => void perform(() => companyAutomation.queue(grant, action, format, principal, undefined, licensing ? ruleId.trim() : undefined), 'Job dauerhaft eingereiht. Der genehmigte App-Worker führt ihn aus.')}>{licensing ? 'Lizenzabgleich einreihen' : 'Exportjob einreihen'}</button>
          <label className="block">Intervall in Minuten<input aria-label="Automationsintervall in Minuten" className={button} style={inputStyle} type="number" min={1} max={43200} value={minutes} disabled={disabled} onChange={event => setMinutes(Number(event.target.value))}/></label>
          <button className={button} disabled={disabled || !action || licensing && !validRule || grant.status !== 'active' || !Number.isInteger(minutes) || minutes < 1 || minutes > 43200 || Date.parse(grant.expiresAt) <= Date.now()} onClick={() => void perform(() => companyAutomation.queue(grant, action, format, principal, minutes * 60, licensing ? ruleId.trim() : undefined), 'Zeitplan gespeichert. Der laufende App-Worker prüft fällige Ausführungen.')}>Zeitplan erstellen</button>
        </>}
      </section>
      {grant && <>
        <section className="space-y-3" aria-label="Gespeicherte Automationsjobs"><h2 className="font-semibold">Gespeicherte Jobs</h2>{!jobs.length && <p>Keine Jobs auf dieser Seite.</p>}
          {jobs.map(job => <article key={job.id} className="rounded border border-white/20 p-3"><p>{names[job.action]} · {statuses[job.status]} · Versuch {job.attemptCount}/5</p><p className="break-all">{job.id}</p>{job.errorCode && <p>Fehlercode: {job.errorCode}</p>}
            {job.ruleId && <p>Lizenzgruppen-Verknüpfung: {job.ruleId}</p>}
            {job.progress && <p>Abgleich {job.progress.cycle} · {job.progress.completed}/{job.progress.total} Mitglieder · {job.progress.blocked} blockiert</p>}
            {job.ruleId && ['failed','cancelled','retry_wait'].includes(job.status) && <p>Bereits bestätigte Mitgliedsschritte bleiben gespeichert. Vor einer Wiederholung den aktuellen Poolstand und dessen Historie prüfen.</p>}
            <button className={button} disabled={disabled} onClick={() => { const version = epoch.current; void perform(async () => { const value = await companyAutomation.history(job, principal); if (version === epoch.current) setHistory(value); }, 'Gespeicherte Job-Historie geladen.', false); }}>Job-Historie</button>
            {['succeeded','partial'].includes(job.status) && <button className={button} disabled={disabled} onClick={() => void download(job)}>{job.ruleId ? `Lizenzbericht herunterladen (${job.rowCount} Mitglieder)` : `Export herunterladen (${job.rowCount} Zeilen)`}</button>}
            {job.action === licenseAutomationAction && ['succeeded','partial'].includes(job.status) && <button className={button} disabled={disabled} onClick={() => { const current = epoch.current; void perform(async () => { const value = await companyAutomation.licenseReport(job, grant, principal); if (current === epoch.current) { setReport(value); setReportPage(1); } }, 'Tatsächlicher Lizenzbericht geprüft.', false); }}>Lizenzbericht anzeigen</button>}
            {['queued', 'retry_wait', 'running'].includes(job.status) && <button className={button} disabled={disabled} onClick={() => void perform(() => companyAutomation.changeJob(job, 'cancel', principal), 'Job abgebrochen.')}>Job abbrechen</button>}
            {['failed','partial'].includes(job.status) && <button className={button} disabled={disabled || grant.status !== 'active'} onClick={() => void perform(() => companyAutomation.changeJob(job, 'retry', principal), 'Neue Versuchsfolge bestätigt; die frühere Historie bleibt erhalten.')}>Erneut einreihen</button>}
          </article>)}
          <div className="flex gap-2"><button className={button} disabled={disabled || jobPage === 1} onClick={() => setJobPage(value => value - 1)}>Vorherige Jobs</button><span>Seite {jobPage} · {jobTotal} Jobs</span><button className={button} disabled={disabled || jobPage * 25 >= jobTotal} onClick={() => setJobPage(value => value + 1)}>Weitere Jobs</button></div>
          {report && <aside aria-label="Geprüfter Lizenzbericht" className="rounded border border-white/20 p-3"><h3>Lizenzbericht · {report.hasBlocked ? 'Teilweise abgeschlossen' : 'Abgeschlossen'}</h3><p>Ausgeführt durch App {report.actor.clientId} · Abgleich {report.progress.cycle} · {report.progress.blocked} blockiert</p><ul>{report.results.slice((reportPage-1)*25,reportPage*25).map(item => <li key={item.userId}>{item.userId} · {{ assigned: 'Zugewiesen', retained: 'Bestehende Gruppenquelle bestätigt', removed: 'Gruppenquelle nicht mehr zugewiesen', blocked: 'Blockiert' }[item.status]}{item.code ? ` · Code ${item.code}` : ''}</li>)}</ul>
            <button className={button} disabled={reportPage===1} onClick={() => setReportPage(value => value-1)}>Vorherige Berichtseite</button><button className={button} disabled={reportPage*25>=report.results.length} onClick={() => setReportPage(value => value+1)}>Weitere Berichtseite</button>
          </aside>}
          {history && <aside aria-label="Job-Historie" className="rounded border border-white/20 p-3"><h3>Historie {history.jobId}</h3><ol>{history.events.map(event => <li key={event.revision}>{new Date(event.createdAt).toLocaleString()} · {statuses[event.status]} · Versuch {event.attemptCount} · {event.actor.kind === 'owner' ? event.actor.userId : event.actor.clientId}{event.errorCode ? ' · ' + event.errorCode : ''}</li>)}</ol>
            <div className="flex gap-2">{[-1, 1].map(direction => <button key={direction} className={button} disabled={disabled || direction < 0 && history.page === 1 || direction > 0 && history.page * 25 >= history.total} onClick={() => { const job = jobs.find(row => row.id === history.jobId); const version = epoch.current; if (job) void perform(async () => { const value = await companyAutomation.history(job, principal, history.page + direction); if (version === epoch.current) setHistory(value); }, 'Job-Historie geladen.', false); }}>{direction < 0 ? 'Frühere Ereignisse' : 'Weitere Ereignisse'}</button>)}</div>
          </aside>}
        </section>
        <section className="space-y-3" aria-label="Gespeicherte Automationszeitpläne"><h2 className="font-semibold">Zeitpläne</h2>{!schedules.length && <p>Keine Zeitpläne auf dieser Seite.</p>}
          {schedules.map(schedule => <article key={schedule.id} className="rounded border border-white/20 p-3"><p>{names[schedule.action]} · alle {schedule.intervalSeconds / 60} Minuten · {schedule.enabled ? 'Aktiv' : 'Gestoppt'}</p><p>Nächste Prüfung: {new Date(schedule.nextRunAt).toLocaleString()}</p>{schedule.enabled && <button className={button} disabled={disabled} onClick={() => void perform(() => companyAutomation.disable(schedule, principal), 'Zeitplan gestoppt; bereits erstellte Jobs separat beachten.')}>Zeitplan stoppen</button>}</article>)}
          <div className="flex gap-2"><button className={button} disabled={disabled || schedulePage === 1} onClick={() => setSchedulePage(value => value - 1)}>Vorherige Zeitpläne</button><span>Seite {schedulePage} · {scheduleTotal} Zeitpläne</span><button className={button} disabled={disabled || schedulePage * 25 >= scheduleTotal} onClick={() => setSchedulePage(value => value + 1)}>Weitere Zeitpläne</button></div>
        </section>
      </>}
      {confirmation && <div role="dialog" aria-modal="true" aria-label={confirmation === 'approve' ? 'App-Datenzugriff bestätigen' : 'App-Freigabe widerrufen'} className="rounded border border-amber-500 p-4 space-y-3">
        {confirmation === 'approve' && enrollment ? <p>Client {enrollment.clientId}, Generation {enrollment.clientRevision}, erhält für {hours} Stunden: {actions.map(value => names[value]).join(', ')}. Die App darf die ausgewählten Aktionen ohne eine offene menschliche Sitzung ausführen.{actions.includes(licenseAutomationAction) && ' Sie darf dabei eigene Lizenzsitze anhand bestehender Gruppenverknüpfungen zuweisen und entziehen.'}</p> : <p>Die ausgewählte App-Freigabe widerrufen? Ihre Zeitpläne werden gestoppt und noch laufende oder wartende Jobs abgebrochen. Bereits heruntergeladene Exporte bleiben beim Empfänger.</p>}
        <button className={button} disabled={disabled} onClick={() => void perform(() => confirmation === 'approve' && enrollment ? companyAutomation.approve(enrollment, actions, hours, reason, principal) : grant ? companyAutomation.revoke(grant, principal) : Promise.reject(new Error('Keine aktuelle Freigabe')), confirmation === 'approve' ? 'App-Freigabe gespeichert.' : 'App-Freigabe widerrufen.')}>Verbindlich bestätigen</button>
        <button className={button} disabled={busy} onClick={() => setConfirmation(null)}>Abbrechen</button>
      </div>}
    </>}
  </section>;
}
