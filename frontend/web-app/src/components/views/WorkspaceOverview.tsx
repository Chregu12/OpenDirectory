'use client';
import { useIdentityAccess } from '@/hooks/useIdentityAccess';
import { ViewShell } from '@/components/ui/ViewShell';
import PIMGroupsPanel from './PIMGroupsPanel';

export default function WorkspaceOverview() {
  const { access, unavailable, reload } = useIdentityAccess();
  const tasks = [
    { href: '/organization', title: 'Organisation', description: 'Firmenprofil und Organisationsstruktur bearbeiten.', visible: access?.permissions.some(permission => ['organization.read', 'ous.read'].includes(permission)) },
    { href: '/users', title: 'Mitarbeitende', description: 'Verzeichniseinträge und Kontofreigabe prüfen.', visible: access?.permissions.some(permission => ['users.read', 'users.create'].includes(permission)) },
    { href: '/employee-invitations', title: 'Einladungen', description: 'Annahme, Ablauf und Versandstatus prüfen.', visible: access?.companyOwner },
    { href: '/usergroups', title: 'Gruppen', description: 'Mitgliedschaften, Regeln und Lizenzquellen prüfen.', visible: access?.permissions.includes('groups.read') },
    { href: '/devices', title: 'Geräteinventar', description: 'Inventarzuweisungen und Rückgaben mit frischer MFA bearbeiten.', visible: access?.companyOwner },
    { href: '/applications', title: 'Apps & Lizenzen', description: 'Lokale Bestände, Zuweisungsquellen und Offboarding öffnen.', visible: access?.companyOwner },
    { href: '/company-blueprints', title: 'Firmen-Blueprints', description: 'Entwürfe, lokale Versionen und Zuweisungen prüfen.', visible: access?.companyOwner },
    { href: '/automation', title: 'Automationen', description: 'Freigaben, letzte Läufe und offene Teilschritte prüfen.', visible: access?.companyOwner },
  ].filter(task => task.visible);
  return <ViewShell title="Übersicht" subtitle={access?.companyOwner ? 'Arbeitsbereich deiner eigenen Firma' : 'Deine freigegebenen Aufgaben'} onRefresh={reload}>
    <div className="mb-6"><PIMGroupsPanel /></div>
    {unavailable ? <p role="alert">Deine Aufgabenberechtigungen konnten nicht bestätigt werden. Bitte erneut prüfen.</p> : !access ? <p role="status">Aufgaben werden geprüft …</p> : <>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">{tasks.map(task => <a key={task.href} href={task.href} className="od-panel block hover:border-[var(--accent)]">
        <h2 className="text-lg font-semibold">{task.title}</h2><p className="mt-2 text-sm" style={{ color: 'var(--text-secondary)' }}>{task.description}</p>
      </a>)}</div>
      {!tasks.length && <p>Für deine Sitzung sind keine Verwaltungsaufgaben freigegeben.</p>}
      <section className="od-object-section mt-8"><h2>Deine Anmeldung</h2><div className="flex flex-wrap gap-3"><a className="fluent-btn-secondary" href="/mfa">MFA einrichten oder prüfen</a><a className="fluent-btn-secondary" href="/sspr">Passwort zurücksetzen</a></div></section>
      <p className="mt-6 text-sm" style={{ color: 'var(--text-secondary)' }}>Die Fachansichten prüfen ihren aktuellen Datenstand und die Berechtigung beim Öffnen. Hier werden keine ungeprüften Gesamtzahlen oder Systemzustände angezeigt.</p>
    </>}
  </ViewShell>;
}
