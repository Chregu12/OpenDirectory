'use client';

import React, { useState, useMemo } from 'react';
import {
  CheckCircleIcon,
  ClockIcon,
  ExclamationCircleIcon,
  FunnelIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ArrowTopRightOnSquareIcon,
} from '@heroicons/react/24/outline';
import { CheckCircleIcon as CheckCircleSolid } from '@heroicons/react/24/solid';

type Status = 'done' | 'in-progress' | 'todo';

interface RoadmapItem {
  id: string;
  title: string;
  description: string;
  status: Status;
  view?: string;   // nav target if clickable
  tags?: string[];
}

interface RoadmapCategory {
  id: string;
  title: string;
  emoji: string;
  items: RoadmapItem[];
}

const ROADMAP: RoadmapCategory[] = [
  {
    id: 'directory',
    title: 'Verzeichnis & Identität',
    emoji: '👤',
    items: [
      { id: 'd1',  status: 'done',        title: 'Benutzer CRUD',                    description: 'Erstellen, bearbeiten, löschen von Benutzern mit LLDAP-Synchronisation.',                                  view: 'users',      tags: ['LLDAP', 'Backend'] },
      { id: 'd2',  status: 'done',        title: 'Gruppen & Organisationseinheiten',  description: 'Gruppen verwalten, Mitglieder hinzufügen/entfernen, OU-Hierarchie mit Tree-View.',                        view: 'users',      tags: ['LLDAP', 'Backend', 'UI'] },
      { id: 'd3',  status: 'done',        title: 'SCIM 2.0 Sync',                    description: 'SCIM-Verbindungen zu Google Workspace, Entra ID, etc. mit Sync-Log und Konfliktauflösung.',               view: 'users',      tags: ['SCIM', 'Backend'] },
      { id: 'd4',  status: 'done',        title: 'Identity Provider (OIDC/SAML)',     description: 'OAuth2-Provider, SAML-SP, Kerberos KDC, JWT-Ausstellung — alles in IdentityProviderView.',               view: 'identity',   tags: ['OIDC', 'SAML', 'Kerberos'] },
      { id: 'd5',  status: 'done',        title: 'Enrollment Hub',                   description: 'Plattform-spezifische Enrollment-Skripte für macOS, Windows, Linux, iOS, Android.',                       view: 'enrollment', tags: ['MDM', 'Agent'] },
      { id: 'd6',  status: 'done',        title: 'Rollen & Berechtigungen',           description: 'RBAC mit vordefinierten Rollen (Admin, IT, Read-Only) und custom Berechtigungen.',                        view: 'permissions',tags: ['RBAC'] },
      { id: 'd7',  status: 'todo',        title: 'Self-Service Passwort-Reset',       description: 'Benutzer können ihr Passwort via E-Mail-Token oder TOTP selbst zurücksetzen, ohne Admin-Eingriff.',      tags: ['Portal', 'E-Mail'] },
      { id: 'd8',  status: 'todo',        title: 'MFA / 2FA Enforcement',            description: 'TOTP-, WebAuthn- und SMS-2FA erzwingen pro Benutzer/Gruppe mit Grace-Period.',                           tags: ['Security', 'TOTP', 'WebAuthn'] },
      { id: 'd9',  status: 'todo',        title: 'Conditional Access',               description: 'Zugriffsregeln basierend auf Gerätezustand, Netzwerk, Tageszeit — wie in Entra Conditional Access.',    tags: ['Policy', 'Zero Trust'] },
      { id: 'd10', status: 'todo',        title: 'Guest-Accounts',                   description: 'Temporäre Gastkonten mit Ablaufdatum, eingeschränkten Berechtigungen und Einladungs-Workflow.',          tags: ['Verzeichnis'] },
      { id: 'd11', status: 'todo',        title: 'LDAP-Proxy (Legacy)',              description: 'LDAP-kompatibles Interface damit alte Apps (Confluence, Jira, etc.) direkt gegen OpenDirectory binden.',tags: ['LDAP', 'Kompatibilität'] },
    ],
  },
  {
    id: 'devices',
    title: 'Geräte & MDM',
    emoji: '💻',
    items: [
      { id: 'dv1',  status: 'done',       title: 'Geräte-Inventar',                  description: 'Vollständiges Geräte-Inventar mit PostgreSQL-Persistenz, Compliance-Status, Letztgesehen.',              view: 'devices',    tags: ['PostgreSQL', 'Backend'] },
      { id: 'dv2',  status: 'done',       title: 'Apple MDM (APNs)',                 description: 'Apple MDM-Server mit APNs-Push, DeviceLock, Erase, InstallApp, Profil-Push via .mobileconfig.',         view: 'devices',    tags: ['Apple', 'MDM', 'APNs'] },
      { id: 'dv3',  status: 'done',       title: 'Go MDM Agent (Win/Mac/Linux)',      description: 'Cross-compiled Go-Agent mit Heartbeat, Befehls-Polling, ClamAV-Scan, Compliance-Reporting.',           view: 'enrollment', tags: ['Agent', 'Go'] },
      { id: 'dv4',  status: 'done',       title: 'Blueprints',                       description: 'Gerätekonfigurations-Profile (WiFi, VPN, FileVault, Gatekeeper) mit Zuweisung zu Geräten/Gruppen.',      view: 'blueprints', tags: ['Config', 'MDM'] },
      { id: 'dv5',  status: 'in-progress',title: 'Blueprint Apply → MDM Push',       description: 'Apply-Button sendet Konfiguration als MDM-Befehl ans Gerät. Backend done, Agent-Empfang fehlt noch.',   view: 'blueprints', tags: ['MDM', 'Agent'] },
      { id: 'dv6',  status: 'in-progress',title: 'App Store (Software-Verteilung)',   description: 'Katalog mit Paketen, Deployment-Targets, Download/Install via Agent. UI fertig, echte Pakete fehlen.',  view: 'appstore',   tags: ['Packages', 'Agent'] },
      { id: 'dv7',  status: 'todo',       title: 'macOS DEP / Zero-Touch',           description: 'Apple Automated Device Enrollment (ADE) via ABM-Integration — Gerät bootet direkt in MDM-Enrollment.',  tags: ['Apple', 'DEP', 'ABM'] },
      { id: 'dv8',  status: 'todo',       title: 'iOS Supervised Mode',              description: 'iOS-Geräteverwaltung im Supervised Mode: App-Beschränkungen, Kiosk, Content-Filter.',                   tags: ['iOS', 'MDM'] },
      { id: 'dv9',  status: 'todo',       title: 'Windows Autopilot',                description: 'Windows Autopilot-ähnlicher Workflow für Zero-Touch Windows-Deployment via MDM.',                       tags: ['Windows', 'MDM'] },
      { id: 'dv10', status: 'todo',       title: 'Gerätezertifikate (SCEP)',         description: 'SCEP-Endpoint damit Geräte automatisch Client-Zertifikate von der internen CA beziehen.',               tags: ['PKI', 'SCEP', 'Zertifikate'] },
      { id: 'dv11', status: 'todo',       title: 'Android Enterprise (AMAPI)',       description: 'Android Management API Integration für Work Profile und Fully Managed Devices.',                        tags: ['Android', 'MDM'] },
    ],
  },
  {
    id: 'network',
    title: 'Netzwerk & Infrastruktur',
    emoji: '🌐',
    items: [
      { id: 'n1',  status: 'done',        title: 'DNS-Verwaltung',                   description: 'DNS-Records CRUD mit PostgreSQL-Persistenz. A, AAAA, CNAME, MX, TXT-Einträge.',                         view: 'infrastructure', tags: ['DNS', 'PostgreSQL'] },
      { id: 'n2',  status: 'done',        title: 'DHCP-Leases',                      description: 'DHCP-Lease-Übersicht und statische Zuweisungen mit PostgreSQL-Persistenz.',                              view: 'infrastructure', tags: ['DHCP', 'PostgreSQL'] },
      { id: 'n3',  status: 'done',        title: 'VLAN-Verwaltung',                  description: 'VLANs definieren, umbenennen, Subnetze zuweisen — persistiert in PostgreSQL.',                          view: 'infrastructure', tags: ['VLAN', 'Netzwerk'] },
      { id: 'n4',  status: 'done',        title: 'Kerberos KDC',                     description: 'Kerberos Key Distribution Center mit REST Admin-API, automatische User-Sync.',                          view: 'identity',       tags: ['Kerberos', 'Auth'] },
      { id: 'n5',  status: 'in-progress', title: 'Netzwerk-Topologie',               description: 'Visualisierung aller Geräte, Switches, Router als interaktiver Graph. Grundstruktur vorhanden.',        view: 'topology',       tags: ['Visualisierung'] },
      { id: 'n6',  status: 'todo',        title: 'VPN-Profile Push (WireGuard)',      description: 'WireGuard-Konfiguration über Blueprint/MDM auf Geräte pushen, Key-Austausch automatisiert.',          tags: ['VPN', 'WireGuard', 'MDM'] },
      { id: 'n7',  status: 'todo',        title: 'Wi-Fi Profil-Push',                description: 'SSID + Passwort/Zertifikat via MDM-Blueprint auf Geräte deployen (bereits in Blueprint-Schema).',      view: 'blueprints',     tags: ['WiFi', 'MDM'] },
      { id: 'n8',  status: 'todo',        title: 'RADIUS / 802.1X',                  description: 'FreeRADIUS-Integration für netzwerkbasierte Authentifizierung an Switches und APs.',                    tags: ['RADIUS', '802.1X', 'Auth'] },
      { id: 'n9',  status: 'todo',        title: 'Firewall-Regelwerk',               description: 'Zentrale Firewall-Richtlinien definieren und via Agent auf Linux-Hosts (nftables/iptables) deployen.',  tags: ['Firewall', 'Policy'] },
      { id: 'n10', status: 'todo',        title: 'Certificate Authority (CA)',        description: 'Interne CA: Root- und Intermediate-Zertifikate ausstellen, CRL/OCSP, automatische Erneuerung.',        tags: ['PKI', 'TLS', 'Zertifikate'] },
    ],
  },
  {
    id: 'security',
    title: 'Sicherheit',
    emoji: '🛡️',
    items: [
      { id: 's1',  status: 'done',        title: 'Antivirus (ClamAV + Defender)',    description: 'ClamAV-Scan via Agent-Befehl, Parse FOUND-Zeilen, Report an Backend, Windows Defender PowerShell.',    view: 'antivirus',  tags: ['ClamAV', 'Agent'] },
      { id: 's2',  status: 'done',        title: 'Security Scanner',                 description: 'CVE-Checks, offene Ports, Schwachstellenscan — Findings in PostgreSQL, Risk-Score, Trends.',             view: 'scanner',    tags: ['CVE', 'Scanner'] },
      { id: 's3',  status: 'done',        title: 'Compliance-Checks',               description: 'CIS-Benchmark-Checks (Passwort-Policy, Firewall aktiv, verschlüsselte Disk) pro Gerät.',                 view: 'compliance', tags: ['CIS', 'Policy'] },
      { id: 's4',  status: 'done',        title: 'Secrets Management (Vault)',       description: 'HashiCorp Vault Integration: Secrets lesen/schreiben, Policies verwalten, Lease-Übersicht.',             view: 'secrets',    tags: ['Vault', 'Secrets'] },
      { id: 's5',  status: 'in-progress', title: 'Threat Intelligence',             description: 'Threat-Feed-Integration (MISP/OTX) für bekannte IOCs. Backend-Datenmodell vorhanden.',                  view: 'antivirus',  tags: ['Threat Intel', 'IOC'] },
      { id: 's6',  status: 'in-progress', title: 'Quarantäne-Management',            description: 'Erkannte Bedrohungen isolieren, in Quarantäne verschieben, Wiederherstellung. UI-Grundlage da.',        view: 'antivirus',  tags: ['Quarantäne'] },
      { id: 's7',  status: 'todo',        title: 'FileVault / BitLocker Enforcement', description: 'Festplattenverschlüsselung via MDM erzwingen und Recovery-Keys zentral escrowen.',                    view: 'blueprints', tags: ['Encryption', 'MDM'] },
      { id: 's8',  status: 'todo',        title: 'Gatekeeper (macOS)',               description: 'Gatekeeper-Richtlinie via MDM-Profil setzen und Compliance prüfen.',                                    view: 'blueprints', tags: ['macOS', 'MDM'] },
      { id: 's9',  status: 'todo',        title: 'EDR-Integration',                  description: 'Anbindung von CrowdStrike, SentinelOne oder OSSEC für erweitertes Endpoint Detection & Response.',       tags: ['EDR', 'Integration'] },
      { id: 's10', status: 'todo',        title: 'SIEM-Export (Syslog/CEF)',         description: 'Security-Events im CEF-Format an Splunk/QRadar/Graylog weiterleiten.',                                 tags: ['SIEM', 'Syslog', 'CEF'] },
      { id: 's11', status: 'todo',        title: 'Zero Trust Network Access (ZTNA)', description: 'Gerät+Identität vor jedem Zugriff prüfen — Integration mit Netzwerk-Policies und Conditional Access.',  tags: ['Zero Trust', 'ZTNA'] },
    ],
  },
  {
    id: 'operations',
    title: 'Monitoring & Betrieb',
    emoji: '📊',
    items: [
      { id: 'o1',  status: 'done',        title: 'Audit Log',                        description: 'Alle Admin-Aktionen werden protokolliert: Wer, Was, Wann, Von wo — filterbar und exportierbar.',         view: 'audit',      tags: ['Compliance', 'Audit'] },
      { id: 'o2',  status: 'in-progress', title: 'Monitoring Dashboard',             description: 'Prometheus-Metriken, Grafana-Einbettung, Service-Health. UI vorhanden, echte Daten fehlen.',             view: 'monitoring', tags: ['Prometheus', 'Grafana'] },
      { id: 'o3',  status: 'in-progress', title: 'Backup & Disaster Recovery',       description: 'Backup-Jobs planen, Status prüfen, Restore anstoßen. UI-Grundlage da, Backend-Jobs fehlen.',            view: 'backup',     tags: ['Backup', 'DR'] },
      { id: 'o4',  status: 'todo',        title: 'Alerting (E-Mail / Slack)',        description: 'Schwellenwert-basierte Alerts wenn Compliance fällt, Threats erkannt, Services down — via Webhooks.',    tags: ['Alerts', 'Notifications'] },
      { id: 'o5',  status: 'todo',        title: 'Service-Health-Dashboard',        description: 'Live-Übersicht ob alle Docker-Services laufen, DB erreichbar ist, Ports offen — alles auf einen Blick.',  view: 'monitoring', tags: ['Health', 'Docker'] },
      { id: 'o6',  status: 'todo',        title: 'Log-Aggregation',                  description: 'Zentralisierte Logs aller Services in Loki/Elasticsearch mit Suchinterface im UI.',                      tags: ['Logs', 'Loki'] },
      { id: 'o7',  status: 'todo',        title: 'Scheduled Tasks / Automation',     description: 'Cronjobs direkt im UI definieren: nächtliche Scans, wöchentliche Berichte, automatische Updates.',       tags: ['Automation', 'Cron'] },
      { id: 'o8',  status: 'todo',        title: 'Update-Mechanismus',               description: 'OpenDirectory-Version anzeigen, Docker-Images updaten, Rollback auf vorherige Version.',                 view: 'settings',   tags: ['Updates', 'Docker'] },
    ],
  },
  {
    id: 'integrations',
    title: 'Integrationen & API',
    emoji: '🔌',
    items: [
      { id: 'i1',  status: 'done',        title: 'Webhooks (Outbound Events)',       description: 'Webhooks für user.created, device.enrolled, threat.detected etc. — CRUD-UI und Signatur-Validation.',    tags: ['Webhooks', 'Events'] },
      { id: 'i2',  status: 'done',        title: 'API-Keys',                         description: 'Service-Account API-Keys generieren und verwalten — für Automationen und externe Integrationen.',        tags: ['API', 'Auth'] },
      { id: 'i3',  status: 'in-progress', title: 'SCIM-Sync UI',                    description: 'Verbindungen zu externen IdPs (Google, Entra) anzeigen, Sync anstoßen, Konflikte auflösen.',            view: 'users',      tags: ['SCIM', 'Google', 'Entra'] },
      { id: 'i4',  status: 'todo',        title: 'Integrationen-Hub (SyncView)',     description: 'Zentrales UI für alle Integrationen, Webhooks und API-Keys an einem Ort — noch nicht in Nav.',         tags: ['UI', 'Nav'] },
      { id: 'i5',  status: 'todo',        title: 'Slack / Teams Benachrichtigungen', description: 'Wichtige Events direkt in Slack/Teams-Channels senden — als Webhook-Template vorkonfiguriert.',         tags: ['Slack', 'Teams', 'Notifications'] },
      { id: 'i6',  status: 'todo',        title: 'Jira / ServiceNow Ticketing',      description: 'Bei Compliance-Failure oder Threat automatisch ein Ticket erstellen.',                                  tags: ['ITSM', 'Ticketing'] },
      { id: 'i7',  status: 'todo',        title: 'REST API Dokumentation (Swagger)', description: 'OpenAPI 3.0 Spec für alle Endpoints mit Swagger-UI direkt im Portal — für Entwickler.',               tags: ['API', 'Docs', 'Swagger'] },
      { id: 'i8',  status: 'todo',        title: 'Terraform Provider',               description: 'Terraform-Provider damit Infra-as-Code-Teams Benutzer, Gruppen und Geräte deklarativ verwalten.',      tags: ['Terraform', 'IaC'] },
    ],
  },
  {
    id: 'infra',
    title: 'Deployment & Infrastruktur',
    emoji: '⚙️',
    items: [
      { id: 'inf1', status: 'done',       title: 'Docker Compose',                   description: 'Vollständiges docker-compose.yml mit allen 20+ Services, Health-Checks, Volumes, Networks.',            tags: ['Docker', 'Deployment'] },
      { id: 'inf2', status: 'done',       title: 'PostgreSQL für alle Services',      description: 'Jeder Service hat eigene DB mit Migrations-Skripten — keine in-memory Daten mehr.',                   tags: ['PostgreSQL', 'Persistence'] },
      { id: 'inf3', status: 'done',       title: 'API Gateway',                      description: 'Zentrales Gateway mit Routing, Auth-Middleware, Rate-Limiting, CORS für alle Services.',               tags: ['Gateway', 'Auth'] },
      { id: 'inf4', status: 'in-progress',title: 'Kubernetes Helm Chart',             description: 'Helm-Chart für K8s-Deployment mit Ingress, PersistentVolumeClaims, HPA. In Arbeit.',                  tags: ['Kubernetes', 'Helm'] },
      { id: 'inf5', status: 'todo',       title: 'High Availability (HA)',            description: 'Mehrere Replicas für kritische Services (Auth, Gateway), PostgreSQL-Replication, Redis-Cluster.',       tags: ['HA', 'Skalierung'] },
      { id: 'inf6', status: 'todo',       title: 'Multi-Tenancy',                    description: 'Mehrere Organisationen auf einer Instanz mit strikter Datentrennung — für MSPs.',                       tags: ['Multi-Tenant', 'MSP'] },
      { id: 'inf7', status: 'todo',       title: 'SMTP-Server (eingehende E-Mails)', description: 'Eigener SMTP-Server damit Passwort-Reset, Alerts und Einladungen direkt aus OpenDirectory kommen.',   tags: ['E-Mail', 'SMTP'] },
      { id: 'inf8', status: 'todo',       title: 'Backup-Schedule & Retention',      description: 'Automatische nächtliche DB-Dumps, S3/MinIO-Upload, Retention-Policy konfigurierbar.',                  view: 'backup',     tags: ['Backup', 'S3'] },
    ],
  },
];

const STATUS_CONFIG: Record<Status, { label: string; color: string; bg: string; icon: React.ComponentType<{ className?: string }> }> = {
  done:        { label: 'Fertig',     color: 'text-[#34C759]', bg: 'bg-[#F0FFF4]', icon: CheckCircleSolid },
  'in-progress': { label: 'In Arbeit', color: 'text-[#FF9500]', bg: 'bg-[#FFFBEB]', icon: ClockIcon },
  todo:        { label: 'Offen',      color: 'text-[#8E8E93]', bg: 'bg-[#F2F2F7]', icon: ExclamationCircleIcon },
};

const ALL_TAGS = Array.from(
  new Set(ROADMAP.flatMap(cat => cat.items.flatMap(i => i.tags ?? [])))
).sort();

interface Props {
  onViewChange?: (view: string) => void;
}

export default function RoadmapView({ onViewChange }: Props) {
  const [filterStatus, setFilterStatus] = useState<Status | 'all'>('all');
  const [filterTag,    setFilterTag]    = useState<string>('');
  const [collapsed,    setCollapsed]    = useState<Record<string, boolean>>({});
  const [search,       setSearch]       = useState('');

  const toggleCategory = (id: string) =>
    setCollapsed(prev => ({ ...prev, [id]: !prev[id] }));

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return ROADMAP.map(cat => ({
      ...cat,
      items: cat.items.filter(item => {
        if (filterStatus !== 'all' && item.status !== filterStatus) return false;
        if (filterTag && !(item.tags ?? []).includes(filterTag)) return false;
        if (q && !item.title.toLowerCase().includes(q) && !item.description.toLowerCase().includes(q)) return false;
        return true;
      }),
    })).filter(cat => cat.items.length > 0);
  }, [filterStatus, filterTag, search]);

  const totals = useMemo(() => {
    const all = ROADMAP.flatMap(c => c.items);
    return {
      total: all.length,
      done:  all.filter(i => i.status === 'done').length,
      inProgress: all.filter(i => i.status === 'in-progress').length,
      todo: all.filter(i => i.status === 'todo').length,
    };
  }, []);

  const donePercent = Math.round((totals.done / totals.total) * 100);

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">

      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold text-[#1D1D1F] tracking-tight">Roadmap & TODO</h1>
        <p className="text-sm text-[#8E8E93] mt-1">Alle Features auf einen Blick — was fertig ist, was gerade gebaut wird und was noch aussteht.</p>
      </div>

      {/* Progress Overview */}
      <div className="bg-white rounded-xl border border-[#E5E5EA] p-5">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-medium text-[#1D1D1F]">Gesamtfortschritt</span>
          <span className="text-sm font-semibold text-[#0071E3]">{donePercent}%</span>
        </div>
        <div className="h-2 bg-[#F2F2F7] rounded-full overflow-hidden">
          <div
            className="h-full bg-[#0071E3] rounded-full transition-all duration-500"
            style={{ width: `${donePercent}%` }}
          />
        </div>
        <div className="flex gap-6 mt-4">
          {([ ['done', totals.done], ['in-progress', totals.inProgress], ['todo', totals.todo] ] as [Status, number][]).map(([s, count]) => {
            const cfg = STATUS_CONFIG[s];
            const Icon = cfg.icon;
            return (
              <button
                key={s}
                onClick={() => setFilterStatus(filterStatus === s ? 'all' : s)}
                className={`flex items-center gap-2 text-sm px-3 py-1.5 rounded-full border transition-all ${
                  filterStatus === s
                    ? `${cfg.bg} border-transparent ${cfg.color} font-medium`
                    : 'border-[#E5E5EA] text-[#3C3C43] hover:bg-[#F2F2F7]'
                }`}
              >
                <Icon className={`w-4 h-4 ${cfg.color}`} />
                <span>{cfg.label}</span>
                <span className={`font-semibold ${cfg.color}`}>{count}</span>
              </button>
            );
          })}
          <div className="ml-auto text-sm text-[#8E8E93]">{totals.total} Features gesamt</div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap items-center">
        <div className="relative flex-1 min-w-[200px]">
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Feature suchen…"
            className="w-full pl-3 pr-3 py-2 text-sm bg-white border border-[#E5E5EA] rounded-lg focus:outline-none focus:border-[#0071E3] focus:ring-1 focus:ring-[#0071E3]"
          />
        </div>
        <div className="flex items-center gap-2">
          <FunnelIcon className="w-4 h-4 text-[#8E8E93]" />
          <select
            value={filterTag}
            onChange={e => setFilterTag(e.target.value)}
            className="text-sm bg-white border border-[#E5E5EA] rounded-lg px-3 py-2 focus:outline-none focus:border-[#0071E3]"
          >
            <option value="">Alle Tags</option>
            {ALL_TAGS.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        {(filterStatus !== 'all' || filterTag || search) && (
          <button
            onClick={() => { setFilterStatus('all'); setFilterTag(''); setSearch(''); }}
            className="text-sm text-[#0071E3] hover:underline"
          >
            Filter zurücksetzen
          </button>
        )}
      </div>

      {/* Categories */}
      {filtered.map(cat => {
        const catDone = cat.items.filter(i => i.status === 'done').length;
        const isCollapsed = collapsed[cat.id];
        return (
          <div key={cat.id} className="bg-white rounded-xl border border-[#E5E5EA] overflow-hidden">
            {/* Category Header */}
            <button
              onClick={() => toggleCategory(cat.id)}
              className="w-full flex items-center justify-between px-5 py-4 hover:bg-[#F9F9F9] transition-colors"
            >
              <div className="flex items-center gap-3">
                <span className="text-xl">{cat.emoji}</span>
                <span className="font-semibold text-[#1D1D1F]">{cat.title}</span>
                <span className="text-xs text-[#8E8E93] bg-[#F2F2F7] px-2 py-0.5 rounded-full">
                  {catDone}/{cat.items.length}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-24 h-1.5 bg-[#F2F2F7] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-[#34C759] rounded-full"
                    style={{ width: `${cat.items.length ? (catDone / cat.items.length) * 100 : 0}%` }}
                  />
                </div>
                {isCollapsed
                  ? <ChevronRightIcon className="w-4 h-4 text-[#8E8E93]" />
                  : <ChevronDownIcon  className="w-4 h-4 text-[#8E8E93]" />}
              </div>
            </button>

            {/* Items */}
            {!isCollapsed && (
              <div className="divide-y divide-[#F2F2F7]">
                {cat.items.map(item => {
                  const cfg = STATUS_CONFIG[item.status];
                  const Icon = cfg.icon;
                  return (
                    <div key={item.id} className="px-5 py-3.5 flex items-start gap-4 hover:bg-[#F9F9F9] group transition-colors">
                      <Icon className={`w-5 h-5 mt-0.5 flex-shrink-0 ${cfg.color}`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`text-sm font-medium ${item.status === 'done' ? 'text-[#1D1D1F]' : item.status === 'in-progress' ? 'text-[#1D1D1F]' : 'text-[#3C3C43]'}`}>
                            {item.title}
                          </span>
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${cfg.bg} ${cfg.color}`}>
                            {cfg.label}
                          </span>
                          {item.tags?.map(tag => (
                            <button
                              key={tag}
                              onClick={() => setFilterTag(filterTag === tag ? '' : tag)}
                              className={`text-xs px-1.5 py-0.5 rounded border transition-colors ${
                                filterTag === tag
                                  ? 'border-[#0071E3] text-[#0071E3] bg-[#EAF4FF]'
                                  : 'border-[#E5E5EA] text-[#8E8E93] hover:border-[#0071E3] hover:text-[#0071E3]'
                              }`}
                            >
                              {tag}
                            </button>
                          ))}
                        </div>
                        <p className="text-xs text-[#8E8E93] mt-0.5 leading-relaxed">{item.description}</p>
                      </div>
                      {item.view && onViewChange && (
                        <button
                          onClick={() => onViewChange(item.view!)}
                          className="flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 text-xs text-[#0071E3] hover:underline"
                        >
                          Öffnen
                          <ArrowTopRightOnSquareIcon className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}

      {filtered.length === 0 && (
        <div className="text-center py-16 text-[#8E8E93]">
          <ExclamationCircleIcon className="w-10 h-10 mx-auto mb-3 opacity-40" />
          <p className="text-sm">Keine Features für diesen Filter gefunden.</p>
        </div>
      )}
    </div>
  );
}
