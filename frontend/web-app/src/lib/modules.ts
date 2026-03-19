/**
 * OpenDirectory Module Registry
 *
 * Zentrale Definition aller verfügbaren Module mit RAM-Kosten.
 * Wird vom Setup-Wizard, ServicesDashboard und RAM-Meter gemeinsam genutzt.
 *
 * Neue Module hinzufügen:
 *   1. Eintrag hier in MODULES ergänzen
 *   2. Docker-Compose Profile in docker-compose.lite.yml anlegen
 *   3. Fertig — Wizard und Settings zeigen es automatisch
 */

export interface ModuleDefinition {
  id: string;
  name: string;
  description: string;
  /** RAM in MB that this module requires */
  ramMB: number;
  /** Docker Compose profile name */
  profile: string;
  /** Category for grouping in UI */
  category: 'core' | 'infrastructure' | 'security' | 'monitoring' | 'enterprise';
  /** Features included in this module */
  features: string[];
  /** Heroicon name for display */
  iconName: string;
  /** Whether this module is recommended for new installations */
  recommended?: boolean;
  /** Ports this module exposes */
  ports?: { port: number; protocol: string; description: string }[];
}

/** Core system RAM cost in MB (always running) */
export const CORE_RAM_MB = 2112;

/** Individual core service RAM breakdown */
export const CORE_SERVICES = [
  { name: 'PostgreSQL', ramMB: 384, description: 'Datenbank' },
  { name: 'MongoDB', ramMB: 384, description: 'Geräte-Daten' },
  { name: 'Redis', ramMB: 96, description: 'Cache & Sessions' },
  { name: 'LLDAP', ramMB: 64, description: 'User-Verzeichnis' },
  { name: 'Identity Service', ramMB: 160, description: 'User-Management' },
  { name: 'Auth Service', ramMB: 160, description: 'Authentifizierung' },
  { name: 'Device Service', ramMB: 160, description: 'Geräte-Management' },
  { name: 'Policy Service', ramMB: 160, description: 'Policy-Engine' },
  { name: 'API Gateway', ramMB: 128, description: 'Routing & Load Balancing' },
  { name: 'API Backend', ramMB: 160, description: 'REST-API' },
  { name: 'Web App', ramMB: 256, description: 'Frontend (Next.js)' },
] as const;

/** All optional modules */
export const MODULES: ModuleDefinition[] = [
  {
    id: 'network',
    name: 'Netzwerk',
    description: 'DNS-Server, DHCP, SMB/NFS File Shares, Netzwerk-Discovery',
    ramMB: 192,
    profile: 'network',
    category: 'infrastructure',
    iconName: 'GlobeAltIcon',
    recommended: true,
    features: [
      'DNS-Server (Port 53)',
      'DHCP-Server (Port 67)',
      'SMB File Shares (Port 445)',
      'NFS Shares (Port 2049)',
      'Netzwerk-Discovery',
    ],
    ports: [
      { port: 53, protocol: 'TCP/UDP', description: 'DNS' },
      { port: 67, protocol: 'UDP', description: 'DHCP' },
      { port: 445, protocol: 'TCP', description: 'SMB' },
      { port: 2049, protocol: 'TCP', description: 'NFS' },
      { port: 3007, protocol: 'TCP', description: 'API' },
    ],
  },
  {
    id: 'printers',
    name: 'Drucker',
    description: 'Drucker- & Scanner-Management mit CUPS',
    ramMB: 192,
    profile: 'printers',
    category: 'infrastructure',
    iconName: 'PrinterIcon',
    features: [
      'CUPS Print Server',
      'Auto-Discovery',
      'Drucker-Quotas',
      'Scanner-Integration',
      'Job-Tracking',
    ],
    ports: [
      { port: 631, protocol: 'TCP', description: 'CUPS Admin' },
      { port: 3006, protocol: 'TCP', description: 'API' },
    ],
  },
  {
    id: 'monitoring',
    name: 'Monitoring',
    description: 'Grafana Dashboards & Prometheus Metriken',
    ramMB: 448,
    profile: 'monitoring',
    category: 'monitoring',
    iconName: 'ChartBarIcon',
    features: [
      'Grafana Dashboards',
      'Prometheus Metrics',
      'Alert-Regeln',
      'Custom Reports',
      'Performance-Tracking',
    ],
    ports: [
      { port: 3500, protocol: 'TCP', description: 'Grafana' },
      { port: 9090, protocol: 'TCP', description: 'Prometheus' },
    ],
  },
  {
    id: 'security',
    name: 'Security',
    description: 'CIS/NIST Compliance Scanner & Auto-Remediation',
    ramMB: 320,
    profile: 'security',
    category: 'security',
    iconName: 'ShieldCheckIcon',
    features: [
      'CIS Benchmark Scanner',
      'NIST Compliance',
      'BSI Grundschutz',
      'Auto-Remediation',
      'Compliance Reports',
    ],
    ports: [
      { port: 3902, protocol: 'TCP', description: 'Scanner' },
      { port: 3904, protocol: 'TCP', description: 'Remediation' },
    ],
  },
  {
    id: 'lifecycle',
    name: 'Lifecycle',
    description: 'Geräte-Lifecycle, Graph Explorer & Policy Simulator',
    ramMB: 448,
    profile: 'lifecycle',
    category: 'enterprise',
    iconName: 'CpuChipIcon',
    features: [
      'Device Lifecycle Management',
      'AD Graph Explorer',
      'Policy Simulator (What-If)',
      'Risk Scoring',
      'Angriffspfad-Analyse',
    ],
    ports: [
      { port: 3900, protocol: 'TCP', description: 'Graph Explorer' },
      { port: 3901, protocol: 'TCP', description: 'Policy Simulator' },
      { port: 3903, protocol: 'TCP', description: 'Lifecycle' },
    ],
  },
];

/**
 * Calculate total RAM for a set of enabled modules
 * @param enabledModuleIds - Array of module IDs that are enabled
 * @returns Object with total, core, and per-module breakdown
 */
export function calculateRam(enabledModuleIds: string[]) {
  const moduleRam = enabledModuleIds.reduce((sum, id) => {
    const mod = MODULES.find(m => m.id === id);
    return sum + (mod?.ramMB ?? 0);
  }, 0);

  return {
    coreMB: CORE_RAM_MB,
    modulesMB: moduleRam,
    totalMB: CORE_RAM_MB + moduleRam,
    totalGB: ((CORE_RAM_MB + moduleRam) / 1024).toFixed(1),
    breakdown: [
      ...CORE_SERVICES.map(s => ({ name: s.name, ramMB: s.ramMB, type: 'core' as const })),
      ...enabledModuleIds
        .map(id => MODULES.find(m => m.id === id))
        .filter(Boolean)
        .map(m => ({ name: m!.name, ramMB: m!.ramMB, type: 'module' as const })),
    ],
  };
}

/** Get module by ID */
export function getModule(id: string): ModuleDefinition | undefined {
  return MODULES.find(m => m.id === id);
}

/** Get all module IDs */
export function getAllModuleIds(): string[] {
  return MODULES.map(m => m.id);
}
