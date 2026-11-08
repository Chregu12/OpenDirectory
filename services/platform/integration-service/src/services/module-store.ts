const { Pool } = require("pg");
export const moduleDefaults = {
  "monitoring-analytics": {
    enabled: true,
    name: "Monitoring & Analytics",
    description: "Grafana und Prometheus",
  },
  "secrets-management": {
    enabled: true,
    name: "Secrets Management",
    description: "Konfiguration der Secrets-Navigation",
  },
  "device-management": {
    enabled: true,
    name: "Geräteverwaltung",
    description: "Inventar, Zuweisungen und Geräteanbindung",
  },
  "network-infrastructure": {
    enabled: true,
    name: "Netzwerk",
    description: "Konfiguration der Infrastruktur-Navigation",
  },
  "security-suite": {
    enabled: true,
    name: "Sicherheit",
    description: "Konfiguration der Sicherheits-Navigation",
  },
};
type Database = {
  query: (
    text: string,
    values?: unknown[],
  ) => Promise<{ rows: any[]; rowCount?: number | null }>;
};
export class ModuleStore {
  private initializing: Promise<void> | null = null;
  constructor(
    private database: Database = new Pool({
      max: 3,
      connectionTimeoutMillis: 5000,
      query_timeout: 5000,
      allowExitOnIdle: true,
    }),
  ) {}
  private initialize() {
    if (!this.initializing)
      this.initializing = (async () => {
        await this.database.query(
          "CREATE TABLE IF NOT EXISTS platform_module_settings (id TEXT PRIMARY KEY, enabled BOOLEAN NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
        );
        for (const [id, value] of Object.entries(moduleDefaults))
          await this.database.query(
            "INSERT INTO platform_module_settings(id,enabled) VALUES($1,$2) ON CONFLICT(id) DO NOTHING",
            [id, value.enabled],
          );
      })().catch((error) => {
        this.initializing = null;
        throw error;
      });
    return this.initializing;
  }
  async list() {
    await this.initialize();
    const result = await this.database.query(
      "SELECT id,enabled FROM platform_module_settings",
    );
    const rows = new Map(result.rows.map((row) => [row.id, row.enabled]));
    return Object.fromEntries(
      Object.entries(moduleDefaults).map(([id, value]) => {
        if (typeof rows.get(id) !== "boolean")
          throw new Error("Incomplete module configuration");
        return [id, { ...value, enabled: rows.get(id) }];
      }),
    );
  }
  async update(id: string, enabled: boolean) {
    if (
      !Object.prototype.hasOwnProperty.call(moduleDefaults, id) ||
      typeof enabled !== "boolean"
    )
      throw new Error("Invalid module change");
    await this.initialize();
    const result = await this.database.query(
      "UPDATE platform_module_settings SET enabled=$2,updated_at=NOW() WHERE id=$1 RETURNING id,enabled",
      [id, enabled],
    );
    if (result.rows.length !== 1 || result.rows[0].enabled !== enabled)
      throw new Error("Module update unconfirmed");
    return { ...moduleDefaults[id as keyof typeof moduleDefaults], enabled };
  }
}
