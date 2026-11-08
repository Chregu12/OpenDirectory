"use client";
import { useCallback, useEffect, useState } from "react";
import { BellAlertIcon, ArrowPathIcon } from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
type Alert = {
  labels: Record<string, string>;
  annotations?: Record<string, string>;
  state: string;
  activeAt?: string;
  value?: string;
};
export default function AlertingView() {
  const [rows, setRows] = useState<Alert[] | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = (await api.get("/api/prometheus/alerts")).data;
      if (
        !Array.isArray(data?.data?.alerts) ||
        data.data.alerts.some(
          (row: Alert) =>
            !row.labels ||
            typeof row.labels.alertname !== "string" ||
            !["firing", "pending", "inactive"].includes(row.state),
        )
      )
        throw new Error("Invalid alerts");
      setRows(data.data.alerts);
    } catch {
      setRows(null);
      setError(
        "Monitoring-Meldungen konnten nicht geladen werden. Der Systemzustand ist nicht bestätigt.",
      );
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 30000);
    return () => clearInterval(timer);
  }, [load]);
  const filtered = rows?.filter((row) =>
    [...Object.values(row.labels), ...Object.values(row.annotations || {})]
      .join(" ")
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  return (
    <div className="space-y-6">
      <PageHeader
        title="Benachrichtigungen"
        subtitle="Aktuelle Prometheus-Meldungen · Quelle und Auslösung bleiben sichtbar"
        icon={BellAlertIcon}
        actions={
          <button
            className="fluent-btn-secondary"
            disabled={loading}
            onClick={() => void load()}
          >
            <ArrowPathIcon
              className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            Aktualisieren
          </button>
        }
      />
      {error && <p role="alert">{error}</p>}
      {loading && <p role="status">Monitoring-Meldungen werden geladen …</p>}
      <div className="grid gap-4 sm:grid-cols-3">
        {[
          ["Ausgelöst", rows?.filter((row) => row.state === "firing").length],
          ["In Prüfung", rows?.filter((row) => row.state === "pending").length],
          ["Meldungen insgesamt", rows?.length],
        ].map(([label, value]) => (
          <div key={label} className="od-panel">
            <p style={{ color: "var(--text-muted)" }}>{label}</p>
            <p className="text-2xl font-semibold mt-2">{value ?? "—"}</p>
          </div>
        ))}
      </div>
      <div className="od-tabs-panel p-5 space-y-4">
        <label className="block max-w-lg">
          Meldungen durchsuchen
          <input
            className="input-apple mt-2"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            maxLength={200}
          />
        </label>
        {rows?.length === 0 && (
          <p>
            Prometheus meldet zum bestätigten Prüfzeitpunkt keine aktiven
            Regeln. Dies ist keine Prüfung aller OpenDirectory-Dienste.
          </p>
        )}
        {!!rows?.length && filtered?.length === 0 && (
          <p>Keine Meldungen für diese Suche.</p>
        )}
        {filtered?.map((row, index) => (
          <article
            key={JSON.stringify(row.labels) + index}
            className="od-panel space-y-3"
          >
            <div className="flex flex-wrap justify-between gap-3">
              <h2 className="font-semibold">
                {row.annotations?.summary || row.labels.alertname}
              </h2>
              <span className="od-badge">
                {row.state === "firing"
                  ? "Ausgelöst"
                  : row.state === "pending"
                    ? "In Prüfung"
                    : "Inaktiv"}{" "}
                · {row.labels.severity || "Schweregrad nicht angegeben"}
              </span>
            </div>
            {row.annotations?.description && (
              <p className="text-sm">{row.annotations.description}</p>
            )}
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Quelle: Prometheus ·{" "}
              {row.labels.job || row.labels.namespace || "kein Job angegeben"} ·
              seit{" "}
              {row.activeAt
                ? new Date(row.activeAt).toLocaleString("de-CH")
                : "nicht angegeben"}
            </p>
            <details>
              <summary>Messwert und Labels</summary>
              <p className="mt-3">Wert: {row.value ?? "nicht angegeben"}</p>
              <dl className="grid gap-3 mt-3 sm:grid-cols-2">
                {Object.entries(row.labels).map(([key, value]) => (
                  <div key={key}>
                    <dt
                      className="text-xs"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {key}
                    </dt>
                    <dd className="break-all text-sm">{value}</dd>
                  </div>
                ))}
              </dl>
            </details>
          </article>
        ))}
      </div>
      <section className="od-panel space-y-3">
        <h2 className="font-semibold">Regeln und Zustellung</h2>
        <p className="text-sm">
          Die bestehende Verbindung liest Prometheus-Meldungen. Quittierung,
          Stummschaltung und Versandkanäle benötigen einen angebundenen
          Alertmanager-Vertrag. Hier werden keine nur im Browser gespeicherten
          Regeln oder simulierten Zustellungen angeboten.
        </p>
        <div className="flex flex-wrap gap-3">
          <a className="fluent-btn-secondary" href="/monitoring">
            Monitoring
          </a>
          <a className="fluent-btn-secondary" href="/integrations">
            Dienstverbindungen
          </a>
        </div>
      </section>
    </div>
  );
}
