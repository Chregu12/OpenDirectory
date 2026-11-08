"use client";
import { useCallback, useEffect, useState } from "react";
import { SignalIcon, ArrowPathIcon } from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
type Service = {
  id: string;
  name: string;
  status: string;
  lastCheck?: string;
  responseTime?: number;
};
export default function ServiceHealthView() {
  const [services, setServices] = useState<Service[] | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.get("/api/services");
      if (
        !Array.isArray(response.data) ||
        response.data.some(
          (value: Service) =>
            !value.id ||
            !value.name ||
            ![
              "healthy",
              "disabled",
              "unknown",
              "degraded",
              "unhealthy",
            ].includes(value.status),
        )
      )
        throw new Error("Invalid health");
      setServices(response.data);
    } catch {
      setServices(null);
      setError(
        "Dienstzustände konnten nicht bestätigt werden. Es wird kein gesunder Ersatzstatus angezeigt.",
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
  const configured = services?.filter(
    (service) => service.status !== "disabled",
  );
  return (
    <div className="space-y-6">
      <PageHeader
        title="Dienstzustand"
        subtitle="Bestätigte Verbindungen des Integrationsdienstes · Aktualisierung alle 30 Sekunden"
        icon={SignalIcon}
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
      {loading && <p role="status">Dienste werden geprüft …</p>}
      <div className="grid gap-4 sm:grid-cols-3">
        {[
          [
            "Verbunden",
            services?.filter((service) => service.status === "healthy").length,
          ],
          ["Konfigurierte Dienste", configured?.length],
          [
            "Nicht eingerichtet",
            services?.filter((service) => service.status === "disabled").length,
          ],
        ].map(([label, value]) => (
          <div className="od-panel" key={label}>
            <p style={{ color: "var(--text-muted)" }}>{label}</p>
            <p className="text-2xl font-semibold mt-2">{value ?? "—"}</p>
          </div>
        ))}
      </div>
      {services?.length === 0 && (
        <p>Die bestätigte Quelle enthält keine Dienste.</p>
      )}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {services?.map((service) => (
          <article className="od-panel space-y-3" key={service.id}>
            <div className="flex justify-between gap-3">
              <h2 className="font-semibold">{service.name}</h2>
              <span
                className="od-badge"
                style={{
                  color:
                    service.status === "healthy"
                      ? "var(--success)"
                      : "var(--text-secondary)",
                }}
              >
                {
                  (
                    {
                      healthy: "Verbunden",
                      disabled: "Nicht eingerichtet",
                      unknown: "Nicht bestätigt",
                      degraded: "Eingeschränkt",
                      unhealthy: "Gestört",
                    } as Record<string, string>
                  )[service.status]
                }
              </span>
            </div>
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Zuletzt geprüft:{" "}
              {service.lastCheck
                ? new Date(service.lastCheck).toLocaleString("de-CH")
                : "nicht bestätigt"}
            </p>
            {typeof service.responseTime === "number" && (
              <p className="text-sm">
                Antwortzeit dieser Prüfung: {service.responseTime} ms
              </p>
            )}
          </article>
        ))}
      </div>
      <section className="od-panel space-y-3">
        <h2 className="font-semibold">Probleme bearbeiten</h2>
        <p className="text-sm">
          Diese Ansicht zeigt aktuelle Dienstprüfungen. Historische
          Verfügbarkeit, Fehlerquoten und Vorfälle werden ohne entsprechende
          Messdaten nicht berechnet.
        </p>
        <div className="flex flex-wrap gap-3">
          <a className="fluent-btn-secondary" href="/integrations">
            Integrationen
          </a>
          <a className="fluent-btn-secondary" href="/alerting">
            Monitoring-Meldungen
          </a>
          <a className="fluent-btn-secondary" href="/monitoring">
            Messwerte öffnen
          </a>
        </div>
      </section>
    </div>
  );
}
