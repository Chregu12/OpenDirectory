"use client";
import { useCallback, useEffect, useState } from "react";
import { Cog6ToothIcon, ArrowPathIcon } from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { ensureSession } from "@/lib/auth";
import { PageHeader } from "@/components/ui/PageHeader";
import ServiceHealthView from "./ServiceHealthView";
type Module = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
};
export default function SettingsView({
  onModuleChange,
}: {
  enabledModules?: string[];
  onModuleChange?: (moduleId: string, enabled: boolean) => void;
}) {
  const [tab, setTab] = useState("modules");
  const [modules, setModules] = useState<Module[] | null>(null);
  const [admin, setAdmin] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [response, session] = await Promise.all([
        api.get("/api/config/modules"),
        ensureSession(),
      ]);
      const data = response.data;
      if (!data || typeof data !== "object" || Array.isArray(data))
        throw new Error("Invalid configuration");
      const rows = Object.entries(data).map(([id, value]: [string, any]) => {
        if (
          typeof value.enabled !== "boolean" ||
          typeof value.name !== "string"
        )
          throw new Error("Invalid module");
        return { id, ...value };
      });
      setModules(rows);
      setAdmin(session.user.roles.includes("admin"));
    } catch {
      setModules(null);
      setAdmin(false);
      setError(
        "Einstellungen konnten nicht bestätigt werden. Bitte erneut laden.",
      );
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Einstellungen"
        subtitle="Gespeicherte Plattformkonfiguration und zugehörige Verwaltungsbereiche"
        icon={Cog6ToothIcon}
        actions={
          <button
            className="fluent-btn-secondary"
            disabled={loading || busy}
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
      {notice && <p role="status">{notice}</p>}
      <div className="od-tabs-panel">
        <nav className="od-tabs" aria-label="Einstellungsbereiche">
          {[
            ["modules", "Module"],
            ["services", "Dienste"],
            ["setup", "Einrichtung"],
          ].map(([id, label]) => (
            <button
              key={id}
              aria-pressed={tab === id}
              onClick={() => setTab(id)}
            >
              {label}
            </button>
          ))}
        </nav>
        <div className="p-5 space-y-5">
          {loading && <p role="status">Konfiguration wird geladen …</p>}
          {tab === "modules" && (
            <>
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                Die Auswahl wird in PostgreSQL gespeichert und gilt für die
                Plattformnavigation. Das Aktivieren eines Eintrags installiert
                keinen Dienst, gibt keine Rechte und richtet keine
                Geräteverwaltung ein.
              </p>
              {!admin && !loading && !error && (
                <p>
                  Nur die Plattformadministration kann die Modulkonfiguration
                  ändern.
                </p>
              )}
              <div className="grid gap-4 md:grid-cols-2">
                {modules?.map((module) => (
                  <article className="od-panel space-y-3" key={module.id}>
                    <div className="flex flex-wrap justify-between gap-3">
                      <h2 className="font-semibold">{module.name}</h2>
                      <span className="od-badge">
                        {module.enabled
                          ? "Konfiguriert aktiv"
                          : "Konfiguriert inaktiv"}
                      </span>
                    </div>
                    <p
                      className="text-sm"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {module.description}
                    </p>
                    {admin && (
                      <button
                        className="fluent-btn-secondary"
                        disabled={busy || !!error}
                        aria-label={`Modul ${module.name} ${module.enabled ? "ausblenden" : "einblenden"}`}
                        onClick={async () => {
                          setBusy(true);
                          setNotice("");
                          try {
                            const response = await api.post(
                              "/api/config/modules/" +
                                encodeURIComponent(module.id),
                              { enabled: !module.enabled },
                            );
                            if (
                              response.status !== 200 ||
                              response.data.enabled !== !module.enabled
                            )
                              throw new Error("Unconfirmed configuration");
                            setModules(
                              (current) =>
                                current?.map((row) =>
                                  row.id === module.id
                                    ? { ...row, enabled: !module.enabled }
                                    : row,
                                ) || null,
                            );
                            onModuleChange?.(module.id, !module.enabled);
                            setNotice(
                              "Modulkonfiguration gespeichert. Bestehende Daten und Zugriffsrechte werden dadurch nicht geändert.",
                            );
                          } catch {
                            setError(
                              "Änderung nicht bestätigt. Bitte Konfiguration neu laden; keine automatische Wiederholung.",
                            );
                          } finally {
                            setBusy(false);
                          }
                        }}
                      >
                        {module.enabled
                          ? "In Navigation ausblenden"
                          : "In Navigation einblenden"}
                      </button>
                    )}
                  </article>
                ))}
              </div>
            </>
          )}
          {tab === "services" && <ServiceHealthView />}
          {tab === "setup" && (
            <div className="grid gap-4 md:grid-cols-2">
              {[
                [
                  "Firma und Organisationsstruktur",
                  "Firmenprofil, Organisationseinheiten und ausdrückliche Delegationen.",
                  "/organization",
                ],
                [
                  "Zentrale Anmeldung",
                  "OIDC-Metadaten, registrierte Anwendungen und externe Anbieter.",
                  "/identity",
                ],
                [
                  "Geräteanbindung",
                  "Inventar und tatsächliche Enrollment-Voraussetzungen.",
                  "/enrollment",
                ],
                [
                  "Integrationen",
                  "Dienste, OAuth-Anwendungen und Webhooks.",
                  "/integrations",
                ],
              ].map(([title, description, href]) => (
                <section className="od-panel space-y-3" key={href}>
                  <h2 className="font-semibold">{title}</h2>
                  <p className="text-sm">{description}</p>
                  <a className="fluent-btn-secondary" href={href}>
                    Verwaltung öffnen
                  </a>
                </section>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
