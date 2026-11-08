"use client";
import { useCallback, useEffect, useState } from "react";
import { Squares2X2Icon, ArrowPathIcon } from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
type Module = {
  id: string;
  name?: string;
  description?: string;
  enabled: boolean;
};
export default function SubscriptionView() {
  const [modules, setModules] = useState<Module[] | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = (await api.get("/api/config/modules")).data;
      if (!data || typeof data !== "object" || Array.isArray(data))
        throw new Error("Invalid modules");
      const rows = Object.entries(data).map(([id, value]: [string, any]) => {
        if (typeof value?.enabled !== "boolean")
          throw new Error("Invalid module");
        return { id, ...value };
      });
      setModules(rows);
    } catch {
      setModules(null);
      setError(
        "Modulkonfiguration konnte nicht geladen werden. Es werden keine erfundenen Abonnementdaten angezeigt.",
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
        title="Abonnement & Module"
        subtitle="Gespeicherte Modulkonfiguration dieser selbst gehosteten Installation"
        icon={Squares2X2Icon}
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
      <section className="od-panel space-y-3">
        <h2 className="font-semibold">Betriebsumfang</h2>
        <p>
          Für diese Installation ist kein Abrechnungsanbieter angebunden. Ein
          kostenpflichtiger Plan, gekaufte Benutzerplätze und ein
          Verlängerungsdatum sind nicht bestätigt. Aktivierte Module beschreiben
          die Konfiguration und keine gekauften Rechte.
        </p>
        <a className="fluent-btn-secondary" href="/licenses">
          Eigene Software-Lizenzpools
        </a>
      </section>
      {error && <p role="alert">{error}</p>}
      {loading && <p role="status">Module werden geladen …</p>}
      <section className="od-tabs-panel p-5 space-y-4">
        <label className="block max-w-lg">
          Module suchen
          <input
            className="input-apple mt-2"
            value={search}
            maxLength={200}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
        {modules?.length === 0 && (
          <p>Keine Module in der bestätigten Konfiguration.</p>
        )}
        <div className="grid gap-4 md:grid-cols-2">
          {modules
            ?.filter((module) =>
              (module.name || module.id)
                .toLowerCase()
                .includes(search.toLowerCase()),
            )
            .map((module) => (
              <article className="od-panel space-y-2" key={module.id}>
                <div className="flex justify-between gap-3">
                  <h2 className="font-semibold">{module.name || module.id}</h2>
                  <span className="od-badge">
                    {module.enabled
                      ? "Konfiguriert aktiv"
                      : "Konfiguriert inaktiv"}
                  </span>
                </div>
                {module.description && (
                  <p className="text-sm">{module.description}</p>
                )}
              </article>
            ))}
        </div>
        <a className="fluent-btn-secondary" href="/settings">
          Modulkonfiguration verwalten
        </a>
      </section>
    </div>
  );
}
