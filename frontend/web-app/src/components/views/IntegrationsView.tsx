"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { Dialog } from "@headlessui/react";
import {
  ArrowPathIcon,
  GlobeAltIcon,
  PlusIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import AppRegistrationsView from "./AppRegistrationsView";

type Hook = {
  id: string;
  name: string;
  url: string;
  events: string[];
  active: boolean;
  last_triggered?: string;
};
type Service = { id: string; name: string; status: string; lastCheck?: string };
type Key = { id: string; name: string; active: boolean };
type Delivery = {
  id: string;
  event_type?: string;
  eventType?: string;
  success: boolean;
  response_status?: number;
  responseStatus?: number;
  delivered_at?: string;
  deliveredAt?: string;
};
const EVENTS = [
  "user.created",
  "user.updated",
  "user.deleted",
  "device.enrolled",
  "device.compliance_failed",
  "group.created",
  "auth.login_failed",
  "auth.mfa_disabled",
];
const date = (value?: string) =>
  value ? new Date(value).toLocaleString("de-CH") : "—";
function origin(value: string) {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}
function HookEditor({
  hook,
  onClose,
  onSaved,
}: {
  hook?: Hook;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(hook?.name || "");
  const [url, setUrl] = useState(hook?.url || "");
  const [active, setActive] = useState(hook?.active ?? true);
  const [events, setEvents] = useState(hook?.events || []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [unconfirmed, setUnconfirmed] = useState(false);
  return (
    <Dialog
      open
      onClose={() => {
        if (!busy) onClose();
      }}
      className="od-modal-frame"
    >
      <Dialog.Panel
        as="form"
        className="od-modal-panel max-w-xl space-y-5"
        onSubmit={async (event) => {
          event.preventDefault();
          if (busy || unconfirmed) return;
          setBusy(true);
          setError("");
          try {
            const target = new URL(url);
            if (
              target.protocol !== "https:" ||
              target.username ||
              target.password ||
              target.hash
            ) {
              setError(
                "Eine HTTPS-Adresse ohne Zugangsdaten oder Fragment angeben.",
              );
              return;
            }
            const fields = {
              name: name.trim(),
              url: target.href,
              events,
              ...(hook ? { active } : {}),
            };
            const response = hook
              ? await api.put("/api/gateway/webhooks/" + hook.id, fields)
              : await api.post("/api/gateway/webhooks", fields);
            if (
              response.status !== (hook ? 200 : 201) ||
              !response.data?.id ||
              (hook && response.data.id !== hook.id)
            )
              throw new Error("Unconfirmed");
            onSaved();
            onClose();
          } catch (failure: any) {
            setError(
              "Speicherung nicht bestätigt. Eingaben bleiben erhalten; vor einer Wiederholung die registrierten Webhooks prüfen.",
            );
            setUnconfirmed(![400, 422].includes(failure?.response?.status));
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="flex justify-between gap-3">
          <Dialog.Title className="text-lg font-semibold">
            {hook ? "Webhook bearbeiten" : "Webhook hinzufügen"}
          </Dialog.Title>
          <button
            type="button"
            disabled={busy}
            aria-label="Webhook-Editor schliessen"
            onClick={onClose}
          >
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          Registriert die lokale Verbindung. Automatische signierte
          Ereigniszustellung ist in diesem Gateway noch nicht integriert.
          Manuelle Tests benötigen eine serverseitig freigegebene Zieladresse.
        </p>
        <label className="block">
          Name
          <input
            className="input-apple mt-2"
            required
            maxLength={160}
            value={name}
            onChange={(event) => setName(event.target.value)}
            disabled={busy || unconfirmed}
          />
        </label>
        <label className="block">
          Payload-URL
          <input
            className="input-apple mt-2"
            required
            type="url"
            pattern="https://.*"
            maxLength={2000}
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            disabled={busy || unconfirmed}
          />
        </label>
        <fieldset>
          <legend className="font-medium mb-3">Vorgesehene Ereignisse</legend>
          <div className="grid gap-3 sm:grid-cols-2">
            {EVENTS.map((value) => (
              <label className="flex gap-2 items-center text-sm" key={value}>
                <input
                  type="checkbox"
                  disabled={busy || unconfirmed}
                  checked={events.includes(value)}
                  onChange={(event) =>
                    setEvents((current) =>
                      event.target.checked
                        ? [...current, value]
                        : current.filter((item) => item !== value),
                    )
                  }
                />
                {value}
              </label>
            ))}
          </div>
        </fieldset>
        {hook && (
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={active}
              disabled={busy || unconfirmed}
              onChange={(event) => setActive(event.target.checked)}
            />
            Verbindung aktiviert
          </label>
        )}
        {error && <p role="alert">{error}</p>}
        <div className="flex gap-3 justify-end">
          <button
            type="button"
            className="fluent-btn-secondary"
            disabled={busy}
            onClick={onClose}
          >
            Abbrechen
          </button>
          <button
            className="fluent-btn-primary"
            type="submit"
            disabled={busy || unconfirmed}
          >
            {busy ? "Wird gespeichert …" : "Speichern"}
          </button>
        </div>
      </Dialog.Panel>
    </Dialog>
  );
}
function Deliveries({ hook, onClose }: { hook: Hook; onClose: () => void }) {
  const [rows, setRows] = useState<Delivery[] | null>(null);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true;
    setError("");
    setRows(null);
    api
      .get("/api/gateway/webhooks/" + hook.id + "/deliveries")
      .then((response) => {
        if (!Array.isArray(response.data))
          throw new Error("Invalid delivery log");
        if (active) setRows(response.data);
      })
      .catch(() => {
        if (active)
          setError("Zustellungsprotokoll konnte nicht geladen werden.");
      });
    return () => {
      active = false;
    };
  }, [hook.id, revision]);
  return (
    <Dialog open onClose={onClose} className="od-modal-frame">
      <Dialog.Panel className="od-modal-panel max-w-3xl space-y-5">
        <Dialog.Title className="text-lg font-semibold">
          Zustellungsprotokoll · {hook.name}
        </Dialog.Title>
        {error && <p role="alert">{error}</p>}
        {!rows && !error && <p role="status">Protokoll wird geladen …</p>}
        {rows?.length === 0 && (
          <p>Keine bestätigten Zustellungsversuche vorhanden.</p>
        )}
        {!!rows?.length && (
          <div className="od-table-scroll">
            <table className="fluent-table">
              <thead>
                <tr>
                  {["Zeitpunkt", "Ereignis", "Ergebnis", "HTTP"].map(
                    (value) => (
                      <th scope="col" key={value}>
                        {value}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td>{date(row.delivered_at || row.deliveredAt)}</td>
                    <td>{row.event_type || row.eventType}</td>
                    <td>{row.success ? "Zugestellt" : "Fehlgeschlagen"}</td>
                    <td>{row.response_status ?? row.responseStatus ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex justify-end gap-3">
          <button
            className="fluent-btn-secondary"
            onClick={() => setRevision((value) => value + 1)}
          >
            Protokoll neu laden
          </button>
          <button className="fluent-btn-secondary" onClick={onClose}>
            Schliessen
          </button>
        </div>
      </Dialog.Panel>
    </Dialog>
  );
}
export default function IntegrationsView() {
  const [tab, setTab] = useState("connections");
  const [permissions, setPermissions] = useState<string[]>([]);
  const [origins, setOrigins] = useState<string[]>([]);
  const [services, setServices] = useState<Service[] | null>(null);
  const [hooks, setHooks] = useState<Hook[] | null>(null);
  const [keys, setKeys] = useState<Key[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [editor, setEditor] = useState<Hook | "new" | null>(null);
  const [log, setLog] = useState<Hook | null>(null);
  const [removing, setRemoving] = useState<Hook | Key | null>(null);
  const [removalError, setRemovalError] = useState("");
  const generation = useRef(0);
  const can = (permission: string) => permissions.includes(permission);
  const load = useCallback(async () => {
    const epoch = ++generation.current;
    setLoading(true);
    setErrors({});
    try {
      const access = (await api.get("/api/gateway/access")).data;
      if (!Array.isArray(access?.permissions) || !access?.subject)
        throw new Error("Invalid access");
      const rights: string[] = access.permissions;
      if (epoch !== generation.current) return;
      setPermissions(rights);
      setOrigins(
        Array.isArray(access.webhooks?.allowedOrigins)
          ? access.webhooks.allowedOrigins.filter(
              (value: unknown) => typeof value === "string",
            )
          : [],
      );
      if (!rights.includes("gateway.webhooks.manage")) setEditor(null);
      const jobs = [
        ["connections", "gateway.status.read", "/api/services", setServices],
        [
          "webhooks",
          "gateway.webhooks.read",
          "/api/gateway/webhooks",
          setHooks,
        ],
        ["apikeys", "gateway.keys.read", "/api/gateway/api-keys", setKeys],
      ] as const;
      await Promise.all(
        jobs.map(async ([area, permission, path, setter]) => {
          if (!rights.includes(permission)) {
            setter(null);
            return;
          }
          try {
            const response = await api.get(path);
            if (!Array.isArray(response.data)) throw new Error("Invalid data");
            if (epoch === generation.current) setter(response.data);
          } catch {
            if (epoch === generation.current) {
              setter(null);
              setErrors((current) => ({
                ...current,
                [area]:
                  "Integrationsdaten konnten nicht bestätigt werden; kein lokaler Ersatz wird angezeigt.",
              }));
            }
          }
        }),
      );
    } catch {
      if (epoch === generation.current) {
        setPermissions([]);
        setOrigins([]);
        setServices(null);
        setHooks(null);
        setKeys(null);
        setEditor(null);
        setLog(null);
        setRemoving(null);
        setErrors({
          access: "Gateway-Anmeldung oder Berechtigungen sind nicht verfügbar.",
        });
      }
    } finally {
      if (epoch === generation.current) setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
    return () => {
      generation.current++;
    };
  }, [load]);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Integrationen"
        subtitle="Verbundene Dienste, OAuth-Anwendungen und Webhooks"
        icon={GlobeAltIcon}
        actions={
          <>
            <button
              className="fluent-btn-secondary"
              disabled={loading || busy || !!editor || !!removing}
              onClick={() => void load()}
            >
              <ArrowPathIcon
                className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
              />
              Aktualisieren
            </button>
            {tab === "webhooks" && can("gateway.webhooks.manage") && (
              <button
                className="fluent-btn-primary"
                disabled={loading || busy}
                onClick={() => setEditor("new")}
              >
                <PlusIcon className="h-4 w-4" />
                Webhook hinzufügen
              </button>
            )}
          </>
        }
      />
      {errors.access && <p role="alert">{errors.access}</p>}
      {notice && <p role="status">{notice}</p>}
      <div className="od-tabs-panel">
        <nav className="od-tabs" aria-label="Integrationsbereiche">
          {[
            ["connections", "Verbindungen"],
            ["oauth", "OAuth-Apps"],
            ["webhooks", "Webhooks"],
            ["apikeys", "Alte API-Schlüssel"],
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
          {loading && <p role="status">Verbindungen werden geprüft …</p>}
          {errors[tab] && <p role="alert">{errors[tab]}</p>}
          {tab === "connections" && (
            <>
              <section
                aria-label="Verbundene Dienste"
                className="grid gap-4 md:grid-cols-2 xl:grid-cols-3"
              >
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
                        {(
                          {
                            healthy: "Verbunden",
                            disabled: "Nicht eingerichtet",
                            unhealthy: "Gestört",
                            unknown: "Nicht bestätigt",
                            degraded: "Eingeschränkt",
                          } as Record<string, string>
                        )[service.status] || "Nicht bestätigt"}
                      </span>
                    </div>
                    <p
                      className="text-sm"
                      style={{ color: "var(--text-muted)" }}
                    >
                      Zuletzt geprüft: {date(service.lastCheck)}
                    </p>
                    <button
                      className="fluent-btn-secondary"
                      disabled={loading}
                      onClick={() => void load()}
                    >
                      Verbindung prüfen
                    </button>
                  </article>
                ))}
              </section>
              {!loading && !can("gateway.status.read") && !errors.access && (
                <p>Keine Freigabe zum Lesen der globalen Dienstverbindungen.</p>
              )}
              {services?.length === 0 && (
                <p>Keine Dienstverbindungen in der bestätigten Antwort.</p>
              )}
              <section className="od-panel space-y-3">
                <h2 className="font-semibold">Anwendung anbinden</h2>
                <p>
                  Registriere eine OAuth-Anwendung und erteile die benötigten
                  Rechte. Eigene Firmen-App-Konten besitzen einen eigenen
                  Geltungsbereich.
                </p>
                <div className="flex flex-wrap gap-3">
                  <button
                    className="fluent-btn-primary"
                    onClick={() => setTab("oauth")}
                  >
                    OAuth-Anwendungen öffnen
                  </button>
                  <a className="fluent-btn-secondary" href="/company-apps">
                    Eigene Firmen-App-Konten
                  </a>
                </div>
              </section>
            </>
          )}
          {tab === "oauth" && <AppRegistrationsView />}
          {tab === "webhooks" && (
            <>
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                Webhooks registrieren lokale Metadaten. Produktive signierte
                Ereigniszustellung ist noch nicht implementiert. Ein manueller
                Test prüft die Erreichbarkeit des freigegebenen Ziels.
              </p>
              {can("gateway.webhooks.manage") && (
                <p className="text-sm">
                  {origins.length
                    ? "Für Tests freigegebene Ziele: " + origins.join(", ")
                    : "Keine Testziele serverseitig freigegeben. Die Ziel-Origin muss in GATEWAY_WEBHOOK_ALLOWED_ORIGINS konfiguriert werden."}
                </p>
              )}
              {!loading && !can("gateway.webhooks.read") && !errors.access && (
                <p>Keine Freigabe zum Lesen der Webhooks.</p>
              )}
              {hooks?.length === 0 && <p>Keine Webhooks konfiguriert.</p>}
              <div className="space-y-4">
                {hooks?.map((hook) => (
                  <article key={hook.id} className="od-panel space-y-3">
                    <div className="flex flex-wrap justify-between gap-3">
                      <div>
                        <h2 className="font-semibold">{hook.name}</h2>
                        <p
                          className="text-sm break-all"
                          style={{ color: "var(--text-muted)" }}
                        >
                          {hook.url}
                        </p>
                      </div>
                      <span className="od-badge">
                        {hook.active ? "Aktiv registriert" : "Inaktiv"}
                      </span>
                    </div>
                    <p className="text-sm">
                      Ereignisauswahl: {hook.events?.join(", ") || "Keine"} ·
                      Letzter Test: {date(hook.last_triggered)}
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <button
                        className="fluent-btn-secondary"
                        onClick={() => setLog(hook)}
                      >
                        Protokoll öffnen
                      </button>
                      <button
                        className="fluent-btn-secondary"
                        disabled={
                          !can("gateway.webhooks.manage") ||
                          busy ||
                          !hook.active ||
                          !origins.includes(origin(hook.url))
                        }
                        onClick={async () => {
                          setBusy(true);
                          setNotice("");
                          try {
                            const response = await api.post(
                              "/api/gateway/webhooks/" + hook.id + "/test",
                            );
                            if (
                              response.status !== 200 ||
                              typeof response.data?.success !== "boolean"
                            )
                              throw new Error("Unconfirmed");
                            setNotice(
                              response.data.success
                                ? `Test zugestellt (HTTP ${response.data.responseStatus}).`
                                : `Test fehlgeschlagen (HTTP ${response.data.responseStatus || "keine Antwort"}).`,
                            );
                            void load();
                          } catch {
                            setNotice(
                              "Test nicht bestätigt. Vor einer Wiederholung das Zustellungsprotokoll prüfen.",
                            );
                          } finally {
                            setBusy(false);
                          }
                        }}
                      >
                        Test senden
                      </button>
                      {can("gateway.webhooks.manage") && (
                        <>
                          <button
                            className="fluent-btn-secondary"
                            disabled={busy}
                            onClick={() => setEditor(hook)}
                          >
                            Bearbeiten
                          </button>
                          <button
                            className="fluent-btn-secondary"
                            disabled={busy}
                            onClick={() => {
                              setRemovalError("");
                              setRemoving(hook);
                            }}
                          >
                            Webhook entfernen
                          </button>
                        </>
                      )}
                    </div>
                  </article>
                ))}
              </div>
            </>
          )}
          {tab === "apikeys" && (
            <>
              <p>
                Gateway-API-Schlüssel sind stillgelegt. Für neue Integrationen
                autorisierte OAuth-App-Zugangsdaten verwenden.
              </p>
              {!loading && !can("gateway.keys.read") && !errors.access && (
                <p>Keine Lesefreigabe für alte Schlüssel.</p>
              )}
              {keys?.length === 0 && <p>Keine alten Schlüssel registriert.</p>}
              {keys?.map((key) => (
                <article
                  className="od-panel flex flex-wrap justify-between gap-3"
                  key={key.id}
                >
                  <div>
                    <h2 className="font-semibold">{key.name}</h2>
                    <p>Stillgelegt</p>
                  </div>
                  {can("gateway.keys.manage") && key.active && (
                    <button
                      className="fluent-btn-secondary"
                      disabled={busy}
                      onClick={() => {
                        setRemovalError("");
                        setRemoving(key);
                      }}
                    >
                      Alten Schlüssel widerrufen
                    </button>
                  )}
                </article>
              ))}
            </>
          )}
        </div>
      </div>
      {editor && can("gateway.webhooks.manage") && (
        <HookEditor
          hook={editor === "new" ? undefined : editor}
          onClose={() => setEditor(null)}
          onSaved={() => {
            setNotice("Webhook-Metadaten lokal gespeichert.");
            void load();
          }}
        />
      )}
      {log && can("gateway.webhooks.read") && (
        <Deliveries hook={log} onClose={() => setLog(null)} />
      )}
      {removing && (
        <Dialog
          open
          onClose={() => {
            if (!busy) setRemoving(null);
          }}
          className="od-modal-frame"
        >
          <Dialog.Panel className="od-modal-panel max-w-lg space-y-5">
            <Dialog.Title className="text-lg font-semibold">
              {"url" in removing
                ? "Webhook entfernen"
                : "Alten Schlüssel widerrufen"}
            </Dialog.Title>
            <p>
              {removing.name} ·{" "}
              {"url" in removing
                ? removing.url
                : "Die bestehende Schlüssel-Metadatenfreigabe wird widerrufen."}
            </p>
            {removalError && <p role="alert">{removalError}</p>}
            <div className="flex gap-3 justify-end">
              <button
                className="fluent-btn-secondary"
                disabled={busy}
                onClick={() => setRemoving(null)}
              >
                Abbrechen
              </button>
              <button
                className="fluent-btn-primary"
                disabled={
                  busy ||
                  !!removalError ||
                  !can(
                    "url" in removing
                      ? "gateway.webhooks.manage"
                      : "gateway.keys.manage",
                  )
                }
                onClick={async () => {
                  setBusy(true);
                  try {
                    const hook = "url" in removing;
                    const response = await api.delete(
                      "/api/gateway/" +
                        (hook ? "webhooks/" : "api-keys/") +
                        removing.id,
                    );
                    if (
                      hook
                        ? response.status !== 204
                        : response.status !== 200 ||
                          response.data.id !== removing.id ||
                          response.data.active !== false
                    )
                      throw new Error("Unconfirmed");
                    setNotice(
                      hook
                        ? "Webhook lokal entfernt."
                        : "Alter Schlüssel widerrufen.",
                    );
                    setRemoving(null);
                    void load();
                  } catch {
                    setRemovalError(
                      "Änderung nicht bestätigt. Dialog schliessen und aktuellen Stand neu laden; keine automatische Wiederholung.",
                    );
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy ? "Wird ausgeführt …" : "Bestätigen"}
              </button>
            </div>
          </Dialog.Panel>
        </Dialog>
      )}
    </div>
  );
}
