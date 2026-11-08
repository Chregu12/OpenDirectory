"use client";
import { useCallback, useEffect, useState } from "react";
import {
  ClipboardDocumentListIcon,
  ArrowPathIcon,
  DocumentArrowDownIcon,
} from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
type Event = {
  id: string | number;
  event_type: string;
  user_id?: string;
  ip_address?: string;
  created_at: string;
  details?: Record<string, unknown>;
};
export default function AuditView({
  title = "Audit Log",
}: { title?: string } = {}) {
  const [events, setEvents] = useState<Event[] | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Event | null>(null);
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = (
        await api.get("/api/auth/audit/security-events", {
          params: { limit: 100 },
        })
      ).data;
      if (
        !Array.isArray(data?.events) ||
        new Set(data.events.map((row: Event) => String(row?.id))).size !== data.events.length ||
        data.events.some(
          (row: Event) =>
            !row || !["number", "string"].includes(typeof row.id) ||
            (typeof row.id === "string" && !row.id.trim()) ||
            typeof row.event_type !== "string" ||
            !Number.isFinite(Date.parse(row.created_at)),
        )
      )
        throw new Error("Invalid audit");
      setEvents(data.events);
      setSelected((current) =>
        current
          ? data.events.find((row: Event) => row.id === current.id) || null
          : null,
      );
    } catch (failure: any) {
      setEvents(null);
      setSelected(null);
      setError(
        failure?.response?.status === 403
          ? "Keine Berechtigung für das globale Authentifizierungsprotokoll. Eigene Anmeldungen stehen in der Passwort-Selbsthilfe."
          : "Das Authentifizierungsprotokoll konnte nicht geladen werden. Es werden keine Beispielereignisse angezeigt.",
      );
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  const filtered = events?.filter((row) =>
    [
      row.event_type,
      row.user_id,
      row.ip_address,
      JSON.stringify(row.details || {}),
    ]
      .join(" ")
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  const exportCsv = () => {
    if (!filtered) return;
    const rows = [
      ["Zeit", "Ereignis", "Person-ID", "IP-Adresse"],
      ...filtered.map((row) => [
        row.created_at,
        row.event_type,
        row.user_id || "",
        row.ip_address || "",
      ]),
    ];
    const csv = rows
      .map((row) =>
        row
          .map(
            (value) =>
              '"' +
              (/^[=+@\-\t\r\n]/.test(value) ? "'" : "") +
              value.replaceAll('"', '""') +
              '"',
          )
          .join(","),
      )
      .join("\r\n");
    const url = URL.createObjectURL(
      new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "opendirectory-auth-audit.csv";
    link.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="space-y-6">
      <PageHeader
        title={title}
        subtitle="Bestätigte Ereignisse des Authentifizierungsdienstes · letzte maximal 100 Einträge"
        icon={ClipboardDocumentListIcon}
        actions={
          <>
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
            <button
              className="fluent-btn-secondary"
              disabled={!filtered?.length}
              onClick={exportCsv}
            >
              <DocumentArrowDownIcon className="h-4 w-4" />
              CSV exportieren
            </button>
          </>
        }
      />
      {error && <p role="alert">{error}</p>}
      {loading && <p role="status">Protokoll wird geladen …</p>}
      <div className="od-panel space-y-3">
        <label className="block max-w-lg">
          Geladene Ereignisse durchsuchen
          <input
            className="input-apple mt-2"
            maxLength={200}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Quelle: Authentication-Service. Ein leerer Ausschnitt ist kein Beleg
          für fehlerfreien Betrieb. Eine dienstübergreifende Integritätskette
          wird hier nicht bestätigt.
        </p>
      </div>
      {events?.length === 0 && (
        <p>Keine Ereignisse im bestätigten Ausschnitt.</p>
      )}
      {!!events?.length && filtered?.length === 0 && (
        <p>Keine Treffer in den geladenen Ereignissen.</p>
      )}
      {!!filtered?.length && (
        <div className="od-tabs-panel od-table-scroll">
          <table className="fluent-table">
            <caption className="sr-only">Authentifizierungsereignisse</caption>
            <thead>
              <tr>
                {["Zeit", "Ereignis", "Person-ID", "IP-Adresse", "Details"].map(
                  (value) => (
                    <th scope="col" key={value}>
                      {value}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={row.id}>
                  <td>{new Date(row.created_at).toLocaleString("de-CH")}</td>
                  <td>{row.event_type}</td>
                  <td className="break-all">
                    {row.user_id || "nicht zugeordnet"}
                  </td>
                  <td>{row.ip_address || "—"}</td>
                  <td>
                    <button
                      className="fluent-btn-secondary"
                      onClick={() => setSelected(row)}
                    >
                      Ereignis öffnen
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {selected && (
        <section className="od-panel space-y-4" aria-label="Ereignisdetails">
          <div className="flex justify-between gap-3">
            <h2 className="font-semibold">{selected.event_type}</h2>
            <button
              className="fluent-btn-secondary"
              onClick={() => setSelected(null)}
            >
              Details schliessen
            </button>
          </div>
          <p>
            {new Date(selected.created_at).toLocaleString("de-CH")} · ID{" "}
            {selected.id}
          </p>
          <pre className="text-sm whitespace-pre-wrap break-all">
            {JSON.stringify(selected.details || {}, null, 2)}
          </pre>
        </section>
      )}
      <a className="fluent-btn-secondary" href="/sspr">
        Eigene Anmeldehistorie
      </a>
    </div>
  );
}
