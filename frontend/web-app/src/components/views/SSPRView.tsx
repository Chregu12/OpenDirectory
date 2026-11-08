"use client";
import { useCallback, useEffect, useState } from "react";
import {
  ArrowPathIcon,
  EnvelopeIcon,
  KeyIcon,
  ShieldCheckIcon,
  ClockIcon,
} from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";

type Event = {
  id: string;
  event_type: string;
  message?: string;
  created_at: string;
  ip_address?: string;
};
export default function SSPRView() {
  const [tab, setTab] = useState("reset");
  const [email, setEmail] = useState("");
  const [events, setEvents] = useState<Event[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const result = await api.get("/api/auth/audit/login-history?limit=25");
      if (!Array.isArray(result.data.history))
        throw new Error("Invalid history");
      setEvents(result.data.history);
    } catch {
      setEvents(null);
      setError("Die eigene Anmeldehistorie konnte nicht geladen werden.");
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
        title="Self-Service Passwort-Reset"
        subtitle="Eigenen Zugang wiederherstellen und Anmeldungen prüfen"
        icon={KeyIcon}
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
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="od-panel flex items-center gap-3">
          <span
            className="p-3 rounded-xl"
            style={{
              background: "var(--accent-light)",
              color: "var(--accent)",
            }}
          >
            <EnvelopeIcon className="h-5 w-5" />
          </span>
          <div>
            <p className="font-medium">Passwort zurücksetzen</p>
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Link anfordern und sicher bestätigen
            </p>
          </div>
        </div>
        <div className="od-panel flex items-center gap-3">
          <span
            className="p-3 rounded-xl"
            style={{
              background: "var(--success-light)",
              color: "var(--success)",
            }}
          >
            <ShieldCheckIcon className="h-5 w-5" />
          </span>
          <div>
            <p className="font-medium">MFA & Wiederherstellung</p>
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Authenticator und Notfallcodes
            </p>
          </div>
        </div>
        <div className="od-panel flex items-center gap-3">
          <span
            className="p-3 rounded-xl"
            style={{
              background: "var(--warning-light)",
              color: "var(--warning)",
            }}
          >
            <ClockIcon className="h-5 w-5" />
          </span>
          <div>
            <p className="font-medium">Eigene Anmeldeereignisse</p>
            <p className="text-lg font-semibold">{events?.length ?? "—"}</p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Letzte maximal 25 Einträge
            </p>
          </div>
        </div>
      </div>
      <div className="od-tabs-panel">
        <nav className="od-tabs" aria-label="Passwort-Selbsthilfe">
          {[
            ["reset", "Passwort zurücksetzen"],
            ["history", "Anmeldehistorie"],
            ["recovery", "Wiederherstellung"],
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
        {tab === "reset" && (
          <form
            className="p-5 space-y-5 max-w-2xl"
            onSubmit={async (event) => {
              event.preventDefault();
              if (busy) return;
              setBusy(true);
              setNotice("");
              try {
                const response = await api.post("/api/auth/reset-password", {
                  email: email.trim(),
                });
                if (response.status !== 200 || response.data.success !== true)
                  throw new Error("Unconfirmed");
                setNotice(
                  "Anfrage angenommen. Wenn ein passendes Konto besteht und der E-Mail-Versand eingerichtet ist, erhältst du einen Rücksetzlink. Die Annahme bestätigt keine Zustellung.",
                );
              } catch {
                setNotice(
                  "Die Rücksetzanfrage konnte nicht bestätigt werden. Bitte später erneut versuchen.",
                );
              } finally {
                setBusy(false);
              }
            }}
          >
            <div>
              <h2 className="font-semibold">Rücksetzlink anfordern</h2>
              <p
                className="mt-2 text-sm"
                style={{ color: "var(--text-secondary)" }}
              >
                Gib die E-Mail-Adresse deines Kontos an. Das neue Passwort wird
                erst nach Prüfung des persönlichen Links gespeichert.
              </p>
            </div>
            <label className="block">
              E-Mail-Adresse
              <input
                className="input-apple mt-2"
                type="email"
                autoComplete="email"
                required
                maxLength={255}
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                disabled={busy}
              />
            </label>
            {notice && <p role="status">{notice}</p>}
            <button
              className="fluent-btn-primary"
              type="submit"
              disabled={busy}
            >
              {busy ? "Wird angefordert …" : "Rücksetzlink anfordern"}
            </button>
          </form>
        )}
        {tab === "history" && (
          <div className="p-5 space-y-4">
            {error && (
              <p role="alert">
                {error}{" "}
                <button className="underline" onClick={() => void load()}>
                  Erneut prüfen
                </button>
              </p>
            )}
            {loading && <p role="status">Anmeldehistorie wird geladen …</p>}
            {events?.length === 0 && (
              <p>Keine eigenen Anmeldeereignisse im geladenen Ausschnitt.</p>
            )}
            {!!events?.length && (
              <div className="od-table-scroll">
                <table className="fluent-table">
                  <caption className="sr-only">Eigene Anmeldehistorie</caption>
                  <thead>
                    <tr>
                      <th scope="col">Zeit</th>
                      <th scope="col">Ereignis</th>
                      <th scope="col">Beschreibung</th>
                      <th scope="col">IP-Adresse</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((event) => (
                      <tr key={event.id}>
                        <td>
                          {new Date(event.created_at).toLocaleString("de-CH")}
                        </td>
                        <td>{event.event_type}</td>
                        <td>{event.message || "—"}</td>
                        <td>{event.ip_address || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
        {tab === "recovery" && (
          <div className="p-5 space-y-6">
            <section>
              <h2 className="font-semibold">Authenticator und Notfallcodes</h2>
              <p
                className="text-sm mt-2"
                style={{ color: "var(--text-secondary)" }}
              >
                Nutze den passenden bestehenden Wiederherstellungsablauf. Ein
                Notfallcode ersetzt keinen Passwort-Reset.
              </p>
              <div className="flex flex-wrap gap-3 mt-4">
                <a href="/mfa" className="fluent-btn-primary">
                  MFA verwalten
                </a>
                <a href="/auth/mfa-recovery" className="fluent-btn-secondary">
                  Mit Notfallcode wiederherstellen
                </a>
                <a href="/auth/mfa-enroll" className="fluent-btn-secondary">
                  Authenticator erstmals einrichten
                </a>
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
