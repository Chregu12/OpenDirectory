"use client";
import { useEffect, useState } from "react";
import { BeakerIcon } from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
type Preview = {
  effectiveSettings: Record<string, unknown>;
  sources: unknown;
  appliedPoliciesCount: number;
  previewOnly: true;
};
export default function PolicySimulatorView() {
  const [allowed, setAllowed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [kind, setKind] = useState("userId");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Preview | null>(null);
  const [checkedAt, setCheckedAt] = useState("");
  useEffect(() => {
    let active = true;
    api
      .get("/api/policies/access")
      .then((response) => {
        if (!Array.isArray(response.data?.permissions))
          throw new Error("Invalid permissions");
        if (active)
          setAllowed(response.data.permissions.includes("policies.read"));
      })
      .catch(() => {
        if (active)
          setError(
            "Berechtigung für die Richtlinienvorschau konnte nicht bestätigt werden.",
          );
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Richtlinienvorschau"
        subtitle="Lokale effektive Einstellungen für ein ausdrücklich angegebenes Ziel berechnen"
        icon={BeakerIcon}
      />
      <section className="od-panel space-y-4">
        <h2 className="font-semibold">Firmen-Blueprints</h2>
        <p className="text-sm">
          Für eigene Firmenentwürfe und konkrete Zuweisungen steht die
          vorhandene Konfliktvorschau beim Blueprint bereit.
        </p>
        <a href="/company-blueprints" className="fluent-btn-primary">
          Firmen-Blueprints öffnen
        </a>
      </section>
      {loading && <p role="status">Vorschau-Berechtigung wird geprüft …</p>}
      {error && <p role="alert">{error}</p>}
      {!loading && !allowed && !error && (
        <p>Für die technische Plattformvorschau fehlt policies.read.</p>
      )}
      {allowed && (
        <form
          className="od-tabs-panel p-5 space-y-5"
          onSubmit={async (event) => {
            event.preventDefault();
            if (busy) return;
            setBusy(true);
            setError("");
            setResult(null);
            try {
              const response = await api.get("/api/policies/simulate", {
                params: { [kind]: target.trim() },
              });
              const data = response.data;
              if (
                data?.previewOnly !== true ||
                !Number.isSafeInteger(data.appliedPoliciesCount) ||
                data.appliedPoliciesCount < 0 ||
                !data.effectiveSettings ||
                typeof data.effectiveSettings !== "object" ||
                Array.isArray(data.effectiveSettings)
              )
                throw new Error("Invalid preview");
              setResult(data);
              setCheckedAt(new Date().toISOString());
            } catch {
              setError(
                "Die Zielvorschau konnte nicht bestätigt werden. Ziel und Berechtigung prüfen.",
              );
            } finally {
              setBusy(false);
            }
          }}
        >
          <h2 className="font-semibold">Technische Plattformvorschau</h2>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Für eine bekannte kanonische Personen- oder Geräte-ID. Die Vorschau
            ändert keine Richtlinie und bestätigt keine Ausführung auf dem
            Gerät.
          </p>
          <div className="grid gap-4 sm:grid-cols-2">
            <label>
              Zielart
              <select
                className="input-apple mt-2"
                value={kind}
                disabled={busy}
                onChange={(event) => {
                  setKind(event.target.value);
                  setResult(null);
                }}
              >
                <option value="userId">Person</option>
                <option value="deviceId">Gerät</option>
              </select>
            </label>
            <label>
              Kanonische Ziel-ID
              <input
                className="input-apple mt-2"
                required
                maxLength={36}
                pattern="[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}"
                value={target}
                disabled={busy}
                onChange={(event) => {
                  setTarget(event.target.value);
                  setResult(null);
                }}
              />
            </label>
          </div>
          <button className="fluent-btn-primary" disabled={busy}>
            {busy ? "Wird berechnet …" : "Vorschau berechnen"}
          </button>
        </form>
      )}
      {result && (
        <section className="od-panel space-y-4">
          <h2 className="font-semibold">Bestätigte lokale Vorschau</h2>
          <p className="text-sm">
            {result.appliedPoliciesCount} berücksichtigte Richtlinien · Ziel{" "}
            {target} · geprüft {new Date(checkedAt).toLocaleString("de-CH")}
          </p>
          <dl className="space-y-4">
            {Object.entries(result.effectiveSettings).map(([key, value]) => (
              <div key={key}>
                <dt className="font-medium break-all">{key}</dt>
                <dd className="text-sm whitespace-pre-wrap break-all">
                  {JSON.stringify(value, null, 2)}
                </dd>
              </div>
            ))}
          </dl>
          {Object.keys(result.effectiveSettings).length === 0 && (
            <p>Keine effektiven Einstellungen in der bestätigten Antwort.</p>
          )}
          <details>
            <summary>Quellen der Vorschau</summary>
            <pre className="text-sm whitespace-pre-wrap break-all mt-3">
              {JSON.stringify(result.sources, null, 2)}
            </pre>
          </details>
        </section>
      )}
    </div>
  );
}
