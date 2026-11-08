"use client";
import { useEffect, useState } from "react";
import {
  ComputerDesktopIcon,
  ArrowPathIcon,
} from "@heroicons/react/24/outline";
import { PageHeader } from "@/components/ui/PageHeader";
import {
  DeviceInventoryClient,
  DeviceCapabilities,
  deviceInventoryError,
} from "@/lib/deviceInventory";
export default function EnrollmentHubView() {
  const [capabilities, setCapabilities] = useState<DeviceCapabilities | null>(
    null,
  );
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const client = new DeviceInventoryClient();
    let active = true;
    setLoading(true);
    setError("");
    client
      .reload()
      .then((value) => {
        if (active) setCapabilities(value);
      })
      .catch((failure) => {
        if (active) {
          setCapabilities(null);
          setError(deviceInventoryError(failure));
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
      client.dispose();
    };
  }, [revision]);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Geräteanbindung"
        subtitle="Inventar, personelle Zuweisung und technische Verwaltung getrennt prüfen"
        icon={ComputerDesktopIcon}
        actions={
          <button
            className="fluent-btn-secondary"
            disabled={loading}
            onClick={() => setRevision((value) => value + 1)}
          >
            <ArrowPathIcon
              className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            Voraussetzungen prüfen
          </button>
        }
      />
      {loading && <p role="status">Gerätevertrag wird geprüft …</p>}
      {error && <p role="alert">{error}</p>}
      <div className="grid gap-4 md:grid-cols-2">
        <section className="od-panel space-y-4">
          <h2 className="font-semibold">Inventar erfassen und zuweisen</h2>
          <p className="text-sm">
            Der vorhandene Gerätevertrag unterstützt eigene Inventareinträge und
            nachvollziehbare Mitarbeitenden-Zuweisungen. Erfassung oder
            Zuweisung installiert keinen Agenten.
          </p>
          <span className="od-badge">
            {capabilities
              ? "Inventarvertrag bestätigt"
              : "Inventarzugriff noch nicht bestätigt"}
          </span>
          <div className="flex flex-wrap gap-3">
            <a className="fluent-btn-primary" href="/devices">
              Geräteinventar
            </a>
            <a className="fluent-btn-secondary" href="/device-returns">
              Rückgaben
            </a>
          </div>
        </section>
        <section className="od-panel space-y-4">
          <h2 className="font-semibold">Technisches Enrollment</h2>
          <p className="text-sm">
            Diese Installation bietet noch keinen bestätigten End-to-End-Vertrag
            für Agent-Registrierung, MDM-Adoption oder Remote-Installation.
            Deshalb werden keine frei erfundenen Tokens, Downloadprofile oder
            Versandbestätigungen erzeugt.
          </p>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Nächster technischer Schritt: einen Geräteprovider mit
            Registrierung, gerätegebundenem Nachweis und bestätigten
            Auftragsergebnissen integrieren.
          </p>
          <a className="fluent-btn-secondary" href="/integrations">
            Dienstverbindungen prüfen
          </a>
        </section>
      </div>
      <section className="od-panel space-y-3">
        <h2 className="font-semibold">Anmeldung bestätigen</h2>
        <p className="text-sm">
          Das eigene Inventar verlangt eine höchstens fünf Minuten alte
          MFA-Anmeldung. Nach der Einrichtung mit Passwort und aktuellem
          Authenticator-Code erneut anmelden.
        </p>
        <a className="fluent-btn-secondary" href="/mfa">
          MFA verwalten
        </a>
      </section>
    </div>
  );
}
