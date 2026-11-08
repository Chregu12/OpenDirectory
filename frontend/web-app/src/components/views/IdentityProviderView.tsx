"use client";
import { useCallback, useEffect, useState } from "react";
import { FingerPrintIcon, ArrowPathIcon } from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import AppRegistrationsView from "./AppRegistrationsView";
type Discovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  scopes_supported?: string[];
  grant_types_supported?: string[];
};
function Endpoint({ label, value }: { label: string; value: string }) {
  const [notice, setNotice] = useState("");
  return (
    <div className="space-y-2">
      <dt className="text-sm" style={{ color: "var(--text-muted)" }}>
        {label}
      </dt>
      <dd className="flex flex-wrap gap-3 items-center">
        <code className="break-all text-sm flex-1 min-w-0">{value}</code>
        <button
          className="fluent-btn-secondary"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              setNotice("Kopiert.");
            } catch {
              setNotice("Kopieren nicht möglich. Adresse manuell auswählen.");
            }
          }}
        >
          Adresse kopieren
        </button>
      </dd>
      {notice && (
        <p role="status" className="text-sm">
          {notice}
        </p>
      )}
    </div>
  );
}
export default function IdentityProviderView() {
  const [tab, setTab] = useState("overview");
  const [discovery, setDiscovery] = useState<Discovery | null>(null);
  const [providers, setProviders] = useState<string[] | null>(null);
  const [error, setError] = useState("");
  const [providerError, setProviderError] = useState("");
  const [loading, setLoading] = useState(true);
  const [saml, setSaml] = useState<"unverified" | "configured" | "unavailable">(
    "unverified",
  );
  const [origin, setOrigin] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    setProviderError("");
    setOrigin(window.location.origin);
    await Promise.all([
      (async () => {
        try {
          const data = (await api.get("/.well-known/openid-configuration"))
            .data;
          if (
            data?.issuer !== window.location.origin ||
            ["authorization_endpoint", "token_endpoint", "jwks_uri"].some(
              (key) => {
                try {
                  return new URL(data[key]).origin !== window.location.origin;
                } catch {
                  return true;
                }
              },
            )
          )
            throw new Error("Invalid discovery");
          setDiscovery(data);
        } catch {
          setDiscovery(null);
          setError("OIDC-Metadaten konnten nicht bestätigt werden.");
        }
      })(),
      (async () => {
        try {
          const data = (await api.get("/oauth/federation/providers")).data;
          if (
            !Array.isArray(data?.providers) ||
            data.providers.some((value: unknown) => typeof value !== "string")
          )
            throw new Error("Invalid providers");
          setProviders(data.providers);
        } catch {
          setProviders(null);
          setProviderError(
            "Konfigurierte externe Anmeldeanbieter konnten nicht geladen werden.",
          );
        }
      })(),
      (async () => {
        try {
          const response = await api.get("/saml/metadata", {
            responseType: "text",
          });
          if (
            response.status !== 200 ||
            typeof response.data !== "string" ||
            !response.data.includes("EntityDescriptor")
          )
            throw new Error("Invalid metadata");
          setSaml("configured");
        } catch {
          setSaml("unavailable");
        }
      })(),
    ]);
    setLoading(false);
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Identitätsanbieter"
        subtitle="Zentrale Anmeldung, registrierte Anwendungen und bestätigte Metadaten"
        icon={FingerPrintIcon}
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
      <div className="od-tabs-panel">
        <nav className="od-tabs" aria-label="Identitätsbereiche">
          {[
            ["overview", "Anmeldung"],
            ["apps", "Anwendungen"],
            ["federation", "Externe Anbieter"],
            ["saml", "SAML 2.0"],
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
          {loading && <p role="status">Anmeldekonfiguration wird geprüft …</p>}
          {tab === "overview" && (
            <>
              {error && <p role="alert">{error}</p>}
              {discovery && (
                <section className="space-y-5">
                  <h2 className="font-semibold">OAuth 2.0 / OpenID Connect</h2>
                  <dl className="space-y-5">
                    <Endpoint label="Issuer" value={discovery.issuer} />
                    <Endpoint
                      label="Autorisierung"
                      value={discovery.authorization_endpoint}
                    />
                    <Endpoint
                      label="Token-Endpunkt"
                      value={discovery.token_endpoint}
                    />
                    <Endpoint
                      label="Öffentliche Signaturschlüssel"
                      value={discovery.jwks_uri}
                    />
                  </dl>
                  {discovery.scopes_supported && (
                    <p className="text-sm">
                      Veröffentlichte Scopes:{" "}
                      {discovery.scopes_supported.join(", ")}
                    </p>
                  )}
                  <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                    Metadaten beschreiben das Anmeldeprotokoll. Eine
                    erfolgreiche Anmeldung an einer bestimmten Anwendung wird
                    damit nicht bestätigt.
                  </p>
                </section>
              )}
              <section className="od-panel space-y-3">
                <h2 className="font-semibold">MFA und Wiederherstellung</h2>
                <p className="text-sm">
                  Authenticator, erneute Bestätigung und Notfallcodes werden im
                  bestehenden geschützten Ablauf verwaltet. Methoden werden erst
                  nach serverseitiger Bestätigung als eingerichtet angezeigt.
                </p>
                <div className="flex flex-wrap gap-3">
                  <a className="fluent-btn-primary" href="/mfa">
                    MFA verwalten
                  </a>
                  <a className="fluent-btn-secondary" href="/sspr">
                    Passwort-Selbsthilfe
                  </a>
                </div>
              </section>
            </>
          )}
          {tab === "apps" && <AppRegistrationsView />}
          {tab === "federation" && (
            <section className="space-y-4">
              <h2 className="font-semibold">
                Konfigurierte externe OIDC-Anbieter
              </h2>
              {providerError && <p role="alert">{providerError}</p>}
              {providers?.length === 0 && (
                <p>
                  Keine externen Anbieter in der bestätigten
                  Serverkonfiguration.
                </p>
              )}
              <ul className="space-y-3">
                {providers?.map((provider) => (
                  <li className="od-panel" key={provider}>
                    {provider}
                    <p
                      className="text-sm mt-2"
                      style={{ color: "var(--text-muted)" }}
                    >
                      Im Server registriert; externer Login nicht durch diese
                      Anzeige geprüft.
                    </p>
                  </li>
                ))}
              </ul>
              <p className="text-sm">
                Vertrauensbeziehung und vertrauliche Client-Zugänge werden
                serverseitig konfiguriert. Die zentrale Anmeldeseite bindet den
                gewählten Anbieter an den begonnenen OAuth-Ablauf.
              </p>
            </section>
          )}
          {tab === "saml" && (
            <section className="space-y-5">
              <h2 className="font-semibold">SAML 2.0</h2>
              <p>
                {saml === "configured"
                  ? "Die öffentlichen SAML-Metadaten sind erreichbar. Die Verbindung mit der Zielanwendung muss separat geprüft werden."
                  : saml === "unverified"
                    ? "SAML-Metadaten werden geprüft."
                    : "SAML-Metadaten sind nicht verfügbar oder nicht konfiguriert. Es wird keine aktive Verbindung behauptet."}
              </p>
              <p className="text-sm">
                Unterstützt sind angemeldete, IdP-initiierte HTTP-POST-Starts
                für fest konfigurierte Anwendungen. SP-initiierte AuthnRequests
                und Single Logout sind noch nicht verfügbar. Diese Ansicht
                bestätigt keine eingerichtete Verbindung.
              </p>
              {origin && (
                <dl className="space-y-5">
                  <Endpoint
                    label="Metadata XML"
                    value={origin + "/saml/metadata"}
                  />
                  <Endpoint
                    label="X.509-Zertifikat"
                    value={origin + "/saml/certificate"}
                  />
                  <Endpoint
                    label="Geschützter Start (POST mit appId)"
                    value={origin + "/saml/sso"}
                  />
                </dl>
              )}
              {origin && (
                <a
                  className="fluent-btn-secondary"
                  href={origin + "/saml/metadata"}
                  target="_blank"
                  rel="noreferrer"
                >
                  Metadaten beim Identity Provider öffnen
                </a>
              )}
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
