"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { Dialog } from "@headlessui/react";
import {
  ArrowPathIcon,
  PlusIcon,
  ShoppingBagIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import { ensureSession } from "@/lib/auth";
import { PageHeader } from "@/components/ui/PageHeader";

type Release = {
  provider: string;
  version?: string;
  status: "confirmed" | "stale" | "unavailable";
  checkedAt?: string;
  sourceUrl: string;
  homepage?: string | null;
  deprecated?: boolean;
  disabled?: boolean;
};
type App = {
  id: string;
  name: string;
  display_name: string;
  publisher: string;
  description: string;
  category: string;
  platforms: string[];
  version: string;
  homepage_url?: string;
  license_type: string;
  packages: Record<string, unknown>;
  metadata?: { catalogReleases?: Record<string, Release> };
};
type AppPage = { apps: App[]; total: number; page: number; totalPages: number };
function safeLink(value?: string | null) {
  try {
    const url = new URL(value || "");
    return url.protocol === "https:" && !url.username && !url.password
      ? url.href
      : undefined;
  } catch {
    return undefined;
  }
}
function releaseFor(app: App, platform: string) {
  const binding = app.packages?.[platform] as { id?: string } | undefined;
  const release = app.metadata?.catalogReleases?.[platform] as
    | (Release & { packageId?: string })
    | undefined;
  return binding?.id && binding.id === release?.packageId ? release : undefined;
}
function ReleaseInfo({
  platform,
  release,
}: {
  platform: string;
  release?: Release;
}) {
  return (
    <div className="space-y-1">
      <p className="font-medium">
        {platform === "macos" ? "macOS" : "Windows"} ·{" "}
        {release?.version || "Version nicht bestätigt"}
      </p>
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        {release?.status === "confirmed"
          ? "Aus Paketquelle bestätigt"
          : release?.status === "stale"
            ? "Letzter bestätigter Stand · Aktualisierung fehlgeschlagen"
            : "Paketquelle noch nicht bestätigt"}
        {release?.checkedAt
          ? " · " + new Date(release.checkedAt).toLocaleString("de-CH")
          : ""}
      </p>
      {release && (release.deprecated || release.disabled) && (
        <p className="text-xs" style={{ color: "var(--warning)" }}>
          Diese Paketquelle ist abgekündigt oder deaktiviert.
        </p>
      )}
      {safeLink(release?.sourceUrl) && (
        <a
          className="text-xs underline"
          href={safeLink(release?.sourceUrl)}
          target="_blank"
          rel="noopener noreferrer"
        >
          {release!.provider}: Quelle öffnen
        </a>
      )}
    </div>
  );
}
function AppEditor({
  app,
  onClose,
  onSaved,
}: {
  app?: App;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(app?.display_name || "");
  const [vendor, setVendor] = useState(app?.publisher || "");
  const [description, setDescription] = useState(app?.description || "");
  const [homepage, setHomepage] = useState(app?.homepage_url || "");
  const [category, setCategory] = useState(app?.category || "productivity");
  const [platforms, setPlatforms] = useState(
    app?.platforms || ["windows", "macos"],
  );
  const [license, setLicense] = useState(app?.license_type || "commercial");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [unconfirmed, setUnconfirmed] = useState(false);
  const bindings = app?.packages as Record<string, any> | undefined;
  const [winget, setWinget] = useState(
    bindings?.windows?.type === "winget" ? bindings.windows.id : "",
  );
  const [brew, setBrew] = useState(
    bindings?.macos?.type === "brew" ? bindings.macos.id : "",
  );
  const [cask, setCask] = useState(
    bindings?.macos?.cask !== false && bindings?.macos?.cask !== undefined,
  );
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
          const packages = { ...(app?.packages || {}) } as Record<
            string,
            unknown
          >;
          if (platforms.includes("windows") && winget.trim())
            packages.windows = { type: "winget", id: winget.trim() };
          else delete packages.windows;
          if (platforms.includes("macos") && brew.trim())
            packages.macos = { type: "brew", id: brew.trim(), cask };
          else delete packages.macos;
          const fields = {
            packages,
            display_name: name.trim(),
            publisher: vendor.trim(),
            description,
            homepage_url: homepage || null,
            category,
            platforms,
            license_type: license,
          };
          try {
            const response = app
              ? await api.put("/api/store/catalog/" + app.id, fields)
              : await api.post("/api/store/catalog", {
                  ...fields,
                  name: crypto.randomUUID(),
                  version: "unknown",
                });
            if (
              response.status !== (app ? 200 : 201) ||
              !response.data?.id ||
              (app && response.data.id !== app.id)
            )
              throw new Error("unconfirmed");
            onSaved();
            onClose();
          } catch (failure: any) {
            setError(
              "Katalogänderung nicht bestätigt. Eingaben bleiben erhalten. Vor einer Wiederholung den aktuellen Bestand prüfen.",
            );
            setUnconfirmed(![400, 422].includes(failure?.response?.status));
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="flex justify-between gap-4">
          <Dialog.Title className="text-lg font-semibold">
            {app ? "App bearbeiten" : "App zum Katalog hinzufügen"}
          </Dialog.Title>
          <button
            type="button"
            disabled={busy}
            aria-label="Editor schliessen"
            onClick={onClose}
          >
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <label>
            App-Name
            <input
              className="input-apple mt-2"
              required
              maxLength={160}
              value={name}
              disabled={busy || unconfirmed}
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label>
            Hersteller
            <input
              className="input-apple mt-2"
              required
              maxLength={160}
              value={vendor}
              disabled={busy || unconfirmed}
              onChange={(event) => setVendor(event.target.value)}
            />
          </label>
        </div>
        <label className="block">
          Beschreibung
          <textarea
            className="input-apple mt-2"
            maxLength={2000}
            rows={3}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </label>
        <div className="grid gap-4 sm:grid-cols-2">
          <label>
            Kategorie
            <select
              className="input-apple mt-2"
              value={category}
              onChange={(event) => setCategory(event.target.value)}
            >
              {[
                "productivity",
                "development",
                "communication",
                "browser",
                "security",
                "utilities",
                "media",
                "other",
              ].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            Lizenzmodell
            <select
              className="input-apple mt-2"
              value={license}
              onChange={(event) => setLicense(event.target.value)}
            >
              <option value="free">Kostenfrei</option>
              <option value="commercial">Kommerziell</option>
              <option value="enterprise">Unternehmenslizenz</option>
            </select>
          </label>
        </div>
        <fieldset>
          <legend className="mb-2">Plattformen</legend>
          <div className="flex flex-wrap gap-4">
            {["windows", "macos", "linux"].map((platform) => (
              <label key={platform} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={platforms.includes(platform)}
                  onChange={(event) =>
                    setPlatforms((current) =>
                      event.target.checked
                        ? [...current, platform]
                        : current.filter((value) => value !== platform),
                    )
                  }
                />
                {platform === "macos"
                  ? "macOS"
                  : platform === "windows"
                    ? "Windows"
                    : "Linux"}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="block">
          Offizielle Produktseite
          <input
            className="input-apple mt-2"
            type="url"
            pattern="https://.*"
            value={homepage}
            onChange={(event) => setHomepage(event.target.value)}
            placeholder="https://…"
          />
        </label>
        <fieldset className="od-panel space-y-4">
          <legend className="font-medium">Öffentliche Paketquellen</legend>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Optionale Paketkennungen für den Versionsabgleich. Es werden keine
            Installer ausgeführt. Nach einer Änderung die Paketquellen erneut
            abgleichen.
          </p>
          {platforms.includes("windows") && (
            <label className="block">
              WinGet-Paket-ID
              <input
                className="input-apple mt-2"
                maxLength={160}
                pattern="[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+"
                placeholder="Hersteller.Produkt"
                value={winget}
                onChange={(event) => setWinget(event.target.value)}
              />
            </label>
          )}
          {platforms.includes("macos") && (
            <>
              <label className="block">
                Homebrew-Paket-ID
                <input
                  className="input-apple mt-2"
                  maxLength={160}
                  pattern="[A-Za-z0-9@+._-]+"
                  placeholder="paketname"
                  value={brew}
                  onChange={(event) => setBrew(event.target.value)}
                />
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={cask}
                  onChange={(event) => setCask(event.target.checked)}
                />
                Cask (grafische macOS-App)
              </label>
            </>
          )}
        </fieldset>
        {error && <p role="alert">{error}</p>}
        <div className="flex justify-end gap-3">
          <button
            type="button"
            className="fluent-btn-secondary"
            disabled={busy}
            onClick={onClose}
          >
            Abbrechen
          </button>
          <button
            type="submit"
            className="fluent-btn-primary"
            disabled={busy || unconfirmed || !platforms.length}
          >
            {busy ? "Wird gespeichert …" : "App speichern"}
          </button>
        </div>
      </Dialog.Panel>
    </Dialog>
  );
}
export default function AppStoreView() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [platform, setPlatform] = useState("");
  const [result, setResult] = useState<AppPage | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [admin, setAdmin] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [selected, setSelected] = useState<App | null>(null);
  const [editing, setEditing] = useState<App | "new" | null>(null);
  const generation = useRef(0);
  const syncEpoch = useRef(0);
  useEffect(
    () => () => {
      syncEpoch.current++;
    },
    [],
  );
  useEffect(() => {
    let active = true;
    ensureSession()
      .then((session) => {
        if (active) setAdmin(session.user.roles.includes("admin"));
      })
      .catch(() => setAdmin(false));
    return () => {
      active = false;
    };
  }, []);
  const reload = useCallback(() => setRefresh((value) => value + 1), []);
  useEffect(() => {
    const version = ++generation.current;
    const controller = new AbortController();
    setLoading(true);
    setError("");
    const timer = setTimeout(
      () =>
        api
          .get("/api/store/catalog", {
            params: {
              page,
              limit: 25,
              search: search.trim() || undefined,
              platform: platform || undefined,
            },
            signal: controller.signal,
          })
          .then((response) => {
            const data = response.data;
            if (
              !Array.isArray(data?.apps) ||
              !Number.isSafeInteger(data.total) ||
              data.page !== page
            )
              throw new Error("Invalid catalog");
            if (version === generation.current) setResult(data);
          })
          .catch(() => {
            if (version === generation.current) {
              setResult(null);
              setError(
                "Der App-Katalog konnte nicht geladen werden. Bitte erneut versuchen.",
              );
            }
          })
          .finally(() => {
            if (version === generation.current) setLoading(false);
          }),
      200,
    );
    return () => {
      ++generation.current;
      clearTimeout(timer);
      controller.abort();
    };
  }, [page, search, platform, refresh]);
  return (
    <div className="space-y-6">
      <PageHeader
        title="App Store"
        subtitle="Anwendungen, aktuelle Paketversionen und eigene Katalogeinträge"
        icon={ShoppingBagIcon}
        actions={
          <>
            <button
              className="fluent-btn-secondary"
              onClick={reload}
              disabled={loading}
              aria-label="Katalog neu laden"
            >
              <ArrowPathIcon className="h-4 w-4" />
              Aktualisieren
            </button>
            {admin && (
              <>
                <button
                  className="fluent-btn-secondary"
                  disabled={syncing}
                  onClick={async () => {
                    setSyncing(true);
                    setNotice("");
                    try {
                      const epoch = ++syncEpoch.current;
                      const response = await api.post(
                        "/api/store/catalog/sync",
                        {},
                      );
                      if (response.status !== 202 || !response.data.id)
                        throw new Error("Unconfirmed refresh");
                      let state = response.data;
                      for (
                        let attempt = 0;
                        attempt < 90 && state.state === "running";
                        attempt++
                      ) {
                        await new Promise((resolve) =>
                          setTimeout(resolve, 1000),
                        );
                        if (syncEpoch.current !== epoch) return;
                        state = (await api.get("/api/store/catalog/sync")).data;
                        if (state.id !== response.data.id)
                          throw new Error("Refresh state changed");
                        setNotice(
                          `Paketquellen werden geprüft: ${state.completedApps || 0} von ${state.totalApps ?? "…"} Apps.`,
                        );
                      }
                      if (state.state === "failed")
                        throw new Error("Refresh failed");
                      if (state.state !== "completed")
                        setNotice(
                          "Der Abgleich läuft noch. Der aktuelle Stand bleibt bei jeder App sichtbar.",
                        );
                      else
                        setNotice(
                          state.result.partial
                            ? `${state.result.confirmedSources} von ${state.result.totalSources} Paketquellen bestätigt. Nicht erreichbare Quellen behalten ihren letzten Stand.`
                            : `${state.result.confirmedSources} Paketquellen erfolgreich aktualisiert.`,
                        );
                      reload();
                    } catch {
                      setNotice(
                        "Quellenabgleich nicht bestätigt. Katalog neu laden und den Zeitstempel der einzelnen Quelle prüfen.",
                      );
                    } finally {
                      setSyncing(false);
                    }
                  }}
                >
                  <ArrowPathIcon
                    className={`h-4 w-4 ${syncing ? "animate-spin" : ""}`}
                  />
                  {syncing
                    ? "Quellen werden geprüft …"
                    : "Paketquellen abgleichen"}
                </button>
                <button
                  className="fluent-btn-primary"
                  onClick={() => setEditing("new")}
                >
                  <PlusIcon className="h-4 w-4" />
                  App hinzufügen
                </button>
              </>
            )}
          </>
        }
      />
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="od-panel">
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Apps im aktuellen Filter
          </p>
          <p className="text-2xl font-semibold mt-1">{result?.total ?? "—"}</p>
        </div>
        <div className="od-panel">
          <p className="font-medium">WinGet & Homebrew</p>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
            Paketversionen aus den jeweiligen öffentlichen Quellen.
          </p>
        </div>
        <div className="od-panel">
          <p className="font-medium">Gerätebereitstellung</p>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
            Gerätegebundene Installation benötigt einen verbundenen Agenten.
          </p>
          <a href="/enrollment" className="text-sm underline">
            Geräteanbindung öffnen
          </a>
        </div>
      </div>
      <div className="od-tabs-panel">
        <div
          className="flex flex-wrap items-end gap-4 p-4 border-b"
          style={{ borderColor: "var(--border)" }}
        >
          <label className="flex-1 min-w-[180px]">
            Apps suchen
            <div className="relative mt-2">
              <MagnifyingGlassIcon className="absolute left-3 top-3 h-4 w-4" />
              <input
                className="input-apple !pl-9"
                value={search}
                maxLength={200}
                onChange={(event) => {
                  setSearch(event.target.value);
                  setPage(1);
                }}
                placeholder="Name oder Hersteller"
              />
            </div>
          </label>
          <label>
            Plattform
            <select
              className="input-apple mt-2"
              value={platform}
              onChange={(event) => {
                setPlatform(event.target.value);
                setPage(1);
              }}
            >
              <option value="">Alle Plattformen</option>
              <option value="windows">Windows</option>
              <option value="macos">macOS</option>
              <option value="linux">Linux</option>
            </select>
          </label>
        </div>
        {notice && (
          <p role="status" className="p-4">
            {notice}
          </p>
        )}
        {error && (
          <p role="alert" className="p-4">
            {error}{" "}
            <button className="underline" onClick={reload}>
              Erneut laden
            </button>
          </p>
        )}
        {loading && (
          <p role="status" className="p-4">
            Katalog wird geladen …
          </p>
        )}
        <div
          className="grid gap-4 p-4 md:grid-cols-2 xl:grid-cols-3"
          aria-busy={loading}
        >
          {result?.apps.map((app) => (
            <article className="od-panel space-y-4" key={app.id}>
              <div>
                <h2 className="font-semibold">{app.display_name}</h2>
                <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                  {app.publisher}
                </p>
              </div>
              <p className="text-sm">{app.description}</p>
              <div className="space-y-3">
                {["windows", "macos"]
                  .filter(
                    (value) =>
                      app.platforms.includes(value) &&
                      (!platform || platform === value),
                  )
                  .map((value) => (
                    <ReleaseInfo
                      key={value}
                      platform={value}
                      release={releaseFor(app, value)}
                    />
                  ))}
                {platform === "linux" && (
                  <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                    Die Version hängt von Distribution und Geräte-Paketquelle
                    ab.
                  </p>
                )}
              </div>
              <button
                className="fluent-btn-secondary"
                onClick={() => setSelected(app)}
              >
                App-Details
              </button>
            </article>
          ))}
        </div>
        {!loading && result?.total === 0 && (
          <p className="p-6">
            Keine Apps in diesem Filter. Suche oder Plattform anpassen
            {admin ? " oder eine eigene App hinzufügen." : "."}
          </p>
        )}
        <nav
          aria-label="Katalogseiten"
          className="flex flex-wrap gap-4 items-center p-4 border-t"
          style={{ borderColor: "var(--border)" }}
        >
          <button
            className="fluent-btn-secondary"
            disabled={loading || page <= 1}
            onClick={() => setPage((value) => value - 1)}
          >
            Zurück
          </button>
          <span>
            Seite {page} von {Math.max(1, result?.totalPages || 1)}
          </span>
          <button
            className="fluent-btn-secondary"
            disabled={loading || !result || page >= result.totalPages}
            onClick={() => setPage((value) => value + 1)}
          >
            Weiter
          </button>
        </nav>
      </div>
      {selected && (
        <Dialog
          open
          onClose={() => setSelected(null)}
          className="od-modal-frame"
        >
          <Dialog.Panel className="od-modal-panel max-w-2xl space-y-5">
            <div className="flex justify-between gap-4">
              <div>
                <Dialog.Title className="text-xl font-semibold">
                  {selected.display_name}
                </Dialog.Title>
                <p>{selected.publisher}</p>
              </div>
              <button
                aria-label="App-Details schliessen"
                onClick={() => setSelected(null)}
              >
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>
            <p>{selected.description}</p>
            {["windows", "macos"]
              .filter((value) => selected.platforms.includes(value))
              .map((value) => (
                <ReleaseInfo
                  key={value}
                  platform={value}
                  release={releaseFor(selected, value)}
                />
              ))}
            <div className="flex flex-wrap gap-3">
              {safeLink(
                selected.homepage_url ||
                  selected.metadata?.catalogReleases?.macos?.homepage,
              ) && (
                <a
                  className="fluent-btn-secondary"
                  target="_blank"
                  rel="noopener noreferrer"
                  href={safeLink(
                    selected.homepage_url ||
                      selected.metadata?.catalogReleases?.macos?.homepage,
                  )}
                >
                  Zum Anbieter
                </a>
              )}
              <a
                className="fluent-btn-secondary"
                href={
                  "/licenses?create=1&product=" +
                  encodeURIComponent(selected.display_name) +
                  "&vendor=" +
                  encodeURIComponent(selected.publisher)
                }
              >
                Lizenzpool vorbereiten
              </a>
              {admin && (
                <button
                  className="fluent-btn-secondary"
                  onClick={() => {
                    setEditing(selected);
                    setSelected(null);
                  }}
                >
                  App bearbeiten
                </button>
              )}
            </div>
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Paketquellen bestätigen eine angebotene Version. Eine Installation
              auf einem bestimmten Gerät wird hier erst mit dessen bestätigtem
              Management-Kontext ausgeführt.
            </p>
          </Dialog.Panel>
        </Dialog>
      )}
      {editing && admin && (
        <AppEditor
          app={editing === "new" ? undefined : editing}
          onClose={() => setEditing(null)}
          onSaved={reload}
        />
      )}
    </div>
  );
}
