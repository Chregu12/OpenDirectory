"use client";
import { useEffect, useState } from "react";
import { ShareIcon, ArrowPathIcon } from "@heroicons/react/24/outline";
import { PageHeader } from "@/components/ui/PageHeader";
import { directoryGroups, DirectoryGroup } from "@/lib/directoryGroups";
export default function GraphExplorerView() {
  const [groups, setGroups] = useState<DirectoryGroup[] | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    directoryGroups
      .access()
      .then((access) => {
        if (!access.permissions.includes("groups.read"))
          throw new Error("Permission missing");
        return directoryGroups.list();
      })
      .then((data) => {
        if (active) setGroups(data.groups);
      })
      .catch(() => {
        if (active) {
          setGroups(null);
          setError(
            "Eigene Gruppenbeziehungen konnten nicht bestätigt werden. Es werden keine Beispielobjekte oder berechneten Angriffswege angezeigt.",
          );
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [revision]);
  const filtered = groups?.filter((group) =>
    (group.name + " " + (group.description || ""))
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  const shown = filtered?.slice((page - 1) * 25, page * 25);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Objektbeziehungen"
        subtitle="Bestätigte Mitgliedschaften des eigenen Verzeichnisses"
        icon={ShareIcon}
        actions={
          <button
            className="fluent-btn-secondary"
            disabled={loading}
            onClick={() => setRevision((value) => value + 1)}
          >
            <ArrowPathIcon
              className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            Aktualisieren
          </button>
        }
      />
      {error && <p role="alert">{error}</p>}
      {loading && <p role="status">Beziehungen werden geladen …</p>}
      <section className="od-panel space-y-4">
        <label className="block max-w-lg">
          Gruppen suchen
          <input
            className="input-apple mt-2"
            maxLength={200}
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
          />
        </label>
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Die Ansicht zeigt gespeicherte Gruppenmitgliedschaften. Effektive
          Rollen, verschachtelte Vererbung und Sicherheitsrisiken werden daraus
          nicht abgeleitet.
        </p>
      </section>
      {filtered?.length === 0 && <p>Keine Gruppen für diese Suche.</p>}
      {shown?.map((group) => (
        <section className="od-panel space-y-3" key={group.id}>
          <div>
            <h2 className="font-semibold">{group.name}</h2>
            {group.description && (
              <p
                className="text-sm mt-1"
                style={{ color: "var(--text-muted)" }}
              >
                {group.description}
              </p>
            )}
          </div>
          <details>
            <summary>
              {group.members.length} gespeicherte Mitgliedschaften · Version{" "}
              {group.revision}
            </summary>
            <ul className="grid gap-3 sm:grid-cols-2 mt-4">
              {group.members.map((id) => (
                <li key={id}>
                  <a
                    className="underline text-sm break-all"
                    href={"/users?selected=" + encodeURIComponent(id)}
                  >
                    {id}
                  </a>
                </li>
              ))}
            </ul>
          </details>
        </section>
      ))}
      {filtered && (
        <nav
          aria-label="Beziehungsseiten"
          className="flex flex-wrap items-center gap-3"
        >
          <button
            className="fluent-btn-secondary"
            disabled={page <= 1}
            onClick={() => setPage((value) => value - 1)}
          >
            Zurück
          </button>
          <span>
            {filtered.length} Gruppen · Seite {page}
          </span>
          <button
            className="fluent-btn-secondary"
            disabled={page * 25 >= filtered.length}
            onClick={() => setPage((value) => value + 1)}
          >
            Weiter
          </button>
          <a className="fluent-btn-secondary" href="/usergroups">
            Gruppen bearbeiten
          </a>
        </nav>
      )}
    </div>
  );
}
