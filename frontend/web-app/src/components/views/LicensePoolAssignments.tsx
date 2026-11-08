"use client";
import { useEffect, useRef, useState } from "react";
import { Dialog } from "@headlessui/react";
import { api } from "@/lib/api";
import { directoryUsers, DirectoryUser, userName } from "@/lib/directoryUsers";
import { DirectoryConfirmation } from "./UserDetailPanel";

type Assignment = {
  id: string;
  license_id: string;
  assignee_id: string;
  assignee_name?: string;
  assignee_type: string;
  sources: Array<{ type: string; id: string; expires_at?: string }>;
};
export default function LicensePoolAssignments({
  pool,
  canManage,
  onClose,
  onChanged,
}: {
  pool: {
    id: string;
    name: string;
    vendor: string;
    total_seats: number;
    used_seats: number;
  };
  canManage: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [assignments, setAssignments] = useState<Assignment[] | null>(null);
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [readDirectory, setReadDirectory] = useState(false);
  const [userId, setUserId] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [confirmation, setConfirmation] = useState<{
    userId: string;
    name: string;
    revoke: boolean;
  } | null>(null);
  const epoch = useRef(0);
  useEffect(() => {
    const version = ++epoch.current;
    setAssignments(null);
    setError("");
    api
      .get("/api/licenses/" + encodeURIComponent(pool.id) + "/assignments")
      .then((response) => {
        if (
          !Array.isArray(response.data.assignments) ||
          response.data.assignments.some(
            (value: Assignment) => value.license_id !== pool.id,
          )
        )
          throw new Error("Wrong pool");
        if (version === epoch.current)
          setAssignments(response.data.assignments);
      })
      .catch(() => {
        if (version === epoch.current)
          setError("Pool-Zuweisungen nicht bestätigt. Bitte erneut laden.");
      });
    return () => {
      epoch.current++;
    };
  }, [pool.id, revision]);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setUsers([]);
    const timer = setTimeout(
      () =>
        directoryUsers
          .access()
          .then(async (access) => {
            if (!active) return;
            const allowed =
              !access.demoMode &&
              !!access.userId &&
              access.directoryReadProtocol === 1 &&
              access.permissions.includes("users.read");
            setReadDirectory(allowed);
            if (!allowed) return;
            const result = await directoryUsers.list(
              page,
              search,
              "true",
              controller.signal,
            );
            if (active) {
              setUsers(result.users);
              setTotal(result.total);
            }
          })
          .catch(() => {
            if (active) {
              setUsers([]);
              setReadDirectory(false);
            }
          }),
      200,
    );
    return () => {
      active = false;
      controller.abort();
      clearTimeout(timer);
    };
  }, [page, search]);
  const refresh = () => {
    setError("");
    setRevision((value) => value + 1);
  };
  return (
    <Dialog
      open
      onClose={() => {
        if (!busy) onClose();
      }}
      className="od-modal-frame"
    >
      <Dialog.Panel className="od-modal-panel max-w-3xl space-y-5">
        <Dialog.Title className="text-xl font-semibold">
          Zuweisungen · {pool.name}
        </Dialog.Title>
        <p>
          {pool.vendor} · {pool.used_seats} von{" "}
          {pool.total_seats || "unbegrenzt"} Plätzen belegt
        </p>
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Die Vergabe erfolgt an eine Person. Zusätzliche Geräte dieser Person
          erzeugen keine weitere Personen-Zuweisung. Der erlaubte Geräteumfang
          richtet sich nach dem Herstellervertrag.
        </p>
        {error && <p role="alert">{error}</p>}
        {notice && <p role="status">{notice}</p>}
        {!assignments && !error && (
          <p role="status">Zuweisungen werden geladen …</p>
        )}
        {assignments?.length === 0 && <p>Noch keine Plätze vergeben.</p>}
        <ul className="space-y-3">
          {assignments?.map((row) => (
            <li key={row.id} className="od-panel space-y-2">
              <p className="font-medium">
                {row.assignee_name || row.assignee_id}
              </p>
              {row.assignee_type === "user" ? (
                <a
                  className="text-sm underline"
                  href={
                    "/users?selected=" + encodeURIComponent(row.assignee_id)
                  }
                >
                  Person öffnen
                </a>
              ) : (
                <p className="text-sm">
                  Ältere {row.assignee_type === "device" ? "Geräte" : "Gruppen"}
                  zuweisung · keine Person bestätigt
                </p>
              )}
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                {row.sources?.length
                  ? row.sources
                      .map((source) =>
                        source.type === "direct"
                          ? "Direktzuweisung"
                          : "Über Gruppe " + source.id,
                      )
                      .join(" · ")
                  : "Herkunft nicht bestätigt"}
              </p>
              {canManage &&
                row.assignee_type === "user" &&
                row.sources?.some((source) => source.type === "direct") && (
                  <button
                    className="fluent-btn-secondary"
                    disabled={busy || !!error}
                    onClick={() =>
                      setConfirmation({
                        userId: row.assignee_id,
                        name: row.assignee_name || row.assignee_id,
                        revoke: true,
                      })
                    }
                  >
                    Direktzuweisung zurücknehmen
                  </button>
                )}
            </li>
          ))}
        </ul>
        {canManage && (
          <section
            className="space-y-4 border-t pt-5"
            style={{ borderColor: "var(--border)" }}
          >
            <h2 className="font-semibold">Platz einer Person zuweisen</h2>
            {readDirectory ? (
              <>
                <label className="block">
                  Mitarbeitende suchen
                  <input
                    className="input-apple mt-2"
                    value={search}
                    maxLength={200}
                    onChange={(event) => {
                      setSearch(event.target.value);
                      setPage(1);
                      setUserId("");
                    }}
                  />
                </label>
                <label className="block">
                  Person
                  <select
                    className="input-apple mt-2"
                    value={userId}
                    onChange={(event) => setUserId(event.target.value)}
                  >
                    <option value="">Person auswählen</option>
                    {users.map((user) => (
                      <option key={user.id} value={user.id}>
                        {userName(user)} · {user.username}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="flex flex-wrap items-center gap-3">
                  <button
                    className="fluent-btn-secondary"
                    disabled={page <= 1}
                    onClick={() => setPage((value) => value - 1)}
                  >
                    Vorherige Personen
                  </button>
                  <span>
                    {total} passende Personen · Seite {page}
                  </span>
                  <button
                    className="fluent-btn-secondary"
                    disabled={page * 25 >= total}
                    onClick={() => setPage((value) => value + 1)}
                  >
                    Weitere Personen
                  </button>
                </div>
              </>
            ) : (
              <label className="block">
                Kanonische Benutzer-ID
                <input
                  className="input-apple mt-2"
                  value={userId}
                  minLength={36}
                  maxLength={36}
                  onChange={(event) => setUserId(event.target.value)}
                />
                <span
                  className="block mt-2 text-sm"
                  style={{ color: "var(--text-muted)" }}
                >
                  Die Personenliste ist nicht freigegeben. Eine bekannte eigene
                  ID wird beim Zuweisen serverseitig geprüft.
                </span>
              </label>
            )}
            <button
              className="fluent-btn-primary"
              disabled={!userId || busy || !!error || !assignments}
              onClick={() =>
                setConfirmation({
                  userId,
                  name:
                    users.find((user) => user.id === userId)?.displayName ||
                    users.find((user) => user.id === userId)?.username ||
                    userId,
                  revoke: false,
                })
              }
            >
              Zuweisung prüfen
            </button>
          </section>
        )}
        <div className="flex flex-wrap justify-end gap-3">
          <button
            className="fluent-btn-secondary"
            disabled={busy}
            onClick={refresh}
          >
            Zuweisungen neu laden
          </button>
          <button
            className="fluent-btn-secondary"
            disabled={busy}
            onClick={onClose}
          >
            Schliessen
          </button>
        </div>
        {confirmation && (
          <DirectoryConfirmation
            title={
              confirmation.revoke
                ? "Direktzuweisung zurücknehmen"
                : "Lizenzplatz zuweisen"
            }
            busy={busy}
            error={error}
            onClose={() => setConfirmation(null)}
            onConfirm={async () => {
              if (busy || error) return;
              setBusy(true);
              const version = epoch.current;
              try {
                if (confirmation.revoke) {
                  const result = await api.delete(
                    "/api/licenses/" +
                      encodeURIComponent(pool.id) +
                      "/assignments/" +
                      encodeURIComponent(confirmation.userId),
                    { params: { assignee_type: "user" } },
                  );
                  if (result.status !== 204) throw new Error("Unconfirmed");
                } else {
                  const result = await api.post(
                    "/api/licenses/" + encodeURIComponent(pool.id) + "/assign",
                    { assignee_type: "user", assignee_id: confirmation.userId },
                  );
                  if (
                    result.status !== 201 ||
                    result.data.assignee_id !== confirmation.userId ||
                    result.data.license_id !== pool.id
                  )
                    throw new Error("Unconfirmed");
                }
                if (version !== epoch.current) return;
                setNotice(
                  confirmation.revoke
                    ? "Die direkte Quelle wurde lokal entfernt. Andere Lizenzquellen bleiben bestehen."
                    : "Lokaler Lizenzplatz bestätigt zugewiesen.",
                );
                setConfirmation(null);
                setUserId("");
                onChanged();
                refresh();
              } catch (failure: any) {
                if (version === epoch.current)
                  setError(
                    failure?.response?.status === 409
                      ? "Bestand oder Zuweisung geändert. Bitte den Pool neu laden."
                      : "Die Änderung ist nicht bestätigt. Aktuelle Zuweisungen prüfen; keine automatische Wiederholung.",
                  );
              } finally {
                setBusy(false);
              }
            }}
          >
            <p>
              {confirmation.name} · {pool.name} · {pool.vendor}
            </p>
            <p className="mt-3">
              {confirmation.revoke
                ? "Nur die direkte Quelle wird entfernt. Bestehende Gruppenquellen können den Platz weiter belegen."
                : "Die Person erhält einen lokalen Lizenzplatz. Andere bestehende Quellen belegen keinen zweiten Platz im selben Pool."}
            </p>
          </DirectoryConfirmation>
        )}
      </Dialog.Panel>
    </Dialog>
  );
}
