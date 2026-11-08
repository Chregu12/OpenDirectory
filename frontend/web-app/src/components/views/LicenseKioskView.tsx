"use client";

import { Dialog } from "@headlessui/react";
import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  ShoppingBagIcon,
  CheckCircleIcon,
  ClockIcon,
  XCircleIcon,
  PlusIcon,
  XMarkIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  UserGroupIcon,
  UserIcon,
  ComputerDesktopIcon,
  PencilIcon,
  TrashIcon,
  ExclamationTriangleIcon,
  TagIcon,
  CurrencyDollarIcon,
  CalendarIcon,
  ArrowDownTrayIcon,
} from "@heroicons/react/24/outline";
import { ShoppingBagIcon as ShoppingBagSolid } from "@heroicons/react/24/solid";
import { PageHeader } from "@/components/ui/PageHeader";
import { api } from "@/lib/api";
import LicensePoolAssignments from "./LicensePoolAssignments";
import LicenseGrantRevokeDialog from "./LicenseGrantRevokeDialog";
import LicenseReviewsView from "./LicenseReviewsView";
import LicenseDelegationsView from "./LicenseDelegationsView";
import LicenseScopeActivationsView from "./LicenseScopeActivationsView";
import LicenseScopePoliciesView from "./LicenseScopePoliciesView";
import LicenseScopeReviewsView from "./LicenseScopeReviewsView";
import LicenseSourceGrantsView from "./LicenseSourceGrantsView";
import toast from "react-hot-toast";
import LicenseFulfillmentView from "./LicenseFulfillmentView";
import { DirectoryConfirmation } from "./UserDetailPanel";
import {
  License,
  inventoryCsv,
  renewalStatus,
  RENEWAL_LABELS,
} from "@/lib/licenseInventory";

// ─── Types ────────────────────────────────────────────────────────────────────

interface LicenseRequest {
  id: string;
  license_id: string;
  license_name: string;
  requester_id: string;
  requester_name: string;
  assignee_type: "user" | "group" | "device";
  assignee_id?: string;
  assignee_name?: string;
  justification?: string;
  status: "pending" | "approved" | "denied" | "cancelled";
  allocation_status?: string;
  identity_bound?: boolean;
  requested_at: string;
  decided_at?: string;
  decided_by?: string;
}

type Tab = "kiosk" | "verwaltung" | "anfragen";

interface LicenseAccess {
  subject: string | null;
  identityState: "active" | "unlinked" | "disabled" | "unavailable";
  permissions: string[];
  demoMode: boolean;
  groupReconciliationEnabled?: boolean;
  userReconciliationEnabled?: boolean;
  groupReconciliationMode?: "client-credentials" | "static-bearer" | "disabled";
}

interface LicenseUserState {
  user_id: string;
  disabled: boolean;
  directory_revision?: string;
  directory_enabled: boolean | null;
  directory_deleted: boolean | null;
  directory_checked_at?: string;
  directory_error?: string;
}

interface LicenseGroupRule {
  license_id: string;
  grant_id?: string;
  group_id: string;
  group_name?: string;
  license_name: string;
  status: string;
  last_error?: string;
  assigned_users: number;
  desired_users: number;
  source_revision?: string;
  last_synced_at?: string;
  directory_observed_at?: string | null;
  directory_valid_until?: string | null;
  membership_valid_until?: string | null;
  source_authorization_valid_until?: string | null;
}

const GROUP_STATUS: Record<string, string> = {
  active: "Aktiv",
  pending: "Abgleich ausstehend",
  "capacity-blocked": "Kapazität fehlt",
  revoked: "Entzogen",
  deleted: "Gruppe gelöscht",
  expired: "Abgelaufen",
  "review-expired": "Prüffrist abgelaufen",
  "directory-unobserved": "Verzeichnisnachweis fehlt",
  "directory-stale": "Verzeichnisnachweis abgelaufen",
  "membership-expired": "Mitgliedschaftsfrist abgelaufen",
  "source-consent-expired": "Service-Lesefreigabe abgelaufen",
};

const CATEGORY_COLORS: Record<string, { color: string; background: string }> = {
  Productivity: { color: "var(--accent)", background: "var(--accent-light)" },
  Design: { color: "#a78bfa", background: "rgba(167,139,250,0.15)" },
  Developer: {
    color: "var(--text-secondary)",
    background: "var(--bg-overlay)",
  },
  Security: { color: "var(--danger)", background: "var(--danger-light)" },
  Monitoring: { color: "var(--warning)", background: "var(--warning-light)" },
  Network: { color: "var(--success)", background: "var(--success-light)" },
};

const TYPE_LABELS: Record<string, string> = {
  per_user: "Pro Benutzer",
  per_device: "Pro Gerät",
  concurrent: "Gleichzeitig",
  subscription: "Abonnement",
};

function fmtDate(s?: string | null) {
  if (!s) return "—";
  return new Date(s).toLocaleDateString("de-CH");
}

function fmtCHF(amount: number | string | null | undefined, currency = "CHF") {
  return `${currency} ${Number(amount ?? 0).toFixed(2)}`;
}

function seatsColor(used: number, total: number) {
  if (total === 0) return "text-[var(--text-muted,#8b949e)] ";
  const pct = used / total;
  if (pct >= 1) return "text-red-500";
  if (pct >= 0.8) return "text-[#FF9500]";
  return "text-[#34C759]";
}

// ─── Request Modal ────────────────────────────────────────────────────────────

function RequestModal({
  license,
  canRequestForOthers,
  onClose,
  onSubmitted,
}: {
  license: License;
  canRequestForOthers: boolean;
  onClose: () => void;
  onSubmitted: () => void;
}) {
  const [justification, setJustification] = useState("");
  const [delegated, setDelegated] = useState(false);
  const [personId, setPersonId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  return (
    <Dialog
      open
      onClose={() => {
        if (!submitting) onClose();
      }}
      className="od-modal-frame"
    >
      <Dialog.Panel
        as="form"
        className="od-modal-panel max-w-lg space-y-5"
        onSubmit={async (event) => {
          event.preventDefault();
          if (submitting || error) return;
          setSubmitting(true);
          try {
            const payload =
              canRequestForOthers && delegated
                ? {
                    justification,
                    assignee_type: "user",
                    assignee_id: personId,
                  }
                : { justification };
            const response = await api.post(
              `/api/licenses/${license.id}/request`,
              payload,
            );
            if (
              ![200, 201].includes(response.status) ||
              !response.data?.id ||
              response.data.license_id !== license.id ||
              response.data.assignee_type !== "user" ||
              !["pending", "approved"].includes(response.data.status) ||
              (delegated && response.data.assignee_id !== personId)
            )
              throw new Error("Unconfirmed request");
            toast.success(
              response.data.status === "approved"
                ? "Lokaler Lizenzplatz bestätigt zugewiesen."
                : "Anfrage eingereicht — wartet auf Genehmigung",
            );
            onSubmitted();
            onClose();
          } catch {
            setError(
              "Anfrage nicht bestätigt. Eingaben bleiben erhalten. Vor einer Wiederholung die Anfragen neu laden.",
            );
          } finally {
            setSubmitting(false);
          }
        }}
      >
        <Dialog.Title className="text-lg font-semibold">
          {license.name} anfragen
        </Dialog.Title>
        <p>{license.vendor}</p>
        <p className="text-sm">
          Die Lizenz wird für dein angemeldetes Benutzerkonto beantragt. Eine
          Person kann mehrere Geräte besitzen; die Vergabe erfolgt an die
          Person.
        </p>
        {canRequestForOthers && (
          <>
            <label className="flex gap-2 items-center">
              <input
                type="checkbox"
                checked={delegated}
                disabled={submitting || !!error}
                onChange={(event) => setDelegated(event.target.checked)}
              />
              Für eine andere Person anfragen
            </label>
            {delegated && (
              <label className="block">
                Kanonische Personen-ID
                <input
                  className="input-apple mt-2"
                  required
                  maxLength={36}
                  pattern="[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}"
                  value={personId}
                  disabled={submitting || !!error}
                  onChange={(event) => setPersonId(event.target.value)}
                />
              </label>
            )}
          </>
        )}
        <label className="block">
          Begründung
          <textarea
            className="input-apple mt-2"
            required={!license.auto_approve}
            rows={3}
            maxLength={2000}
            placeholder="Warum wird diese Lizenz benötigt?"
            value={justification}
            disabled={submitting || !!error}
            onChange={(event) => setJustification(event.target.value)}
          />
        </label>
        {error && <p role="alert">{error}</p>}
        <div className="flex justify-end gap-3">
          <button
            type="button"
            className="fluent-btn-secondary"
            disabled={submitting}
            onClick={onClose}
          >
            Abbrechen
          </button>
          <button
            className="fluent-btn-primary"
            type="submit"
            disabled={submitting || !!error}
          >
            {submitting ? "Wird angefragt …" : "Lizenz anfragen"}
          </button>
        </div>
      </Dialog.Panel>
    </Dialog>
  );
}

// ─── License Form Modal ───────────────────────────────────────────────────────

function LicenseFormModal({
  license,
  initialProduct = "",
  initialVendor = "",
  onClose,
  onSaved,
}: {
  license?: License;
  initialProduct?: string;
  initialVendor?: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState({
    inventory_details: {
      reference: license?.inventory_details?.reference || "",
      orderReference: license?.inventory_details?.orderReference || "",
      supplier: license?.inventory_details?.supplier || "",
      receivedDate: license?.inventory_details?.receivedDate || "",
    },
    name: license?.name || initialProduct,
    vendor: license?.vendor || initialVendor,
    category: license?.category || "Software",
    license_type: license?.license_type || "per_user",
    total_seats: license?.total_seats ?? 1,
    cost_per_seat: Number(license?.cost_per_seat || 0),
    currency: license?.currency || "CHF",
    renewal_date: license?.renewal_date?.slice(0, 10) || "",
    auto_approve: license?.auto_approve || false,
    description: license?.description || "",
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [unconfirmed, setUnconfirmed] = useState(false);
  return (
    <Dialog
      open
      onClose={() => {
        if (!saving) onClose();
      }}
      className="od-modal-frame"
    >
      <Dialog.Panel
        as="form"
        className="od-modal-panel max-w-2xl space-y-5"
        onSubmit={async (event) => {
          event.preventDefault();
          if (saving || unconfirmed) return;
          setSaving(true);
          setError("");
          try {
            const payload = {
              ...form,
              inventory_details: Object.fromEntries(
                Object.entries(form.inventory_details).map(([key, value]) => [
                  key,
                  value.trim(),
                ]),
              ),
            };
            const response = license
              ? await api.put("/api/licenses/" + license.id, payload)
              : await api.post("/api/licenses", payload);
            if (
              response.status !== (license ? 200 : 201) ||
              !response.data?.id ||
              (license && response.data.id !== license.id) ||
              Object.entries(payload.inventory_details).some(
                ([key, value]) =>
                  response.data.inventory_details?.[key] !== value,
              )
            )
              throw new Error("unconfirmed");
            toast.success(
              license
                ? "Lizenzeintrag aktualisiert."
                : "Lizenzeintrag erfasst.",
            );
            onSaved();
            onClose();
          } catch (failure: any) {
            setError(
              failure?.response?.status === 409
                ? "Der Bestand kann nicht unter die bereits vergebenen Plätze reduziert werden. Prüfe den aktuellen Bestand."
                : failure?.response?.status === 400
                  ? "Die Angaben sind ungültig. Prüfe Produktname, Bestand, Preis und Erneuerungsdatum."
                  : "Speicherung nicht bestätigt. Eingaben bleiben erhalten. Prüfe den Bestand vor einer Wiederholung.",
            );
            setUnconfirmed(
              ![400, 409, 422].includes(failure?.response?.status),
            );
          } finally {
            setSaving(false);
          }
        }}
      >
        <div className="flex justify-between items-center gap-4">
          <Dialog.Title className="text-lg font-semibold">
            {license ? "Lizenzeintrag bearbeiten" : "Erhaltene Lizenz erfassen"}
          </Dialog.Title>
          <button
            type="button"
            disabled={saving}
            aria-label="Lizenzpool-Editor schliessen"
            onClick={onClose}
          >
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Erfasse jede erhaltene Lizenz oder jeden Vertrag als eigenen Eintrag
          mit Hersteller, Produkt und Anzahl Plätzen. Weitere Verträge desselben
          Produkts können getrennt erfasst werden. Die Erfassung löst keine
          Bestellung beim Anbieter aus.
        </p>
        <fieldset
          disabled={saving || unconfirmed}
          className="grid gap-4 sm:grid-cols-2"
        >
          <label>
            Produktname
            <input
              className="input-apple mt-2"
              required
              maxLength={160}
              value={form.name}
              onChange={(event) =>
                setForm((current) => ({ ...current, name: event.target.value }))
              }
              placeholder="z.B. JetBrains, Adobe oder eine eigene Anwendung"
            />
          </label>
          <label>
            Hersteller
            <input
              className="input-apple mt-2"
              required
              maxLength={160}
              value={form.vendor}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  vendor: event.target.value,
                }))
              }
            />
          </label>
          <label>
            Lizenz-/Vertragsreferenz
            <input
              className="input-apple mt-2"
              maxLength={255}
              value={form.inventory_details.reference}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  inventory_details: {
                    ...current.inventory_details,
                    reference: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label>
            Bestell-/Belegreferenz
            <input
              className="input-apple mt-2"
              maxLength={255}
              value={form.inventory_details.orderReference}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  inventory_details: {
                    ...current.inventory_details,
                    orderReference: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label>
            Lieferant
            <input
              className="input-apple mt-2"
              maxLength={255}
              value={form.inventory_details.supplier}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  inventory_details: {
                    ...current.inventory_details,
                    supplier: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label>
            Erhalten am
            <input
              className="input-apple mt-2"
              type="date"
              value={form.inventory_details.receivedDate}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  inventory_details: {
                    ...current.inventory_details,
                    receivedDate: event.target.value,
                  },
                }))
              }
            />
          </label>
          <p
            className="sm:col-span-2 text-sm"
            style={{ color: "var(--text-muted)" }}
          >
            Referenzen und Bezugsdaten sind nur im berechtigten Bestandskatalog
            sichtbar. Vertrauliche Lizenzschlüssel gehören nicht in diese
            Referenzfelder.
          </p>
          <label>
            Kategorie
            <input
              className="input-apple mt-2"
              required
              maxLength={100}
              value={form.category}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  category: event.target.value,
                }))
              }
            />
          </label>
          <label>
            Lizenzart
            <select
              className="input-apple mt-2"
              value={form.license_type}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  license_type: event.target.value as License["license_type"],
                }))
              }
            >
              {Object.entries(TYPE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Gekaufte Plätze (Gesamtbestand)
            <input
              className="input-apple mt-2"
              type="number"
              required
              min={Math.max(1, license?.used_seats || 0)}
              max={2147483647}
              step={1}
              value={form.total_seats}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  total_seats: Number(event.target.value),
                }))
              }
            />
          </label>
          <p
            className="sm:col-span-2 text-sm"
            style={{ color: "var(--text-muted)" }}
          >
            Die Zuweisung erfolgt immer an eine Person. Das Lizenzmodell
            beschreibt den Herstellervertrag; der erlaubte Geräteumfang richtet
            sich nach diesem Vertrag.
          </p>
          <label>
            Kosten je Platz
            <input
              className="input-apple mt-2"
              type="number"
              min={0}
              step="0.01"
              value={form.cost_per_seat}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  cost_per_seat: Number(event.target.value),
                }))
              }
            />
          </label>
          <label>
            Währung
            <select
              className="input-apple mt-2"
              value={form.currency}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  currency: event.target.value,
                }))
              }
            >
              {["CHF", "EUR", "USD", "GBP"].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            Erneuerungsdatum
            <input
              className="input-apple mt-2"
              type="date"
              value={form.renewal_date}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  renewal_date: event.target.value,
                }))
              }
            />
          </label>
          <label className="sm:col-span-2">
            Beschreibung
            <textarea
              className="input-apple mt-2"
              rows={3}
              maxLength={2000}
              value={form.description}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  description: event.target.value,
                }))
              }
            />
          </label>
          <label className="sm:col-span-2 flex items-center gap-3">
            <input
              type="checkbox"
              checked={form.auto_approve}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  auto_approve: event.target.checked,
                }))
              }
            />
            Anfragen ohne zusätzliche Genehmigung zuteilen
          </label>
        </fieldset>
        {error && <p role="alert">{error}</p>}
        <div className="flex justify-end gap-3">
          <button
            type="button"
            className="fluent-btn-secondary"
            disabled={saving}
            onClick={onClose}
          >
            Abbrechen
          </button>
          <button
            type="submit"
            className="fluent-btn-primary"
            disabled={saving || unconfirmed}
          >
            {saving ? "Wird gespeichert …" : "Speichern"}
          </button>
        </div>
      </Dialog.Panel>
    </Dialog>
  );
}

function AdvancedPanel({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <section className="od-panel">
      <button
        className="font-medium text-left w-full py-2"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        {title} <span aria-hidden="true">{open ? "−" : "+"}</span>
      </button>
      {open && <div className="mt-4">{children}</div>}
    </section>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

export default function LicenseKioskView({
  createRequested = false,
  initialProduct = "",
  initialVendor = "",
  onCreateHandled,
}: {
  createRequested?: boolean;
  initialProduct?: string;
  initialVendor?: string;
  onCreateHandled?: () => void;
} = {}) {
  const [tab, setTab] = useState<Tab>("kiosk");
  const initialTabChosen = useRef(false);
  const [assignmentPool, setAssignmentPool] = useState<License | null>(null);
  const [createDefaults, setCreateDefaults] = useState({
    product: initialProduct,
    vendor: initialVendor,
  });
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [licenses, setLicenses] = useState<License[]>([]);
  const [requests, setRequests] = useState<LicenseRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [catFilter, setCatFilter] = useState("");
  const [renewalFilter, setRenewalFilter] = useState("");
  const [capacityFilter, setCapacityFilter] = useState("");
  const [sort, setSort] = useState("name");
  const [deleteTarget, setDeleteTarget] = useState<License | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [orderLicense, setOrderLicense] = useState<License | null>(null);
  const [editLicense, setEditLicense] = useState<License | undefined>();
  const [showLicForm, setShowLicForm] = useState(false);
  const [access, setAccess] = useState<LicenseAccess | null>(null);
  const [loadError, setLoadError] = useState("");
  const [groupRules, setGroupRules] = useState<LicenseGroupRule[]>([]);
  const [grantToRevoke, setGrantToRevoke] = useState<{
    licenseId: string;
    grantId: string;
  } | null>(null);
  const [groupError, setGroupError] = useState("");
  const [userStates, setUserStates] = useState<LicenseUserState[]>([]);
  const [userStateError, setUserStateError] = useState("");
  const canSelfService = access?.identityState === "active";
  const canReadCatalog =
    access?.permissions.includes("licenses.catalog.read") ?? false;
  const canManageCatalog =
    access?.permissions.includes("licenses.catalog.manage") ?? false;
  const canReviewRequests =
    access?.permissions.includes("licenses.requests.review") ?? false;
  const canRequestForOthers =
    access?.permissions.includes("licenses.requests.delegate") ?? false;
  const canReadAssignments =
    access?.permissions.includes("licenses.assignments.read") ?? false;
  const canManageAssignments =
    access?.permissions.includes("licenses.assignments.manage") ?? false;
  useEffect(() => {
    if (!canManageCatalog) {
      setDeleteTarget(null);
      setShowLicForm(false);
    }
  }, [canManageCatalog]);
  useEffect(() => {
    if (!canManageAssignments) setGrantToRevoke(null);
  }, [canManageAssignments]);

  useEffect(() => {
    if (createRequested && canManageCatalog) {
      setCreateDefaults({ product: initialProduct, vendor: initialVendor });
      setEditLicense(undefined);
      setShowLicForm(true);
      onCreateHandled?.();
    }
  }, [createRequested, canManageCatalog, onCreateHandled]);
  const load = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    setGroupError("");
    setUserStateError("");
    try {
      const accessResponse = await api.get<LicenseAccess>(
        "/api/licenses/access",
      );
      const nextAccess = {
        ...accessResponse.data,
        permissions:
          accessResponse.data.identityState === "active"
            ? accessResponse.data.permissions
            : [],
      };
      setAccess(nextAccess);
      if (nextAccess.identityState !== "active") {
        setOrderLicense(null);
        setShowLicForm(false);
      }
      if (!nextAccess.permissions.includes("licenses.catalog.read")) {
        setTab((current) => (current === "verwaltung" ? "kiosk" : current));
        setRenewalFilter("");
        setCapacityFilter("");
        setSort("name");
      }
      const [licRes, reqRes, groupRes, userRes] = await Promise.all([
        api.get(
          nextAccess.permissions.includes("licenses.catalog.read")
            ? "/api/licenses"
            : "/api/licenses/kiosk",
        ),
        nextAccess.identityState === "active"
          ? api.get("/api/licenses/requests")
          : Promise.resolve({ data: { requests: [] } }),
        nextAccess.permissions.includes("licenses.assignments.read")
          ? api.get("/api/licenses/groups").catch(() => {
              setGroupError("Gruppenregeln konnten nicht geladen werden.");
              return { data: { groups: [] } };
            })
          : Promise.resolve({ data: { groups: [] } }),
        nextAccess.permissions.includes("licenses.assignments.read")
          ? api.get("/api/licenses/users").catch(() => {
              setUserStateError("Kontostände konnten nicht geladen werden.");
              return { data: { users: [] } };
            })
          : Promise.resolve({ data: { users: [] } }),
      ]);
      if (!initialTabChosen.current) {
        setTab(
          nextAccess.permissions.includes("licenses.catalog.read")
            ? "verwaltung"
            : "kiosk",
        );
        initialTabChosen.current = true;
      }
      setLicenses(licRes.data?.licenses ?? []);
      setRequests(reqRes.data?.requests ?? []);
      setGroupRules(groupRes.data?.groups ?? []);
      setUserStates(userRes.data?.users ?? []);
    } catch {
      setAccess(null);
      setLicenses([]);
      setRequests([]);
      setGroupRules([]);
      setUserStates([]);
      setTab("kiosk");
      setOrderLicense(null);
      setShowLicForm(false);
      setLoadError(
        "Lizenzdaten konnten nicht geladen werden. Bitte erneut versuchen.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const reconcileUser = async (userId: string) => {
    try {
      const result = await api.post(`/api/licenses/users/${userId}/reconcile`);
      toast.success(
        `Kontostand abgeglichen: ${result.data.assignmentsRevoked || 0} lokale Zuweisungen entzogen`,
      );
      await load();
    } catch {
      toast.error("Kontostand konnte nicht abgeglichen werden.");
      await load();
    }
  };

  const approveLicReq = async (id: string) => {
    try {
      const result = await api.post(`/api/licenses/requests/${id}/approve`);
      toast.success(
        result.data?.allocation_status === "capacity-blocked"
          ? "Anfrage genehmigt; Gruppenvergabe wartet auf Kapazität"
          : "Lizenz zugewiesen",
      );
      load();
    } catch {
      toast.error("Anfrage konnte nicht genehmigt werden");
      load();
    }
  };

  const reconcileGroup = async (rule: LicenseGroupRule) => {
    try {
      const result = await api.post(
        `/api/licenses/${encodeURIComponent(rule.license_id)}/groups/${encodeURIComponent(rule.group_id)}/reconcile`,
      );
      toast.success(
        result.data?.rule?.status === "capacity-blocked"
          ? "Abgeglichen; für neue Mitglieder fehlt Kapazität"
          : "Gruppe abgeglichen",
      );
      load();
    } catch {
      toast.error("Gruppenabgleich fehlgeschlagen");
    }
  };

  const denyLicReq = async (id: string) => {
    try {
      await api.post(`/api/licenses/requests/${id}/deny`);
      toast.success("Anfrage abgelehnt");
      load();
    } catch {
      toast.error("Anfrage konnte nicht abgelehnt werden");
      load();
    }
  };
  const deleteLicense = async () => {
    if (!deleteTarget || deleting || deleteError || !canManageCatalog) return;
    setDeleting(true);
    try {
      const response = await api.delete(
        `/api/licenses/${encodeURIComponent(deleteTarget.id)}`,
      );
      if (response.status !== 204) throw new Error("unconfirmed");
      toast.success("Lizenz entfernt");
      setDeleteTarget(null);
      await load();
    } catch (failure: any) {
      setDeleteError(
        failure?.response?.status === 409
          ? "Dieser Eintrag besitzt geschützte Zuweisungen oder Historie und kann nicht gelöscht werden."
          : "Löschung nicht bestätigt. Dialog schliessen und den Bestand neu laden, bevor du es erneut versuchst.",
      );
    } finally {
      setDeleting(false);
    }
  };

  const categories = Array.from(
    new Set(licenses.map((l) => l.category)),
  ).sort();
  const pending = requests.filter((r) => r.status === "pending");

  const filteredLicenses = licenses
    .filter((l) => {
      if (catFilter && l.category !== catFilter) return false;
      const renewal = renewalStatus(l.renewal_date);
      if (
        renewalFilter === "attention" &&
        !["overdue", "soon"].includes(renewal)
      )
        return false;
      if (
        renewalFilter &&
        renewalFilter !== "attention" &&
        renewal !== renewalFilter
      )
        return false;
      if (
        capacityFilter === "available" &&
        l.total_seats > 0 &&
        l.used_seats >= l.total_seats
      )
        return false;
      if (
        capacityFilter === "full" &&
        (l.total_seats === 0 || l.used_seats < l.total_seats)
      )
        return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          l.name.toLowerCase().includes(q) ||
          l.vendor?.toLowerCase().includes(q) ||
          l.description?.toLowerCase().includes(q) ||
          Object.values(l.inventory_details || {}).some((value) =>
            value?.toLowerCase().includes(q),
          )
        );
      }
      return true;
    })
    .sort((a, b) => {
      let comparison = 0;
      if (sort === "vendor")
        comparison = (a.vendor || "").localeCompare(b.vendor || "", "de-CH");
      if (sort === "renewal")
        comparison = (a.renewal_date || "9999-12-31").localeCompare(
          b.renewal_date || "9999-12-31",
        );
      if (sort === "capacity")
        comparison =
          (a.total_seats === 0 ? Infinity : a.total_seats - a.used_seats) -
          (b.total_seats === 0 ? Infinity : b.total_seats - b.used_seats);
      return comparison || a.name.localeCompare(b.name, "de-CH");
    });
  const overdue = licenses.filter(
    (license) => renewalStatus(license.renewal_date) === "overdue",
  ).length;
  const dueSoon = licenses.filter(
    (license) => renewalStatus(license.renewal_date) === "soon",
  ).length;
  const exportInventory = () => {
    if (!canReadCatalog || loading || loadError) return;
    const url = URL.createObjectURL(
      new Blob([inventoryCsv(filteredLicenses)], {
        type: "text/csv;charset=utf-8",
      }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `lizenzbestand-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const costs = licenses.reduce<Record<string, number>>((totals, license) => {
    const currency = license.currency || "CHF";
    totals[currency] =
      (totals[currency] || 0) +
      Number(license.cost_per_seat ?? 0) * license.used_seats;
    return totals;
  }, {});
  const costLabel =
    Object.entries(costs)
      .map(([currency, cost]) => currency + " " + cost.toFixed(2))
      .join(" · ") || "—";
  const totalSeats = licenses.reduce((sum, l) => sum + l.total_seats, 0);
  const usedSeats = licenses.reduce((sum, l) => sum + l.used_seats, 0);

  const TABS: { key: Tab; label: string; badge?: number }[] = [
    { key: "kiosk", label: "Verfügbare Lizenzen" },
    ...(canReadCatalog
      ? [{ key: "verwaltung" as Tab, label: "Lizenzbestand" }]
      : []),
    { key: "anfragen", label: "Anfragen", badge: pending.length },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Lizenzverwaltung"
        subtitle="Gekaufte Lizenzbestände aller Hersteller erfassen und Personen zuweisen"
        icon={TagIcon}
        actions={
          <>
            <div className="flex gap-2">
              <button
                aria-label="Lizenzen neu laden"
                disabled={loading}
                onClick={load}
                className="fluent-btn-secondary"
              >
                <ArrowPathIcon
                  className={`w-5 h-5 text-[var(--text-muted,#8b949e)]  ${loading ? "animate-spin" : ""}`}
                />
              </button>
              {canManageCatalog && (
                <button
                  onClick={() => {
                    setCreateDefaults({ product: "", vendor: "" });
                    setEditLicense(undefined);
                    setShowLicForm(true);
                  }}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#006FFF]/90"
                >
                  <PlusIcon className="w-4 h-4" /> Erhaltene Lizenz erfassen
                </button>
              )}
            </div>
          </>
        }
      />
      {loadError && (
        <p role="alert" className="text-sm text-red-500">
          {loadError}
        </p>
      )}
      {access?.demoMode && (
        <p role="status" className="text-sm text-amber-600">
          Demo-Modus: Bei Datenbankausfall werden Beispieldaten im
          Arbeitsspeicher verwendet.
        </p>
      )}
      {access && !canSelfService && (
        <p role="status" className="text-sm text-amber-600">
          {access.identityState === "unlinked"
            ? "Dein Konto ist noch keiner Verzeichnis-Identität zugeordnet. Bitte die Administration kontaktieren."
            : access.identityState === "disabled"
              ? "Deine Verzeichnis-Identität ist deaktiviert. Lizenzaktionen sind gesperrt."
              : "Die Identitätsquelle ist nicht verfügbar. Lizenzaktionen sind vorübergehend gesperrt."}
        </p>
      )}

      <section
        className="od-panel space-y-2"
        aria-label="Personenbezogene Lizenzvergabe"
      >
        <h2 className="font-semibold">
          Erhaltene Lizenzen verwalten und Personen zuweisen
        </h2>
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          Eine Lizenz wird einer Person zugewiesen. Ihre ein oder mehreren
          Geräte bleiben dieser Person zugeordnet; ein zusätzliches Gerät
          erzeugt keine zweite Zuweisung im selben Personenpool. Die zulässige
          Nutzung richtet sich nach dem Lizenzvertrag.
        </p>
      </section>
      {/* Stats */}
      <div
        className={`grid grid-cols-2 ${canReadCatalog ? "xl:grid-cols-5" : "lg:grid-cols-3"} gap-4`}
      >
        {[
          {
            label: "Lizenzen total",
            value: loadError ? "—" : licenses.length,
            sub: "Produkte",
          },
          {
            label: "Seats vergeben",
            value: loadError
              ? "—"
              : `${usedSeats} / ${licenses.some((license) => license.total_seats === 0) ? "inkl. unbegrenzt" : totalSeats}`,
            sub: "belegt / Gesamtbestand",
          },
          ...(canReadCatalog
            ? [
                {
                  label: "Kosten der Zuweisungen",
                  value: costLabel,
                  sub: "gemäss Katalogpreisen",
                },
                {
                  label: "Erneuerungen offen",
                  value: loadError ? "—" : overdue + dueSoon,
                  sub: `${overdue} überfällig · ${dueSoon} in den nächsten 30 Tagen`,
                },
              ]
            : []),
          {
            label: "Offene Anfragen",
            value: loadError ? "—" : pending.length,
            sub: "warten auf Genehmigung",
          },
        ].map(({ label, value, sub }) => (
          <div
            key={label}
            className="rounded-xl p-4"
            style={{
              background: "var(--bg-surface, #161b22)",
              border: "1px solid var(--border)",
            }}
          >
            <p className="text-xs text-[var(--text-muted,#8b949e)]  mb-1">
              {label}
            </p>
            <p className="text-xl font-semibold text-[var(--text-primary,#e4e6ea)] ">
              {value}
            </p>
            <p className="text-xs text-[var(--text-muted,#8b949e)]  mt-0.5">
              {sub}
            </p>
          </div>
        ))}
      </div>

      {canReadCatalog && !loadError && !loading && overdue + dueSoon > 0 && (
        <section
          className="od-panel flex flex-wrap items-center justify-between gap-3"
          aria-label="Anstehende Erneuerungen"
        >
          <p>
            {overdue} Erneuerungen überfällig · {dueSoon} in den nächsten 30
            Tagen. Die Hinweise basieren auf den erfassten Vertragsdaten.
          </p>
          <button
            className="fluent-btn-secondary"
            onClick={() => {
              setTab("verwaltung");
              setRenewalFilter("attention");
              setSearch("");
              setCatFilter("");
              setCapacityFilter("");
              setSort("renewal");
            }}
          >
            Erneuerungen ansehen
          </button>
        </section>
      )}

      {/* Tabs */}
      <div
        className="od-tabs"
        style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}
      >
        {TABS.map((t) => (
          <button
            key={t.key}
            aria-pressed={tab === t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              tab === t.key
                ? "border-[#006FFF] text-[#006FFF]"
                : "border-transparent text-[var(--text-muted,#8b949e)] hover:text-[var(--text-secondary,#b1b5bd)]"
            }`}
          >
            {t.label}
            {t.badge != null && t.badge > 0 && (
              <span className="bg-[#FF9500] text-white text-xs font-semibold px-1.5 py-0.5 rounded-full">
                {t.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Kiosk Tab ── */}
      {tab === "kiosk" && (
        <div className="space-y-4">
          {/* Search + category filter */}
          <div className="flex gap-3">
            <div className="relative flex-1">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted,#8b949e)] " />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Software suchen…"
                className="w-full pl-9 pr-3 py-2 text-sm rounded-lg focus:outline-none"
                style={{
                  border: "1px solid var(--border)",
                  background: "var(--bg-surface-raised, #21262d)",
                  color: "var(--text-primary)",
                }}
              />
            </div>
            <div className="flex gap-2 flex-wrap">
              <button
                onClick={() => setCatFilter("")}
                className={`px-3 py-2 text-xs rounded-lg border transition-colors ${!catFilter ? "border-[#006FFF] bg-[rgba(0,111,255,0.15)] text-[#006FFF]" : "text-[var(--text-secondary,#b1b5bd)]"}`}
                style={{
                  borderColor: !catFilter
                    ? "#006FFF"
                    : "rgba(255,255,255,0.07)",
                }}
              >
                Alle
              </button>
              {categories.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setCatFilter(catFilter === cat ? "" : cat)}
                  className={`px-3 py-2 text-xs rounded-lg border transition-colors ${catFilter === cat ? "border-[#006FFF] bg-[rgba(0,111,255,0.15)] text-[#006FFF]" : "text-[var(--text-secondary,#b1b5bd)]"}`}
                  style={{
                    borderColor:
                      catFilter === cat ? "#006FFF" : "rgba(255,255,255,0.07)",
                  }}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* License cards */}
          {loading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {[1, 2, 3, 4].map((i) => (
                <div
                  key={i}
                  className="h-44 bg-gray-100 rounded-xl animate-pulse"
                />
              ))}
            </div>
          ) : filteredLicenses.length === 0 ? (
            <div className="text-center py-20">
              <ShoppingBagSolid className="w-12 h-12 mx-auto mb-3 text-[var(--text-muted,#8b949e)]  opacity-30" />
              <p className="text-sm text-[var(--text-muted,#8b949e)] ">
                Keine Lizenzen gefunden
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {filteredLicenses.map((lic) => {
                const avail = lic.total_seats - lic.used_seats;
                const pct =
                  lic.total_seats > 0 ? lic.used_seats / lic.total_seats : 0;
                return (
                  <div
                    key={lic.id}
                    className="rounded-xl p-5 flex flex-col transition-colors group"
                    style={{
                      background: "var(--bg-surface, #161b22)",
                      border: "1px solid var(--border)",
                    }}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className={`text-xs px-2 py-0.5 rounded-full font-medium ${CATEGORY_COLORS[lic.category] || "bg-gray-50 text-gray-700"}`}
                          >
                            {lic.category}
                          </span>
                          {lic.auto_approve && (
                            <span className="text-xs bg-green-50 text-green-700 px-2 py-0.5 rounded-full">
                              ⚡ Sofort
                            </span>
                          )}
                        </div>
                        <h3 className="text-sm font-semibold text-[var(--text-primary,#e4e6ea)]  truncate">
                          {lic.name}
                        </h3>
                        <p className="text-xs text-[var(--text-muted,#8b949e)] ">
                          {lic.vendor}
                        </p>
                      </div>
                      {lic.cost_per_seat != null && (
                        <div className="text-right flex-shrink-0 ml-3">
                          <p className="text-sm font-semibold text-[var(--text-primary,#e4e6ea)] ">
                            {fmtCHF(lic.cost_per_seat, lic.currency)}
                          </p>
                          <p className="text-xs text-[var(--text-muted,#8b949e)] ">
                            pro{" "}
                            {TYPE_LABELS[lic.license_type]?.split(" ")[1] ??
                              "Seat"}
                          </p>
                        </div>
                      )}
                    </div>

                    {lic.description && (
                      <p className="text-xs text-[var(--text-secondary,#b1b5bd)]  mb-3 line-clamp-2">
                        {lic.description}
                      </p>
                    )}

                    {/* Seat bar */}
                    <div className="mb-3">
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-[var(--text-muted,#8b949e)] ">
                          Verfügbar
                        </span>
                        <span
                          className={seatsColor(
                            lic.used_seats,
                            lic.total_seats,
                          )}
                        >
                          {lic.total_seats === 0
                            ? "Unbegrenzt"
                            : `${avail} / ${lic.total_seats}`}
                        </span>
                      </div>
                      <div className="h-1.5 bg-[rgba(255,255,255,0.06)]  rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${pct >= 1 ? "bg-red-500" : pct >= 0.8 ? "bg-[#FF9500]" : "bg-[#34C759]"}`}
                          style={{ width: `${Math.min(pct * 100, 100)}%` }}
                        />
                      </div>
                    </div>

                    <div className="mt-auto">
                      <button
                        disabled={!canSelfService}
                        onClick={() => setOrderLicense(lic)}
                        className="w-full flex items-center justify-center gap-2 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#006FFF]/90 transition-colors"
                      >
                        <ShoppingBagIcon className="w-4 h-4" />
                        Lizenz anfragen
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ── Verwaltung Tab ── */}
      {tab === "verwaltung" && (
        <div
          className="rounded-xl overflow-x-auto"
          style={{
            background: "var(--bg-surface, #161b22)",
            border: "1px solid var(--border)",
          }}
        >
          <div
            className="p-4 border-b"
            style={{ borderColor: "var(--border)" }}
          >
            <div className="flex flex-wrap items-end justify-between gap-4">
              <label className="block flex-1 min-w-48 max-w-lg">
                Lizenzbestand durchsuchen
                <input
                  className="input-apple mt-2"
                  value={search}
                  maxLength={200}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Produkt, Hersteller, Vertragsreferenz oder Lieferant"
                />
              </label>
              <button
                className="fluent-btn-secondary"
                disabled={loading || !!loadError || !filteredLicenses.length}
                onClick={exportInventory}
              >
                <ArrowDownTrayIcon className="h-4 w-4" /> CSV exportieren
              </button>
            </div>
            <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-4">
              <label className="block mt-3 max-w-lg">
                Kategorie
                <select
                  className="input-apple mt-2"
                  value={catFilter}
                  onChange={(event) => setCatFilter(event.target.value)}
                >
                  <option value="">Alle Kategorien</option>
                  {categories.map((category) => (
                    <option key={category} value={category}>
                      {category}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block mt-3">
                Erneuerungsstatus
                <select
                  className="input-apple mt-2"
                  value={renewalFilter}
                  onChange={(event) => setRenewalFilter(event.target.value)}
                >
                  <option value="">Alle Erneuerungen</option>
                  <option value="attention">
                    Überfällig oder innerhalb 30 Tagen
                  </option>
                  {Object.entries(RENEWAL_LABELS).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block mt-3">
                Platzverfügbarkeit
                <select
                  className="input-apple mt-2"
                  value={capacityFilter}
                  onChange={(event) => setCapacityFilter(event.target.value)}
                >
                  <option value="">Alle Bestände</option>
                  <option value="available">Freie Plätze</option>
                  <option value="full">Vollständig belegt</option>
                </select>
              </label>
              <label className="block mt-3">
                Sortierung
                <select
                  className="input-apple mt-2"
                  value={sort}
                  onChange={(event) => setSort(event.target.value)}
                >
                  <option value="name">Produktname</option>
                  <option value="vendor">Hersteller</option>
                  <option value="renewal">Nächste Erneuerung</option>
                  <option value="capacity">Wenigste freie Plätze zuerst</option>
                </select>
              </label>
            </div>
            <p className="text-sm mt-3" style={{ color: "var(--text-muted)" }}>
              {filteredLicenses.length} von {licenses.length} Einträgen
            </p>
            {(search || catFilter || renewalFilter || capacityFilter) && (
              <button
                className="text-sm underline mt-2"
                onClick={() => {
                  setSearch("");
                  setCatFilter("");
                  setRenewalFilter("");
                  setCapacityFilter("");
                }}
              >
                Filter zurücksetzen
              </button>
            )}
          </div>
          {loading ? (
            <div className="p-6 space-y-3">
              {[1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="h-16 rounded-lg animate-pulse"
                  style={{ background: "rgba(255,255,255,0.06)" }}
                />
              ))}
            </div>
          ) : filteredLicenses.length === 0 ? (
            <div className="text-center py-16">
              <TagIcon className="w-10 h-10 mx-auto mb-3 text-[var(--text-muted,#8b949e)]  opacity-40" />
              <p className="text-sm text-[var(--text-muted,#8b949e)] ">
                Kein Lizenzbestand für diese Suche. Bestellte Lizenzen über
                „Erhaltene Lizenz erfassen“ hinzufügen.
              </p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-[rgba(255,255,255,0.04)]  border-b border-[rgba(255,255,255,0.07)] ">
                <tr>
                  {[
                    "Produkt",
                    "Lizenzmodell",
                    "Belegt / Gesamt",
                    "Frei",
                    "Kosten je Platz",
                    "Erneuerung",
                    "Aktionen",
                  ].map((h) => (
                    <th
                      scope="col"
                      key={h}
                      className="px-4 py-3 text-left text-xs font-medium text-[var(--text-muted,#8b949e)]  uppercase tracking-wider"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[rgba(255,255,255,0.07)] ">
                {filteredLicenses.map((lic) => (
                  <tr
                    key={lic.id}
                    className="hover:bg-[rgba(255,255,255,0.04)] "
                  >
                    <td className="px-4 py-3">
                      <p className="text-sm font-medium text-[var(--text-primary,#e4e6ea)] ">
                        {lic.name}
                      </p>
                      <p className="text-xs text-[var(--text-muted,#8b949e)] ">
                        {lic.vendor} · {lic.category}
                      </p>
                      {lic.inventory_details?.reference && (
                        <p className="text-sm mt-1">
                          Vertrag: {lic.inventory_details.reference}
                        </p>
                      )}
                      {lic.inventory_details?.orderReference && (
                        <p
                          className="text-xs mt-1"
                          style={{ color: "var(--text-muted)" }}
                        >
                          Bestellung: {lic.inventory_details.orderReference}
                        </p>
                      )}
                      {lic.inventory_details?.supplier && (
                        <p
                          className="text-xs mt-1"
                          style={{ color: "var(--text-muted)" }}
                        >
                          Lieferant: {lic.inventory_details.supplier}
                        </p>
                      )}
                      {lic.inventory_details?.receivedDate && (
                        <p
                          className="text-xs mt-1"
                          style={{ color: "var(--text-muted)" }}
                        >
                          Erhalten:{" "}
                          {fmtDate(lic.inventory_details.receivedDate)}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">
                      {TYPE_LABELS[lic.license_type]}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`text-sm font-medium ${seatsColor(lic.used_seats, lic.total_seats)}`}
                      >
                        {lic.used_seats}
                      </span>
                      <span className="text-sm text-[var(--text-muted,#8b949e)] ">
                        {" "}
                        / {lic.total_seats || "unbegrenzt"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {lic.total_seats === 0
                        ? "Unbegrenzt"
                        : Math.max(0, lic.total_seats - lic.used_seats)}
                    </td>
                    <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">
                      {fmtCHF(lic.cost_per_seat, lic.currency)}
                    </td>
                    <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">
                      {fmtDate(lic.renewal_date)}
                      <p
                        className="text-xs mt-1"
                        style={{
                          color:
                            renewalStatus(lic.renewal_date) === "overdue"
                              ? "var(--danger)"
                              : "var(--text-muted)",
                        }}
                      >
                        {RENEWAL_LABELS[renewalStatus(lic.renewal_date)]}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1">
                        {canReadAssignments && (
                          <button
                            className="fluent-btn-secondary"
                            onClick={() => setAssignmentPool(lic)}
                          >
                            {canManageAssignments
                              ? "Personen zuweisen"
                              : "Zuweisungen"}
                          </button>
                        )}
                        {canManageCatalog && (
                          <button
                            aria-label={`Lizenz ${lic.name} bearbeiten`}
                            onClick={() => {
                              setEditLicense(lic);
                              setShowLicForm(true);
                            }}
                            className="p-1.5 rounded-lg hover:bg-[rgba(255,255,255,0.06)] "
                          >
                            <PencilIcon className="w-4 h-4 text-[var(--text-muted,#8b949e)] " />
                          </button>
                        )}
                        {canManageCatalog && (
                          <button
                            aria-label={`Lizenz ${lic.name} entfernen`}
                            onClick={() => {
                              setDeleteError("");
                              setDeleteTarget(lic);
                            }}
                            className="p-1.5 rounded-lg hover:bg-red-50"
                          >
                            <TrashIcon className="w-4 h-4 text-red-400" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Anfragen Tab ── */}
      {tab === "anfragen" && (
        <div className="space-y-4">
          {/* Pending */}
          {pending.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-[var(--text-muted,#8b949e)]  uppercase tracking-wider mb-2">
                Ausstehend
              </p>
              <div
                className="rounded-xl overflow-x-auto"
                style={{
                  background: "var(--bg-surface, #161b22)",
                  border: "1px solid var(--border)",
                }}
              >
                <table className="w-full">
                  <thead
                    className="border-b"
                    style={{
                      background: "rgba(255,255,255,0.04)",
                      borderColor: "rgba(255,255,255,0.07)",
                    }}
                  >
                    <tr>
                      {[
                        "Benutzer",
                        "Lizenz",
                        "Für",
                        "Begründung",
                        "Angefragt",
                        "Aktionen",
                      ].map((h) => (
                        <th
                          scope="col"
                          key={h}
                          className="px-4 py-3 text-left text-xs font-medium text-[var(--text-muted,#8b949e)]  uppercase tracking-wider"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[rgba(255,255,255,0.07)] ">
                    {pending.map((r) => (
                      <tr
                        key={r.id}
                        className="hover:bg-[rgba(255,255,255,0.04)] "
                      >
                        <td className="px-4 py-3 text-sm font-medium text-[var(--text-primary,#e4e6ea)] ">
                          {r.requester_name}
                        </td>
                        <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">
                          {r.license_name}
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs bg-[rgba(255,255,255,0.06)]  text-[var(--text-secondary,#b1b5bd)]  px-2 py-0.5 rounded-full capitalize">
                            {r.assignee_type}
                          </span>
                          {r.assignee_name && (
                            <span className="text-xs text-[var(--text-muted,#8b949e)]  ml-1">
                              {r.assignee_name}
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <p className="text-xs text-[var(--text-secondary,#b1b5bd)]  max-w-xs truncate">
                            {r.justification || "—"}
                          </p>
                        </td>
                        <td className="px-4 py-3 text-xs text-[var(--text-muted,#8b949e)]  whitespace-nowrap">
                          {fmtDate(r.requested_at)}
                        </td>
                        <td className="px-4 py-3">
                          {r.identity_bound !== true ? (
                            <span className="text-xs text-amber-600">
                              Identität ungeklärt – Anfrage neu erstellen
                            </span>
                          ) : canReviewRequests &&
                            r.requester_id !== access?.subject &&
                            !(
                              r.assignee_type === "user" &&
                              r.assignee_id === access?.subject
                            ) ? (
                            <div className="flex gap-2">
                              <button
                                onClick={() => approveLicReq(r.id)}
                                className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white bg-[#34C759] rounded-lg hover:bg-green-600"
                              >
                                <CheckCircleIcon className="w-3.5 h-3.5" />{" "}
                                Genehmigen
                              </button>
                              <button
                                onClick={() => denyLicReq(r.id)}
                                className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 rounded-lg hover:bg-red-100"
                              >
                                <XCircleIcon className="w-3.5 h-3.5" /> Ablehnen
                              </button>
                            </div>
                          ) : (
                            <span className="text-xs text-[var(--text-muted)]">
                              Wartet auf unabhängige Genehmigung
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* History */}
          <div>
            <p className="text-xs font-semibold text-[var(--text-muted,#8b949e)]  uppercase tracking-wider mb-2">
              Verlauf
            </p>
            <div
              className="rounded-xl overflow-x-auto"
              style={{
                background: "var(--bg-surface, #161b22)",
                border: "1px solid var(--border)",
              }}
            >
              {requests.filter((r) => r.status !== "pending").length === 0 ? (
                <div className="text-center py-12">
                  <ClockIcon className="w-8 h-8 mx-auto mb-2 text-[var(--text-muted,#8b949e)]  opacity-40" />
                  <p className="text-sm text-[var(--text-muted,#8b949e)] ">
                    Noch kein Verlauf
                  </p>
                </div>
              ) : (
                <table className="w-full">
                  <thead className="bg-[rgba(255,255,255,0.04)]  border-b border-[rgba(255,255,255,0.07)] ">
                    <tr>
                      {[
                        "Benutzer",
                        "Lizenz",
                        "Status",
                        "Entschieden am",
                        "Durch",
                      ].map((h) => (
                        <th
                          scope="col"
                          key={h}
                          className="px-4 py-3 text-left text-xs font-medium text-[var(--text-muted,#8b949e)]  uppercase tracking-wider"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[rgba(255,255,255,0.07)] ">
                    {requests
                      .filter((r) => r.status !== "pending")
                      .map((r) => (
                        <tr
                          key={r.id}
                          className="hover:bg-[rgba(255,255,255,0.04)] "
                        >
                          <td className="px-4 py-3 text-sm text-[var(--text-primary,#e4e6ea)] ">
                            {r.requester_name}
                          </td>
                          <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">
                            {r.license_name}
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
                                r.status === "approved"
                                  ? "bg-green-50 text-green-700 border-green-200"
                                  : "bg-red-50 text-red-700 border-red-200"
                              }`}
                            >
                              {r.status === "approved"
                                ? r.assignee_type === "group"
                                  ? `Genehmigt · ${GROUP_STATUS[r.allocation_status || "pending"] || r.allocation_status}`
                                  : "Genehmigt"
                                : r.status === "cancelled"
                                  ? "Zurückgezogen"
                                  : "Abgelehnt"}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-xs text-[var(--text-muted,#8b949e)] ">
                            {fmtDate(r.decided_at)}
                          </td>
                          <td className="px-4 py-3 text-xs text-[var(--text-secondary,#b1b5bd)] ">
                            {r.decided_by || "—"}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {orderLicense && (
        <RequestModal
          license={orderLicense}
          canRequestForOthers={canRequestForOthers}
          onClose={() => setOrderLicense(null)}
          onSubmitted={load}
        />
      )}
      <div className="od-advanced-section">
        <button
          type="button"
          className="fluent-btn-secondary"
          aria-expanded={advancedOpen}
          disabled={!!grantToRevoke}
          onClick={() => setAdvancedOpen((value) => !value)}
        >
          Erweiterte Einstellungen
        </button>
        <p className="mt-2 text-sm" style={{ color: "var(--text-muted)" }}>
          Gruppenabgleich, Zugriffsprüfungen und optionale
          Anbieter-Verbindungen.
        </p>
        {advancedOpen && (
          <div className="space-y-4 mt-4">
            {access && (
              <AdvancedPanel title="Optionale Microsoft-365-Verbindung">
                <LicenseFulfillmentView
                  permissions={access.permissions}
                  subject={access.subject}
                />
              </AdvancedPanel>
            )}
            {access?.subject &&
              access.permissions.some((permission) =>
                permission.startsWith("licenses.reviews."),
              ) && (
                <AdvancedPanel title="Wiederkehrende Lizenzprüfungen">
                  <LicenseReviewsView
                    permissions={access.permissions}
                    userId={access.subject}
                  />
                </AdvancedPanel>
              )}
            {access?.subject &&
              access.permissions.some((permission) =>
                permission.startsWith("licenses.delegations."),
              ) && (
                <AdvancedPanel title="Pool-Aufgaben delegieren">
                  <LicenseDelegationsView
                    permissions={access.permissions}
                    userId={access.subject}
                  />
                </AdvancedPanel>
              )}
            {access?.subject &&
              access.permissions.some(
                (permission) =>
                  permission.startsWith("licenses.delegations.") ||
                  permission === "licenses.scopepim.review",
              ) && (
                <AdvancedPanel title="Privilegierte Pool-Aktivierung">
                  <LicenseScopeActivationsView
                    permissions={access.permissions}
                    userId={access.subject}
                  />
                </AdvancedPanel>
              )}
            {access?.subject &&
              access.permissions.includes("licenses.scopepolicies.read") && (
                <AdvancedPanel title="Pool-Richtlinien">
                  <LicenseScopePoliciesView
                    permissions={access.permissions}
                    userId={access.subject}
                  />
                </AdvancedPanel>
              )}
            {access?.subject &&
              access.permissions.some(
                (permission) =>
                  permission.startsWith("licenses.scopereviews.") ||
                  permission === "licenses.delegations.self",
              ) && (
                <AdvancedPanel title="Prüfung delegierter Verwaltungsrechte">
                  <LicenseScopeReviewsView
                    permissions={access.permissions}
                    userId={access.subject}
                  />
                </AdvancedPanel>
              )}
            {access?.subject &&
              access.permissions.includes("licenses.sources.read") && (
                <AdvancedPanel title="Dienstfreigaben für Lizenzgruppen">
                  <LicenseSourceGrantsView
                    permissions={access.permissions}
                    userId={access.subject}
                  />
                </AdvancedPanel>
              )}
            {canReadAssignments && (
              <section
                aria-label="Gruppenbasierte Lizenzvergabe"
                className="rounded-xl p-4 space-y-3"
                style={{ border: "1px solid var(--border)" }}
              >
                <h3 className="font-semibold">Gruppenbasierte Lizenzvergabe</h3>
                <p className="text-xs">
                  Überlappende Gruppen und Direktzuweisungen verbrauchen
                  zusammen nur einen Sitz je Benutzer. Konfigurierte
                  Hersteller-Connectoren verarbeiten wirksame Änderungen
                  separat; deren Status gesondert prüfen.
                </p>
                <p className="text-xs">
                  Gruppenrechte gelten höchstens fünf Minuten ab
                  Verzeichnisbestätigung, bei früherer Mitgliedschafts- oder
                  Prüffrist entsprechend kürzer. Ein Ausfall verlängert keine
                  Rechte.
                </p>
                <p className="text-xs">
                  Der angezeigte Status ist ein Lesestand. Die Fristen wirken
                  auch ohne erneutes Laden.
                </p>
                {!access?.groupReconciliationEnabled && (
                  <p role="status" className="text-xs text-amber-600">
                    Automatischer Gruppenabgleich ist nicht konfiguriert. Ohne
                    rechtzeitigen manuellen Abgleich laufen Gruppenrechte
                    spätestens nach fünf Minuten ab.
                  </p>
                )}
                {access?.groupReconciliationMode === "client-credentials" && (
                  <p className="text-xs">
                    Automatische Token-Erneuerung ist konfiguriert. Nur
                    ausdrücklich freigegebene Gruppen und lebende
                    Client-Fassungen können einen Nachweis erneuern.
                  </p>
                )}
                {access?.groupReconciliationMode === "static-bearer" && (
                  <p role="status" className="text-xs text-amber-600">
                    Älterer statischer Quellen-Bearer: keine automatische
                    Erneuerung. Sein Ablauf kann den Gruppenabgleich
                    unterbrechen.
                  </p>
                )}
                {groupError && <p role="alert">{groupError}</p>}
                {!loading && groupRules.length === 0 && (
                  <p className="text-sm">Keine Gruppenregeln vorhanden.</p>
                )}
                {groupRules.map((rule) => (
                  <div
                    key={`${rule.license_id}:${rule.group_id}`}
                    className="flex flex-wrap gap-3 items-center text-sm"
                  >
                    <span>
                      {rule.license_name} · {rule.group_name || rule.group_id}
                    </span>
                    <span>{GROUP_STATUS[rule.status] || rule.status}</span>
                    <span>
                      {rule.assigned_users} / {rule.desired_users} Mitglieder
                    </span>
                    <span>Version {rule.source_revision || "—"}</span>
                    <span>
                      Letzter Abgleich:{" "}
                      {rule.last_synced_at
                        ? new Date(rule.last_synced_at).toLocaleString("de-CH")
                        : "—"}
                    </span>
                    <span>
                      Verzeichnis gültig bis:{" "}
                      {rule.directory_valid_until
                        ? new Date(rule.directory_valid_until).toLocaleString(
                            "de-CH",
                          )
                        : "nicht bestätigt"}
                    </span>
                    {rule.membership_valid_until && (
                      <span>
                        Früheste Mitgliedschaftsfrist:{" "}
                        {new Date(rule.membership_valid_until).toLocaleString(
                          "de-CH",
                        )}
                      </span>
                    )}
                    {rule.source_authorization_valid_until && (
                      <span>
                        Service-Lesefreigabe gültig bis:{" "}
                        {new Date(
                          rule.source_authorization_valid_until,
                        ).toLocaleString("de-CH")}
                      </span>
                    )}
                    {rule.last_error && (
                      <span role="alert">{rule.last_error}</span>
                    )}
                    {canManageAssignments &&
                      ![
                        "revoked",
                        "expired",
                        "deleted",
                        "review-expired",
                      ].includes(rule.status) && (
                        <>
                          <button
                            onClick={() => reconcileGroup(rule)}
                            className="text-blue-500"
                          >
                            Abgleichen
                          </button>
                          {rule.grant_id && (
                            <button
                              onClick={() =>
                                setGrantToRevoke({
                                  licenseId: rule.license_id,
                                  grantId: rule.grant_id!,
                                })
                              }
                              className="text-red-500"
                            >
                              Gruppenquelle entziehen
                            </button>
                          )}
                        </>
                      )}
                  </div>
                ))}
              </section>
            )}

            {grantToRevoke && canManageAssignments && (
              <LicenseGrantRevokeDialog
                key={`${grantToRevoke.licenseId}:${grantToRevoke.grantId}`}
                {...grantToRevoke}
                onClose={() => setGrantToRevoke(null)}
                onRevoked={(retained) => {
                  setGrantToRevoke(null);
                  toast.success(
                    `Quelle lokal entzogen; ${retained} Benutzer behalten andere Vergaben. Herstellerstatus separat prüfen.`,
                  );
                  load();
                }}
              />
            )}
            {canReadAssignments && (
              <section
                aria-label="Kontostände für Lizenzen"
                className="rounded-xl p-4 space-y-3"
                style={{ border: "1px solid var(--border)" }}
              >
                <h3 className="font-semibold">Kontostände für Lizenzen</h3>
                <p className="text-xs">
                  Letzte bestätigte Verzeichnisstände, maximal 200 Einträge.
                  Sperren und Löschungen entziehen lokale Benutzer-Zuweisungen;
                  eine Reaktivierung stellt Direktlizenzen nicht automatisch
                  wieder her.
                </p>
                {!access?.userReconciliationEnabled && (
                  <p role="status" className="text-xs text-amber-600">
                    Automatischer Kontenabgleich ist nicht konfiguriert.
                    Bestehende Direktlizenzen müssen manuell abgeglichen werden.
                  </p>
                )}
                {userStateError && <p role="alert">{userStateError}</p>}
                {!loading && !userStateError && userStates.length === 0 && (
                  <p className="text-sm">
                    Keine geprüften Kontostände vorhanden.
                  </p>
                )}
                {userStates.map((state) => (
                  <div
                    key={state.user_id}
                    className="flex flex-wrap gap-3 items-center text-sm"
                  >
                    <span>{state.user_id}</span>
                    <span>
                      {state.disabled
                        ? "Lokal gesperrt"
                        : state.directory_deleted
                          ? "Im Verzeichnis gelöscht"
                          : state.directory_enabled === false
                            ? "Im Verzeichnis deaktiviert"
                            : state.directory_enabled
                              ? "Im Verzeichnis aktiv"
                              : "Identität ungeklärt"}
                    </span>
                    <span>Version {state.directory_revision || "—"}</span>
                    <span>
                      Letzte Bestätigung:{" "}
                      {state.directory_checked_at
                        ? new Date(state.directory_checked_at).toLocaleString(
                            "de-CH",
                          )
                        : "—"}
                    </span>
                    {state.directory_error && (
                      <span role="alert">
                        Abgleichfehler: {state.directory_error}
                      </span>
                    )}
                    {canManageAssignments && (
                      <button
                        onClick={() => reconcileUser(state.user_id)}
                        className="text-blue-500"
                      >
                        Kontostand abgleichen
                      </button>
                    )}
                  </div>
                ))}
              </section>
            )}
          </div>
        )}
      </div>
      {assignmentPool && canReadAssignments && (
        <LicensePoolAssignments
          pool={
            licenses.find((pool) => pool.id === assignmentPool.id) ||
            assignmentPool
          }
          canManage={canManageAssignments}
          onClose={() => setAssignmentPool(null)}
          onChanged={load}
        />
      )}
      {deleteTarget && canManageCatalog && (
        <DirectoryConfirmation
          title="Lizenzeintrag löschen"
          busy={deleting}
          error={deleteError}
          onClose={() => setDeleteTarget(null)}
          onConfirm={deleteLicense}
        >
          <p>
            {deleteTarget.name} · {deleteTarget.vendor}
          </p>
          <p className="mt-3">
            Diesen Bestands- und Vertragseintrag löschen? Der lokale Bestand
            wird entfernt. Geschützte Zuweisungen oder Historie können die
            Löschung verhindern. Dies kündigt keinen Vertrag beim Hersteller.
          </p>
        </DirectoryConfirmation>
      )}
      {showLicForm && canManageCatalog && (
        <LicenseFormModal
          license={editLicense}
          initialProduct={createDefaults.product.slice(0, 160)}
          initialVendor={createDefaults.vendor.slice(0, 160)}
          onClose={() => setShowLicForm(false)}
          onSaved={load}
        />
      )}
    </div>
  );
}
