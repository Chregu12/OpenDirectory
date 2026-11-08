export interface License {
  inventory_details?: {
    reference?: string;
    orderReference?: string;
    supplier?: string;
    receivedDate?: string;
  };
  id: string;
  name: string;
  vendor: string;
  category: string;
  license_type: "per_user" | "per_device" | "concurrent" | "subscription";
  total_seats: number;
  used_seats: number;
  cost_per_seat?: number | string | null;
  currency?: string;
  renewal_date?: string | null;
  auto_approve: boolean;
  description?: string;
  notes?: string;
  created_at: string;
}

export type RenewalStatus = "overdue" | "soon" | "later" | "none";
export const RENEWAL_LABELS: Record<RenewalStatus, string> = {
  overdue: "Erneuerung überfällig",
  soon: "In den nächsten 30 Tagen",
  later: "Später fällig",
  none: "Kein Erneuerungsdatum",
};

export function renewalStatus(
  value: string | null | undefined,
  now = new Date(),
): RenewalStatus {
  if (!value) return "none";
  const due = Date.parse(value.slice(0, 10) + "T00:00:00Z");
  if (
    !Number.isFinite(due) ||
    new Date(due).toISOString().slice(0, 10) !== value.slice(0, 10)
  )
    return "none";
  const today = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
  const days = (due - today) / 86400000;
  return days < 0 ? "overdue" : days <= 30 ? "soon" : "later";
}

export function inventoryCsv(licenses: License[], now = new Date()): string {
  const cell = (value: unknown) => {
    const text = value == null ? "" : String(value);
    const safe = /^\s*[=+\-@]/.test(text) ? "'" + text : text;
    return '"' + safe.replaceAll('"', '""') + '"';
  };
  const rows: unknown[][] = [
    [
      "Produkt",
      "Hersteller",
      "Kategorie",
      "Lizenzmodell",
      "Vertragsreferenz",
      "Bestellreferenz",
      "Lieferant",
      "Erhalten am",
      "Plätze gesamt",
      "Belegt",
      "Frei",
      "Kosten je Platz",
      "Währung",
      "Erneuerungsdatum",
      "Erneuerungsstatus",
      "Beschreibung",
    ],
  ];
  for (const license of licenses)
    rows.push([
      license.name,
      license.vendor,
      license.category,
      license.license_type,
      license.inventory_details?.reference,
      license.inventory_details?.orderReference,
      license.inventory_details?.supplier,
      license.inventory_details?.receivedDate,
      license.total_seats === 0 ? "Unbegrenzt" : license.total_seats,
      license.used_seats,
      license.total_seats === 0
        ? "Unbegrenzt"
        : Math.max(0, license.total_seats - license.used_seats),
      license.cost_per_seat,
      license.currency || "CHF",
      license.renewal_date?.slice(0, 10),
      RENEWAL_LABELS[renewalStatus(license.renewal_date, now)],
      license.description,
    ]);
  return (
    "\uFEFF" + rows.map((row) => row.map(cell).join(";")).join("\r\n") + "\r\n"
  );
}
