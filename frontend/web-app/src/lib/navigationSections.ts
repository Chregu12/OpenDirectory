import type { ViewDefinition } from "./views";
export const MAIN_SECTIONS = [
  { id: "home", label: "Home", primary: "dashboard" },
  { id: "people", label: "People", primary: "users" },
  { id: "devices", label: "Devices", primary: "devices" },
  { id: "apps", label: "Apps & Services", primary: "licenses" },
  { id: "automation", label: "Automationen", primary: "integrations" },
  { id: "administration", label: "Administration", primary: "servicehealth" },
] as const;
export type MainSectionId = (typeof MAIN_SECTIONS)[number]["id"];
export function sectionFor(
  view: Pick<ViewDefinition, "id" | "group">,
): MainSectionId {
  if (["dashboard", "mfa", "sspr"].includes(view.id)) return "home";
  if (view.group === "Unternehmen & Personen") return "people";
  if (view.group === "Geräte" || view.group === "Blueprints") return "devices";
  if (view.group === "Apps & Lizenzen") return "apps";
  if (view.group === "Automatisierung & Integrationen") return "automation";
  return "administration";
}
