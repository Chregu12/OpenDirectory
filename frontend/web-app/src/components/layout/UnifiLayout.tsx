"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { logout } from "@/lib/auth";
import { NAVIGATION_GROUPS, VIEW_BY_ID, visibleViews } from "@/lib/views";
import {
  MAIN_SECTIONS,
  sectionFor,
  MainSectionId,
} from "@/lib/navigationSections";
import type { DirectoryAccess } from "@/lib/directoryUsers";
import GlobalSearch from "./GlobalSearch";
import { Dialog } from "@headlessui/react";
import { directoryUsers } from "@/lib/directoryUsers";
import ThemeSelector from "./ThemeSelector";
import toast, { Toaster } from "react-hot-toast";
import {
  BellIcon,
  Bars3Icon,
  XMarkIcon,
  ChevronDownIcon,
} from "@heroicons/react/24/outline";

// ─── Notifications ────────────────────────────────────────────────────────────
interface Notification {
  id: string;
  title: string;
  message?: string;
  time: string;
  read: boolean;
  type: "enrollment" | "compliance" | "pim" | "security" | "warning" | "info";
}

const NOTIF_COLOR: Record<Notification["type"], string> = {
  enrollment: "bg-blue-400",
  compliance: "bg-orange-400",
  pim: "bg-purple-400",
  security: "bg-red-500",
  warning: "bg-orange-400",
  info: "bg-blue-400",
};

interface LayoutProps {
  children: React.ReactNode;
  activeView: string;
  onViewChange: (view: string) => void;
  enabledModules?: string[];
  currentUser?: {
    id?: string;
    name: string;
    role: string;
    roles?: string[];
  } | null;
}

// Get user initials from name
function getInitials(name: string): string {
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2)
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

export default function UnifiLayout({
  children,
  activeView,
  onViewChange,
  enabledModules,
  currentUser,
}: LayoutProps) {
  const router = useRouter();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [accessError, setAccessError] = useState(false);
  const [access, setAccess] = useState<DirectoryAccess | null>(null);
  const [configuredServices, setConfiguredServices] = useState<string[] | null>(
    [],
  );
  useEffect(() => {
    let active = true;
    setAccess(null);
    setAccessError(false);
    const invalid = () => {
      active = false;
      setAccess(null);
      setAccessError(true);
    };
    const refresh = () =>
      directoryUsers
        .access()
        .then((result) => {
          if (active) {
            setAccess(result);
            setAccessError(false);
          }
        })
        .catch(() => {
          if (active) {
            setAccess(null);
            setAccessError(true);
          }
        });
    window.addEventListener("od:session-error", invalid);
    api
      .get("/api/platform/capabilities")
      .then((response) => {
        if (
          response.data.configuredServices !== null &&
          (!Array.isArray(response.data.configuredServices) ||
            response.data.configuredServices.some(
              (item: unknown) => typeof item !== "string",
            ))
        )
          throw new Error("Invalid configuration");
        if (active) setConfiguredServices(response.data.configuredServices);
      })
      .catch(() => {
        if (active) setConfiguredServices([]);
      });
    void refresh();
    const timer = window.setInterval(refresh, 30000);
    return () => {
      active = false;
      window.clearInterval(timer);
      window.removeEventListener("od:session-error", invalid);
    };
  }, [currentUser?.id, currentUser?.role, currentUser?.roles?.join(",")]);
  const [notifOpen, setNotifOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [notificationState, setNotificationState] = useState<
    "loading" | "available" | "failed"
  >("loading");
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const notifRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  const unreadCount = notifications.filter((n) => !n.read).length;

  // Load real alerts from backend services
  useEffect(() => {
    if (!currentUser) return;

    let active = true;
    const loadAlerts = async () => {
      const alerts: Notification[] = [];
      let verifiedHistory = false;

      // Fetch escalation alerts from least-privilege service
      try {
        const configured = (await api.get("/api/platform/capabilities")).data
          .configuredServices;
        if (configured !== null && !configured.includes("least-privilege"))
          throw new Error("Extension not configured");
        const res = await api.get("/api/permissions/escalation-alerts");
        const data = Array.isArray(res.data) ? res.data : [];
        for (const a of data.slice(0, 3)) {
          alerts.push({
            id: `esc-${a.id ?? a.userId}`,
            title: "Privilege Escalation",
            message: `Benutzer ${a.user_id ?? a.userId} hat Admin-Rechte auf ${a.admin_count} Ressourcen`,
            type: "warning" as const,
            time: a.detected_at
              ? new Date(a.detected_at).toLocaleString("de-CH")
              : "Gerade eben",
            read: false,
          });
        }
      } catch {}

      // Fetch recent audit events from auth service
      try {
        const res = await api.get("/api/auth/audit/login-history?limit=5");
        if (!Array.isArray(res.data.history))
          throw new Error("Invalid history");
        const events = res.data.history;
        verifiedHistory = true;
        for (const e of events
          .filter(
            (ev: any) =>
              ev.severity === "warning" || ev.event_type === "login_failed",
          )
          .slice(0, 2)) {
          alerts.push({
            id: `audit-${e.id}`,
            title:
              e.event_type === "login_failed"
                ? "Anmeldung fehlgeschlagen"
                : "Sicherheitsereignis",
            message: e.message,
            type: "warning" as const,
            time: new Date(e.created_at).toLocaleString("de-CH"),
            read: false,
          });
        }
      } catch {}

      if (active) {
        setNotificationState(verifiedHistory ? "available" : "failed");
        setNotifications((previous) =>
          alerts.map((alert) => ({
            ...alert,
            read: previous.find((item) => item.id === alert.id)?.read ?? false,
          })),
        );
      }
    };

    loadAlerts();
    const interval = setInterval(loadAlerts, 30000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [currentUser]);

  useEffect(() => {
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setNotifOpen(false);
        setUserMenuOpen(false);
      }
    };
    window.addEventListener("keydown", escape);
    return () => window.removeEventListener("keydown", escape);
  }, []);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false);
      }
      if (
        userMenuRef.current &&
        !userMenuRef.current.contains(e.target as Node)
      ) {
        setUserMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const markAllRead = () =>
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));

  const handleLogout = async () => {
    try {
      await logout();
      router.replace("/login");
    } catch {
      toast.error("Abmeldung nicht bestätigt. Bitte erneut versuchen.");
    }
  };

  const navigationItems = React.useMemo(
    () =>
      visibleViews({
        access,
        roles: currentUser?.roles || (currentUser ? [currentUser.role] : []),
        platformAdmin: (currentUser?.roles || [currentUser?.role]).includes(
          "admin",
        ),
        enabledModules,
        configuredServices,
      }),
    [access, currentUser, enabledModules, configuredServices],
  );
  const navigationActive = VIEW_BY_ID[activeView]?.canonical || activeView;
  const routeSection = VIEW_BY_ID[navigationActive]
    ? sectionFor(VIEW_BY_ID[navigationActive])
    : "home";
  const [selectedSection, setSelectedSection] =
    useState<MainSectionId>(routeSection);
  const lastViewed = useRef<Partial<Record<MainSectionId, string>>>({});
  useEffect(() => {
    setSelectedSection(routeSection);
    lastViewed.current[routeSection] = navigationActive;
  }, [routeSection, navigationActive]);
  const sections = MAIN_SECTIONS.map((section) => ({
    ...section,
    items: navigationItems.filter((view) => sectionFor(view) === section.id),
  })).filter((section) => section.items.length > 0);
  const currentSection =
    sections.find((section) => section.id === selectedSection) || sections[0];
  const sectionItems = currentSection?.items || [];
  const groupLabel = (view: (typeof navigationItems)[number]) =>
    ["mfa", "sspr"].includes(view.id) ? "Mein Zugang" : view.group;
  const navigationGroups = [...NAVIGATION_GROUPS, "Mein Zugang"].map(
    (label) => ({
      label,
      items: sectionItems.filter((item) => groupLabel(item) === label),
    }),
  );
  const chooseSection = (section: (typeof sections)[number]) => {
    setSelectedSection(section.id);
    setSidebarOpen(false);
    const remembered = lastViewed.current[section.id];
    const target =
      section.items.find((item) => item.id === remembered)?.id ||
      section.items.find((item) => item.id === section.primary)?.id ||
      section.items[0].id;
    if (target !== navigationActive) onViewChange(target);
  };

  const userInitials = currentUser?.name ? getInitials(currentUser.name) : "OD";

  // Sidebar content — shared between desktop and mobile overlay
  const sidebarContent = (
    <div className="flex flex-col h-full">
      <div className="od-section-heading">
        <h2>{currentSection?.label || "Home"}</h2>
        <p>
          {access?.companyOwner
            ? "Eigene Firma"
            : (currentUser?.roles || [currentUser?.role]).includes("admin")
              ? "Plattformverwaltung"
              : "Persönlicher Arbeitsbereich"}
        </p>
        <button
          onClick={() => setSidebarOpen(false)}
          aria-label="Navigation schliessen"
          className="lg:hidden"
        >
          <XMarkIcon className="h-5 w-5" />
        </button>
      </div>

      {/* Navigation */}
      <nav
        aria-label="Bereichsnavigation"
        style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}
      >
        {accessError && (
          <p role="status" className="p-4 text-sm">
            Aufgabenberechtigungen nicht bestätigt. Wird erneut geprüft.
          </p>
        )}
        {navigationGroups
          .filter((group) => group.items.length)
          .map((group) => (
            <details
              key={group.label}
              className="group"
              open={
                navigationGroups.filter((item) => item.items.length).length ===
                  1 || group.items.some((item) => item.id === navigationActive)
              }
            >
              <summary
                className="list-none [&::-webkit-details-marker]:hidden flex items-center justify-between"
                style={{
                  padding: "8px 12px 4px",
                  fontSize: 12,
                  fontWeight: 600,
                  color: "var(--text-secondary)",
                  cursor: "pointer",
                }}
              >
                {group.label}
                <ChevronDownIcon className="h-4 w-4 transition-transform group-open:rotate-180" />
              </summary>
              {group.items.map((item) => {
                const isActive = navigationActive === item.id;
                return (
                  <button
                    key={item.id}
                    aria-current={isActive ? "page" : undefined}
                    onClick={() => {
                      onViewChange(item.id);
                      setSidebarOpen(false);
                    }}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      width: "calc(100% - 16px)",
                      margin: "1px 8px",
                      padding: "6px 10px",
                      fontSize: 13,
                      fontWeight: isActive ? 600 : 400,
                      textAlign: "left",
                      background: isActive ? "var(--accent)" : "transparent",
                      color: isActive ? "#ffffff" : "var(--text-secondary)",
                      border: "none",
                      borderRadius: 4,
                      cursor: "pointer",
                      transition: "background 0.15s, color 0.15s",
                      whiteSpace: "normal",
                      overflowWrap: "anywhere",
                    }}
                    onMouseEnter={(e) => {
                      if (!isActive) {
                        (
                          e.currentTarget as HTMLButtonElement
                        ).style.background = "var(--bg-sidebar-hover)";
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive) {
                        (
                          e.currentTarget as HTMLButtonElement
                        ).style.background = "transparent";
                      }
                    }}
                  >
                    <item.icon
                      style={{
                        width: 16,
                        height: 16,
                        flexShrink: 0,
                        color: isActive ? "#ffffff" : "var(--text-secondary)",
                      }}
                    />
                    {item.name}
                  </button>
                );
              })}
            </details>
          ))}
      </nav>
    </div>
  );

  return (
    <div className="od-app-frame">
      <a href="#main-content" className="od-skip-link">
        Zum Inhalt springen
      </a>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: "var(--bg-surface-raised)",
            color: "var(--text-primary)",
            borderRadius: "10px",
            fontSize: 13,
          },
        }}
      />

      <header className="od-app-topbar">
        <div className="od-app-brand">
          <button
            className="lg:hidden"
            aria-label="Navigation öffnen"
            aria-expanded={sidebarOpen}
            onClick={() => setSidebarOpen(true)}
          >
            <Bars3Icon className="h-5 w-5" />
          </button>
          <span className="od-brand-mark" aria-hidden="true">
            OD
          </span>
          <span>OpenDirectory</span>
        </div>
        <nav className="od-main-sections" aria-label="Hauptbereiche">
          {sections.map((section) => (
            <button
              key={section.id}
              aria-current={
                currentSection?.id === section.id ? "true" : undefined
              }
              onClick={() => chooseSection(section)}
            >
              {section.label}
            </button>
          ))}
        </nav>
        <div className="od-app-tools">
          <div className="od-header-search">
            <GlobalSearch views={navigationItems} />
          </div>
          {/* Right actions */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexShrink: 0,
            }}
          >
            <ThemeSelector />
            {/* Bell */}
            <div ref={notifRef} style={{ position: "relative" }}>
              <button
                aria-label="Benachrichtigungen"
                aria-expanded={notifOpen}
                onClick={() => {
                  setNotifOpen((o) => !o);
                  setUserMenuOpen(false);
                }}
                style={{
                  position: "relative",
                  background: "transparent",
                  border: "none",
                  cursor: "pointer",
                  padding: 6,
                  color: "var(--text-secondary)",
                  borderRadius: 8,
                  display: "flex",
                  alignItems: "center",
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLButtonElement).style.background =
                    "var(--bg-surface-raised)";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLButtonElement).style.background =
                    "transparent";
                }}
              >
                <BellIcon style={{ width: 20, height: 20 }} />
                {unreadCount > 0 && (
                  <span
                    style={{
                      position: "absolute",
                      top: 2,
                      right: 2,
                      width: 16,
                      height: 16,
                      background: "#FF3B30",
                      color: "white",
                      fontSize: 10,
                      fontWeight: 600,
                      borderRadius: "50%",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    {unreadCount}
                  </span>
                )}
              </button>

              {/* Notification dropdown */}
              {notifOpen && (
                <div
                  style={{
                    position: "absolute",
                    top: "calc(100% + 8px)",
                    right: 0,
                    width: "min(320px, calc(100vw - 32px))",
                    background: "var(--bg-surface)",
                    borderRadius: 12,
                    border: "1px solid var(--border-strong)",
                    boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
                    zIndex: 100,
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "12px 16px",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    <span
                      style={{
                        fontSize: 13,
                        fontWeight: 600,
                        color: "var(--text-primary)",
                      }}
                    >
                      Benachrichtigungen
                    </span>
                    <button
                      onClick={markAllRead}
                      style={{
                        fontSize: 12,
                        color: "var(--accent)",
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                      }}
                    >
                      Alle gelesen
                    </button>
                  </div>
                  <div style={{ maxHeight: 320, overflowY: "auto" }}>
                    {(notificationState !== "available" ||
                      !notifications.length) && (
                      <p
                        role="status"
                        className="p-4 text-sm"
                        style={{ color: "var(--text-secondary)" }}
                      >
                        {notificationState === "failed"
                          ? "Anmeldehistorie nicht verfügbar. Der Systemzustand ist damit nicht bestätigt."
                          : notificationState === "loading"
                            ? "Anmeldehistorie wird geprüft …"
                            : "Keine Warnungen in der zuletzt geladenen eigenen Anmeldehistorie."}
                      </p>
                    )}
                    {notifications.map((n) => (
                      <div
                        key={n.id}
                        style={{
                          display: "flex",
                          alignItems: "flex-start",
                          gap: 10,
                          padding: "10px 16px",
                          background: !n.read ? "#EAF4FF40" : "transparent",
                          borderBottom: "1px solid var(--apple-gray-1)",
                        }}
                      >
                        <span
                          className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${NOTIF_COLOR[n.type]}`}
                          style={{ flexShrink: 0, marginTop: 5 }}
                        />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <p
                            style={{
                              fontSize: 12,
                              color: "var(--text-primary)",
                              lineHeight: 1.4,
                            }}
                          >
                            {n.title}
                          </p>
                          {n.message && (
                            <p
                              style={{
                                fontSize: 11,
                                color: "var(--text-secondary)",
                                marginTop: 2,
                                lineHeight: 1.4,
                              }}
                            >
                              {n.message}
                            </p>
                          )}
                          <p
                            style={{
                              fontSize: 11,
                              color: "var(--text-muted)",
                              marginTop: 2,
                            }}
                          >
                            {n.time}
                          </p>
                        </div>
                        {!n.read && (
                          <span
                            style={{
                              width: 6,
                              height: 6,
                              borderRadius: "50%",
                              background: "var(--accent)",
                              flexShrink: 0,
                              marginTop: 5,
                            }}
                          />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* User avatar + dropdown */}
            <div ref={userMenuRef} style={{ position: "relative" }}>
              <button
                onClick={() => {
                  setUserMenuOpen((o) => !o);
                  setNotifOpen(false);
                }}
                aria-label="Benutzermenü"
                aria-expanded={userMenuOpen}
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: "50%",
                  background: "var(--accent)",
                  color: "#ffffff",
                  fontSize: 12,
                  fontWeight: 600,
                  border: "none",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                }}
              >
                {userInitials}
              </button>

              {/* User dropdown */}
              {userMenuOpen && (
                <div
                  style={{
                    position: "absolute",
                    top: "calc(100% + 8px)",
                    right: 0,
                    width: 200,
                    background: "var(--bg-surface)",
                    borderRadius: 12,
                    border: "1px solid var(--border-strong)",
                    boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
                    zIndex: 100,
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      padding: "12px 16px",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    <p
                      style={{
                        fontSize: 13,
                        fontWeight: 600,
                        color: "var(--text-primary)",
                      }}
                    >
                      {currentUser?.name ?? "—"}
                    </p>
                    <p
                      style={{
                        fontSize: 12,
                        color: "var(--text-secondary)",
                        marginTop: 2,
                      }}
                    >
                      {currentUser?.role ?? ""}
                    </p>
                  </div>
                  <button
                    onClick={handleLogout}
                    style={{
                      display: "block",
                      width: "100%",
                      padding: "10px 16px",
                      fontSize: 13,
                      color: "var(--danger)",
                      background: "none",
                      border: "none",
                      textAlign: "left",
                      cursor: "pointer",
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLButtonElement).style.background =
                        "var(--bg-surface-raised)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLButtonElement).style.background =
                        "none";
                    }}
                  >
                    Abmelden
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>
      <div className="od-app-body">
        <aside className="od-app-sidebar hidden lg:flex">
          {sidebarContent}
        </aside>
        <Dialog
          open={sidebarOpen}
          onClose={setSidebarOpen}
          className="relative z-[70] lg:hidden"
        >
          <div className="fixed inset-0 bg-black/60" aria-hidden="true" />
          <Dialog.Panel
            className="fixed inset-y-0 left-0"
            style={{
              width: "min(var(--sidebar-width), 90vw)",
              background: "var(--bg-sidebar)",
            }}
          >
            <Dialog.Title className="sr-only">Hauptnavigation</Dialog.Title>
            {sidebarContent}
          </Dialog.Panel>
        </Dialog>

        <main
          id="main-content"
          tabIndex={-1}
          className="od-main"
          style={{
            flex: 1,
            minHeight: 0,
            overflowY: "auto",
            background: "var(--bg-base)",
          }}
        >
          {children}
        </main>
      </div>
    </div>
  );
}
