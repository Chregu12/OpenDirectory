# UI Overview

OpenDirectory's web interface is a Next.js 14 / React 18 / TypeScript single-page application that closely follows the visual language of Apple Business Manager. It runs at `http://localhost:3000` in development.

## Technology stack

| Layer | Choice |
|---|---|
| Framework | Next.js 14 (App Router) |
| UI library | React 18 |
| Language | TypeScript |
| Styling | Inline CSS only — no Tailwind, no CSS-in-JS library, no component library |
| Icons | Emoji (no SVG icon library beyond `@heroicons/react` for a small number of structural icons) |

## Layout system

The shell uses an Apple Business Manager-inspired 3-column layout. Three variants are used depending on the active view:

### 3-column layout (sidebar + list + detail)

Used by: **Devices** (fleet), **Service Principals**, **Users**

```
┌──────────────────────────────────────────────────────┐
│  Sidebar (200px)  │  List column (300px)  │  Detail  │
│                   │                        │  (flex-1)│
└──────────────────────────────────────────────────────┘
```

The list column (`showListColumn` prop on `ABMShell`) renders a scrollable item list. Selecting a row populates the detail panel on the right. When no item is selected the detail panel shows a neutral empty state.

### Full-width layout

Used by: Compliance, Audit Log, Privileged Access (PIM), Policies, Group Policy, Trust Management, Kerberos Admin, Replication, and most other views.

```
┌──────────────────────────────────────────────────────┐
│  Sidebar (200px)  │  Main content area (flex-1)      │
└──────────────────────────────────────────────────────┘
```

## Colour palette

| Token | Hex | Usage |
|---|---|---|
| Selected blue | `#0071e3` | Active nav pill, primary buttons, progress indicators |
| Sidebar background | `#f5f5f7` | Sidebar fill |
| Borders | `#e5e5ea` | Dividers, card outlines, list item separators |
| Section headers | `#86868b` | Section labels inside the sidebar |
| Text (primary) | `#1d1d1f` | Body text |
| Text (secondary) | `#6e6e73` | Metadata, labels |

## Navigation sidebar

The sidebar (`Sidebar.tsx`) is 200 px wide. Navigation items are grouped into sections separated by horizontal dividers. The active item is highlighted with a blue pill (background `#0071e3`, white text). Items that have a list column carry `hasList: true` in the nav definition.

### Module gating

Some nav items are only rendered if the corresponding module is enabled in the server-side subscription. Items without a required module are always shown.

| Nav item | Required module |
|---|---|
| Monitoring | `monitoring-analytics` |
| Secrets | `secrets-management` |
| Devices / Printers | `device-management` |
| Infrastructure | `network-infrastructure` |
| Security | `security-suite` |

## Full navigation map

The sidebar is defined in `frontend/web-app/src/components/layout/Sidebar.tsx`. Current sections and items:

**Home**
- Dashboard, Subscription, Activity, Locations

**Identity**
- Users, User Groups, Roles, Privileges, Privileged Access (PIM), MFA / 2FA, Password Reset, Identity Provider, Directory Sync

**Devices**
- Devices, Enrollment, Assignment History, Blueprints, Antivirus, Printers

**Applications**
- Service Principals, Apps and Books, App Store, License Kiosk, Applications

**Compliance & Security**
- Compliance, Conditional Access, Certificates / PKI, Security Scanner, Security, Secrets

**Policy & Operations**
- Group Policy, Policies, Audit Log, Monitoring, Alerts, Service Health, Backup & DR, Network, Infrastructure, RADIUS / 802.1X, Forest & Trusts, Kerberos Admin, Replication

**Platform**
- Integrations, Roadmap, Settings

## Code style conventions

- All layout is inline CSS. Do not introduce a CSS file or className-based styling.
- Use emoji for icons (see `NAV_ITEMS` in `Sidebar.tsx` for the established set).
- No external UI component libraries (no MUI, no shadcn, no Radix).
- Components are colocated under `src/components/views/` (full-width) or alongside their shell (list+detail split).
