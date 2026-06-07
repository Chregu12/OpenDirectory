# Device Fleet View

The Device Fleet view (`DeviceFleetView.tsx`) is a 3-column layout: sidebar, device list (300 px), and detail panel. It gives administrators a full picture of every managed device and direct access to remediation actions.

## Accessing the view

Click **Devices** (💻) in the sidebar. The list column loads immediately; the detail panel is blank until you select a device.

## OS summary cards

Across the top of the list column, a row of OS summary cards shows the total device count and compliance status breakdown for each operating system (macOS, Windows, Linux, iOS, Android). Click a card to filter the device list to that OS only. Click again to clear the filter.

## Device list

The list column is scrollable and shows one row per device. Each row displays:

- OS icon (emoji)
- Device name (hostname)
- MDM server name · serial number (secondary line, `#86868b`)

The selected row receives a blue background pill (`#0071e3`).

## Searching and filtering

Type in the search field at the top of the list column to filter by device name, serial number, or assigned user. The filter is applied client-side and updates instantly.

## Sorting

Use the sort control above the list to order by:

- Name (A → Z / Z → A)
- Serial number
- Date added (newest first / oldest first)
- Compliance status

## Compliance status pills

Each device row carries a compliance pill:

| Colour | Meaning |
|---|---|
| Green | Compliant — all policies satisfied |
| Yellow / amber | Warning — non-critical policy drift detected |
| Red | Non-compliant — one or more enforced policies violated |

## Selecting a device

Click any row to load its details in the right-hand detail panel. The panel is divided into collapsible sections:

### Overview
- MDM server name
- Model (e.g. "MacBook Pro 14-inch, 2023")
- Serial number

### Details
- Source (ABM / manual enrollment / DEP)
- Order number (if ABM-sourced)
- Storage (disk capacity)

### Activity
- Date added
- Last seen (last check-in timestamp)

### LAPS (Local Administrator Password Solution)
- Reveals the current local admin password on demand (click **Reveal**)
- **Rotate** generates a new password immediately; the old password is invalidated
- Retrieval and rotation events are recorded as `ad.laps.password.retrieved` / `ad.laps.password.rotated` on the event bus

### BitLocker
- Lists all stored recovery key entries for the device
- Click **Retrieve** next to a key to display the full 48-digit recovery key
- Key retrievals are recorded as `ad.bitlocker.key.retrieved`

## Device actions menu

Click the **...** (ellipsis) button on a device row or in the detail panel header to open the actions menu:

| Action | Description |
|---|---|
| View Details | Expands the full detail panel |
| Unenroll | Removes the device from MDM; triggers `device.retired` event |
| Push Policy | Immediately pushes the assigned policy profile to the device |
| Remote Lock | Sends a lock command via the MDM channel |

## Enrolling a new device

Click **+ Enroll Device** in the Quick Actions Bar at the top of the page. This opens the Enrollment Wizard — see [Enrollment Wizard Guide](./enrollment.md) for step-by-step instructions.
