# Enrollment Wizard

The Enrollment Wizard walks an administrator through registering a new device in OpenDirectory. It is a 4-step modal dialog accessible from any view.

## Opening the wizard

Click **+ Enroll Device** in the Quick Actions Bar at the top of the screen.

## Step 1 — Platform

Select the operating system of the device being enrolled:

| Option | Description |
|---|---|
| 🍎 macOS | Ventura, Sonoma, Sequoia |
| 🪟 Windows | Windows 10/11, Server |
| 🐧 Linux | Ubuntu, Debian, RHEL |
| 📱 iOS | iPhone, iPad (iOS 15+) |
| 🤖 Android | Android 12+ |

Click the platform tile to select it, then click **Next**.

## Step 2 — Details

Fill in the device details:

| Field | Required | Description |
|---|---|---|
| Device Name | Yes | Hostname as it will appear in the directory (e.g. `macbook-alice`) |
| Serial Number | Yes | Manufacturer serial number |
| Assigned User | No | Username of the primary user; links the device to a directory account |

Click **Next**.

## Step 3 — Placement

Choose the Organisational Unit (OU) the device will be placed in. The dropdown shows the available OUs from your Active Directory tree, for example:

- `OU=Workstations,DC=corp,DC=local`
- `OU=Laptops,DC=corp,DC=local`
- `OU=Servers,DC=corp,DC=local`
- `OU=Mobile,DC=corp,DC=local`
- `OU=IOT,DC=corp,DC=local`

Select the appropriate OU for the device type and location, then click **Next**.

## Step 4 — Confirm

Review the enrollment summary:

- Platform
- Device name
- Serial number
- Assigned user (if set)
- Target OU

Click **Enroll** to submit.

## After enrollment

The wizard calls the quick-actions API (`/api/quick-actions/enroll-device`), which in turn calls the device service. On success, the wizard shows the **Enrollment Instructions** screen, which is tailored to the platform selected in Step 1.

### macOS instructions

1. Open **System Settings → Privacy & Security → Profiles**.
2. Click the **+** button and enter the MDM enrollment URL:
   ```
   https://<your-mdm-hostname>/enroll/<enrollment-token>
   ```
3. Follow the on-screen prompts to approve the MDM profile.
4. The device will appear as **Pending** in the Device Fleet view until the MDM check-in completes (typically within 60 seconds).

### Windows instructions

1. Open **Settings → Accounts → Access work or school → Connect**.
2. Select **Join this device to Azure Active Directory** (the OpenDirectory AD endpoint is compatible).
3. Enter your OpenDirectory domain credentials.
4. Alternatively, run the following from an elevated command prompt using the token shown:
   ```
   dsregcmd /join /tenantid <enrollment-token>
   ```

### Linux instructions

1. Install the OpenDirectory agent:
   ```bash
   curl -fsSL https://<your-od-hostname>/install/linux | sudo bash
   ```
2. Run the join command with the enrollment token shown:
   ```bash
   sudo od-agent join --token <enrollment-token> --ou "OU=Workstations,DC=corp,DC=local"
   ```
3. Restart the agent service:
   ```bash
   sudo systemctl restart od-agent
   ```

### iOS instructions

1. Open Safari on the device and navigate to:
   ```
   https://<your-mdm-hostname>/enroll
   ```
2. Tap **Download Profile** and follow the iOS prompts to install the MDM configuration profile.
3. Go to **Settings → General → VPN & Device Management** and tap **Trust** for the OpenDirectory profile.

### Android instructions

1. Open the **OpenDirectory** app from the enterprise app store (or use the QR code shown in the wizard).
2. Enter the enrollment token when prompted.
3. Accept the device management permissions.
4. The device will appear as **Pending** until the first policy sync completes.

## Events published on enrollment

A successful enrollment publishes the following events to the event bus:

- `device.enrolled` — fired by the device service immediately
- `mdm.device.enrolled` — fired by the Apple MDM service for iOS/macOS
- `device.lifecycle.onboarded` — fired by the device-lifecycle service after the initial compliance check

Compliance and policy services subscribe to `device.enrolled` and will evaluate the device against active policies automatically.
