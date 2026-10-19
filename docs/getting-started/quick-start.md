# Quick Start

Get OpenDirectory running and perform the most common first-time tasks in under 10 minutes.

## Step 1: Start with Docker Compose

If you have not already installed OpenDirectory, follow the [Installation guide](installation.md). The shortest path is:

```bash
git clone https://github.com/Chregu12/OpenDirectory
cd OpenDirectory
cp .env.example .env
# Edit .env: set DB_PASSWORD, JWT_SECRET, ENCRYPTION_KEY, ADMIN_PASSWORD (and others marked as required)
docker compose up -d
```

Wait for all containers to report healthy:

```bash
docker compose ps
```

---

## Step 2: Open the UI

Navigate to **http://localhost:3000** in your browser.

You will see the OpenDirectory login screen. Log in with:

| Field | Value |
|---|---|
| Username | The `ADMIN_USERNAME` value from your `.env` (default: `admin`) |
| Password | The `ADMIN_PASSWORD` value you set in `.env` |

After login you land on the **Dashboard** — the Apple Business Manager-style three-column layout. The left sidebar shows the main navigation sections: Devices, Directory, Policy, Security, and Settings.

---

## Step 3: Enroll Your First Device

1. In the left sidebar, click **Devices**.
2. Click the **Enroll Device** button in the top-right of the device list panel.
3. The **Enrollment Wizard** opens. Select your device operating system:
   - **Windows** — Generates a WinRM configuration command to run on the device
   - **macOS** — Generates an APNS enrollment profile
   - **Linux** — Generates an SSSD configuration file for domain join
   - **iOS** — Displays a QR code that opens the mobile enrollment flow
   - **Android** — Displays a QR code with an MDM provisioning payload
4. Complete the 4 steps: choose OS → enter device details (hostname, serial number) → review enrollment method → confirm.
5. After confirming, apply the generated command or profile on the target device.
6. Return to the device list. The device appears with status **Pending** and transitions to **Enrolled** once it checks in.

Once enrolled, the device appears in the fleet view with its compliance status and last-seen timestamp.

---

## Step 4: Create Your First Service Principal

A service principal is an application identity with a Client ID, Client Secret, and a Kerberos SPN. Use it to give scripts, CI/CD pipelines, or third-party tools authenticated access to the OpenDirectory API.

1. In the sidebar, click **Directory** then **Service Principals**.
2. Click **Create Service Principal**.
3. The **Service Principal Wizard** opens:
   - Enter a name (e.g. `ci-pipeline` or `monitoring-bot`)
   - Select the permission scopes the principal needs (read-only, device management, directory write, etc.)
   - Click **Create**
4. The wizard returns:
   - **Client ID** — a UUID; safe to store in plain text
   - **Client Secret** — shown once; copy it now
   - **Download `.env`** — click to download a ready-made `.env` snippet for the principal
5. Click **Done**.

Use the credentials in API calls:

```bash
# Get a bearer token
curl -X POST http://localhost:8080/api/auth/service-principal/token \
  -H 'Content-Type: application/json' \
  -d '{"clientId":"<id>","clientSecret":"<secret>"}'

# Use the token
curl http://localhost:8080/api/devices \
  -H 'Authorization: Bearer <token>'
```

---

## Step 5: Set Up PIM for a Privileged Role

Privileged Identity Management (PIM) gives users time-limited access to sensitive roles instead of permanent membership.

1. In the sidebar, click **Security** then **Privileged Access (PIM)**.
2. Click the **Roles** tab.
3. Click **Create Role**.
4. Fill in:
   - **Name** — e.g. `Domain Admins (JIT)`
   - **AD Group** — the Active Directory group whose membership is managed by this role
   - **Max Duration** — maximum elevation duration (e.g. `4h`)
   - **Approvers** — select one or more users who must approve requests
   - **Risk Threshold** — requests scoring above this threshold require additional approval tiers
5. Click **Save**.

To test the flow:
1. Click **Request Access** and select the new role.
2. Enter a business justification and requested duration.
3. Log in as an approver and approve the request from the **Requests** tab.
4. Return to **Active Elevations** — the requesting user now has temporary group membership, visible with an expiry timer.

Session activities during the elevation window are recorded and viewable via **Session Replay** after the elevation expires or is revoked.

---

## Next Steps

| Task | Guide |
|---|---|
| Configure your Active Directory domain and OU structure | [Active Directory & Identity](../features/active-directory.md) |
| Deploy a Group Policy Object | [Group Policy](../features/group-policy.md) |
| Set up Conditional Access policies | [Security & Compliance](../features/security-compliance.md) |
| Configure MFA for all users | [Authentication & SSO](../features/authentication-sso.md) |
| Production Kubernetes deployment | [Kubernetes / Helm](../deployment/kubernetes.md) |
| Full environment variable reference | [Environment Variables](../deployment/environment-variables.md) |
