# Privileged Identity Management (PIM) View

The PIM view is full-width and provides a single place to manage time-bound privilege elevation, review pending requests, monitor active sessions, and handle break-glass emergencies. It maps to the `conditional-access` service on the backend.

## Accessing the view

Click **Privileged Access** (🛡) in the sidebar.

## Tabs

### Roles

Lists all PIM roles defined in the system. Built-in roles:

- `domain-admin` — full domain administrative rights
- `server-admin` — elevated rights on server OUs
- Custom roles — defined by administrators

For each role you can configure:
- Maximum elevation duration
- Number of required approvals (1 or 2)
- Justification required (yes / no)
- Allowed users / groups

### Requests

Shows all pending elevation requests waiting for approval. Each entry displays the requesting user, the role requested, the justification, and the time the request was submitted.

**To approve or deny a request:**
1. Click the request row.
2. Read the justification.
3. Click **Approve** or **Deny**.
4. If the role requires 2 approvals, the request remains in a "1/2 approvals" state until a second approver acts on it.

### Active

Lists all currently active privilege elevations. Each row shows:

| Column | Description |
|---|---|
| User | The elevated user |
| Role | The role granted |
| Started | Elevation start time |
| Expires | Scheduled expiry time |
| Risk score | Live risk score (0.0 – 1.0), updated as the user performs actions |

The **Revoke** button immediately terminates the elevation, removes the user from the corresponding AD group, and fires `security.elevation.revoked` on the event bus.

### Sessions

Archive of completed and terminated privileged sessions. Click any session row to open the session replay view.

**Session replay timeline:**

Each activity in the session is listed chronologically:

| Column | Description |
|---|---|
| Timestamp | When the action occurred |
| Type | Action category (e.g. `ldap.write`, `gpo.modify`, `ssh.command`) |
| Details | Action description |
| Risk score | Risk contribution of this individual action |

Entries with a risk score above 0.7 are highlighted in red and are flagged for security review.

### Break-Glass

Shows all emergency access events, both active and historical.

## Requesting elevation (end-user flow)

1. Click **Request Access**.
2. Select the role you need from the dropdown.
3. Enter a justification explaining why elevated access is needed and for how long.
4. Click **Submit**.

The request appears in the **Requests** tab for approvers. You will receive a notification when it is approved or denied.

## Approving a request (approver flow)

1. Open the **Requests** tab.
2. Click the pending request.
3. Review the justification and the requested role.
4. Click **Approve** or **Deny**.

For roles configured with multi-level approval (2 approvers required), both approvers must act before the elevation activates. The request shows `Approvals: 1/2` after the first approval.

## Revoking an active elevation

1. Open the **Active** tab.
2. Find the elevation you want to terminate.
3. Click **Revoke**.

Revocation is immediate. The event `security.elevation.revoked` is published and the audit service records the action.

## Break-glass emergency access

Break-glass is for situations where normal approval workflows cannot be completed in time (e.g. an on-call engineer locked out during an incident).

**To activate break-glass:**
1. Click **Request Emergency Access** (shown on the Break-Glass tab).
2. Fill in:
   - **Reason** — describe the incident or emergency
   - **Affected systems** — list the systems requiring access
   - **Estimated duration** — maximum 4 hours
3. Click **Request**.

A second manager or security officer must confirm the activation before access is granted. This two-person rule prevents unilateral break-glass abuse.

Every action performed during a break-glass session is recorded with elevated audit detail. The session appears in the Break-Glass tab and fires `security.breakglass.activated` / `security.breakglass.terminated` events.
