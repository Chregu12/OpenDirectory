# Service Principals View

Service Principals are machine identities used by applications and automation scripts to authenticate against OpenDirectory APIs. The view uses the 3-column layout: sidebar, principal list (300 px), and detail panel.

## Accessing the view

Click **Service Principals** (🔑) in the sidebar.

## List column

Each row in the list shows:

- 🔑 key icon
- Application name
- Truncated Client ID (first 8 characters + `…`)

Type in the search field to filter by application name.

## Creating a service principal

1. Click **+ Service Principal** in the Quick Actions Bar.
2. Fill in the creation form:
   - **App Name** (required) — human-readable name for the application
   - **Description** (optional)
   - **Permissions** — select the required permission scopes via checkboxes
3. Click **Create**.

### Credentials screen (shown once)

Immediately after creation, the credentials screen is displayed. This is the **only time** the client secret is available in full.

| Field | Controls |
|---|---|
| Client ID | Copy button |
| Client Secret | Masked by default; reveal toggle; copy button |
| .env snippet | Download button — generates a ready-to-paste `.env` fragment |

> **Warning:** The client secret cannot be retrieved again after you leave this screen. Save it to a password manager or secrets vault now.

## Managing an existing principal

Select a principal from the list to open its detail panel:

- **Full details** — permissions list, Service Principal Name (SPN), status (active / disabled)
- **Rotate Secret** — generates a new client secret. The old secret is **invalidated immediately** when you confirm. A new credentials screen is shown.
- **Disable / Enable** — toggles the principal without deleting it. Disabled principals cannot authenticate.
- **Delete** — permanently removes the principal from AD, Kerberos, and the auth service. This action cannot be undone.

## Using a service principal from code

Exchange the client ID and secret for a short-lived access token from the authentication service, then include the token as a `Bearer` header on subsequent API calls.

```python
import requests

resp = requests.post(
    'http://authentication-service:3001/api/auth/token',
    json={
        'clientId': 'your-client-id',
        'clientSecret': 'your-client-secret',
        'grantType': 'client_credentials',
    }
)
token = resp.json()['accessToken']

# Use the token
headers = {'Authorization': f'Bearer {token}'}
devices = requests.get('http://device-service:3003/api/devices', headers=headers).json()
```

In local development replace the hostnames with `localhost` and the appropriate port numbers (see the [port reference in contributing.md](../development/contributing.md)).
