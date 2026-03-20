"""
OpenDirectory API Client
Shared module utility for all OpenDirectory Ansible modules.
"""

import json
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode


class OpenDirectoryAPIError(Exception):
    """Exception raised for OpenDirectory API errors."""
    def __init__(self, message, status_code=None, response=None):
        self.status_code = status_code
        self.response = response
        super().__init__(message)


class OpenDirectoryAPI:
    """REST API client for OpenDirectory platform."""

    def __init__(self, api_url, api_key, timeout=30, verify_ssl=True):
        self.base_url = api_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _request(self, method, path, data=None, params=None):
        """Make an HTTP request to the OpenDirectory API."""
        url = f"{self.base_url}{path}"
        if params:
            url += '?' + urlencode(params)

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'ansible-opendirectory/1.0'
        }

        body = json.dumps(data).encode('utf-8') if data else None
        req = Request(url, data=body, headers=headers, method=method)

        try:
            response = urlopen(req, timeout=self.timeout)
            response_data = response.read().decode('utf-8')
            return json.loads(response_data) if response_data else {}
        except HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else ''
            try:
                error_data = json.loads(error_body)
                msg = error_data.get('error', error_body)
            except (json.JSONDecodeError, ValueError):
                msg = error_body or str(e)
            raise OpenDirectoryAPIError(msg, status_code=e.code, response=error_body)
        except URLError as e:
            raise OpenDirectoryAPIError(f"Connection error: {e.reason}")

    def get(self, path, params=None):
        return self._request('GET', path, params=params)

    def post(self, path, data=None):
        return self._request('POST', path, data=data)

    def put(self, path, data=None):
        return self._request('PUT', path, data=data)

    def delete(self, path):
        return self._request('DELETE', path)

    # =====================================================
    # Device Management
    # =====================================================

    def get_devices(self, filters=None):
        return self.get('/api/devices', params=filters)

    def get_device(self, device_id):
        return self.get(f'/api/devices/{device_id}')

    def create_device(self, device_data):
        return self.post('/api/devices', data=device_data)

    def update_device(self, device_id, device_data):
        return self.put(f'/api/devices/{device_id}', data=device_data)

    def delete_device(self, device_id):
        return self.delete(f'/api/devices/{device_id}')

    # =====================================================
    # Policy Management
    # =====================================================

    def get_policies(self):
        return self.get('/api/policies')

    def get_policy(self, policy_id):
        return self.get(f'/api/policies/{policy_id}')

    def create_policy(self, policy_data):
        return self.post('/api/policies', data=policy_data)

    def update_policy(self, policy_id, policy_data):
        return self.put(f'/api/policies/{policy_id}', data=policy_data)

    def delete_policy(self, policy_id):
        return self.delete(f'/api/policies/{policy_id}')

    # =====================================================
    # Agent Commands (Update, Network, Compliance)
    # =====================================================

    def configure_updates(self, device_id, policy):
        return self.post('/api/agent/update/configure', data={'deviceId': device_id, 'policy': policy})

    def trigger_update(self, device_id, options=None):
        return self.post('/api/agent/update/trigger', data={'deviceId': device_id, 'options': options or {}})

    def configure_winget(self, device_id, policy):
        return self.post('/api/agent/update/configure-winget', data={'deviceId': device_id, 'policy': policy})

    def configure_wifi(self, device_id, profile):
        return self.post('/api/agent/network/configure-wifi', data={'deviceId': device_id, 'profile': profile})

    def remove_wifi(self, device_id, profile_id, ssid=None):
        return self.post('/api/agent/network/remove-wifi', data={'deviceId': device_id, 'profileId': profile_id, 'ssid': ssid})

    def configure_vpn(self, device_id, profile):
        return self.post('/api/agent/network/configure-vpn', data={'deviceId': device_id, 'profile': profile})

    def remove_vpn(self, device_id, profile_id):
        return self.post('/api/agent/network/remove-vpn', data={'deviceId': device_id, 'profileId': profile_id})

    def configure_email(self, device_id, profile):
        return self.post('/api/agent/network/configure-email', data={'deviceId': device_id, 'profile': profile})

    def remove_email(self, device_id, profile_id):
        return self.post('/api/agent/network/remove-email', data={'deviceId': device_id, 'profileId': profile_id})

    # =====================================================
    # Compliance & Encryption
    # =====================================================

    def check_compliance(self, device_id):
        return self.post('/api/agent/policy/check-device-compliance', data={'deviceId': device_id})

    def check_encryption(self, device_id):
        result = self.get(f'/api/devices/{device_id}')
        return result.get('data', {}).get('encryption', {})

    # =====================================================
    # Backup & DR
    # =====================================================

    def trigger_backup(self, backup_type='incremental'):
        return self.post('/api/backup/trigger', data={'type': backup_type})

    def get_backup_status(self):
        return self.get('/api/backup/status')

    def get_dr_health(self):
        return self.get('/api/dr/health')

    # =====================================================
    # Analytics & Dashboard
    # =====================================================

    def get_threats(self, severity=None, limit=None):
        params = {}
        if severity:
            params['severity'] = severity
        if limit:
            params['limit'] = str(limit)
        return self.get('/api/analytics/threats', params=params)

    def get_dashboard(self):
        return self.get('/api/dashboard')

    # =====================================================
    # Reports
    # =====================================================

    def generate_report(self, template, report_format, params=None):
        return self.post('/api/reports/generate', data={
            'template': template,
            'format': report_format,
            'params': params or {}
        })

    def get_report_templates(self):
        return self.get('/api/reports/templates')
