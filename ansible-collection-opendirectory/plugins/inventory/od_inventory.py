#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
OpenDirectory Dynamic Inventory Plugin for Ansible.
Fetches managed devices and groups them by OS, compliance status, and location.
"""

DOCUMENTATION = r'''
---
name: od_inventory
plugin_type: inventory
short_description: OpenDirectory dynamic inventory
description:
    - Fetches devices from OpenDirectory and creates Ansible inventory groups.
    - Groups by platform (windows, macos, linux), compliance status, and custom groups.
version_added: "1.0.0"
author: "OpenDirectory Team"
options:
    api_url:
        description: OpenDirectory API URL
        required: true
        env:
            - name: OD_API_URL
    api_key:
        description: OpenDirectory API key
        required: true
        env:
            - name: OD_API_KEY
    groups_by:
        description: Properties to group hosts by
        type: list
        default: ['platform', 'compliance_status']
'''

EXAMPLES = r'''
# inventory.od_inventory.yml
plugin: opendirectory.core.od_inventory
api_url: "https://od.example.com"
api_key: "{{ lookup('env', 'OD_API_KEY') }}"
groups_by:
  - platform
  - compliance_status
'''

import json
import os
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from ansible.plugins.inventory import BaseInventoryPlugin


class InventoryModule(BaseInventoryPlugin):
    NAME = 'opendirectory.core.od_inventory'

    def verify_file(self, path):
        """Verify that the inventory source is valid."""
        valid = False
        if super().verify_file(path):
            if path.endswith(('.od_inventory.yml', '.od_inventory.yaml')):
                valid = True
        return valid

    def parse(self, inventory, loader, path, cache=True):
        super().parse(inventory, loader, path, cache)
        self._read_config_data(path)

        api_url = self.get_option('api_url') or os.environ.get('OD_API_URL', '')
        api_key = self.get_option('api_key') or os.environ.get('OD_API_KEY', '')

        if not api_url or not api_key:
            raise Exception('api_url and api_key are required')

        devices = self._fetch_devices(api_url, api_key)
        groups_by = self.get_option('groups_by') or ['platform']

        # Create groups and add hosts
        for device in devices:
            hostname = device.get('name', device.get('id', 'unknown'))
            self.inventory.add_host(hostname)

            # Set host variables
            self.inventory.set_variable(hostname, 'od_device_id', device.get('id', ''))
            self.inventory.set_variable(hostname, 'od_platform', device.get('platform', 'unknown'))
            self.inventory.set_variable(hostname, 'od_status', device.get('status', 'unknown'))
            self.inventory.set_variable(hostname, 'od_owner', device.get('owner', ''))
            self.inventory.set_variable(hostname, 'od_last_seen', device.get('lastSeen', ''))

            if device.get('ip'):
                self.inventory.set_variable(hostname, 'ansible_host', device['ip'])

            # Group by platform
            if 'platform' in groups_by:
                platform = device.get('platform', 'unknown').lower()
                group_name = f'od_{platform}'
                self.inventory.add_group(group_name)
                self.inventory.add_child(group_name, hostname)

            # Group by compliance status
            if 'compliance_status' in groups_by:
                compliance = device.get('compliance', {})
                status = compliance.get('status', 'unknown') if isinstance(compliance, dict) else 'unknown'
                group_name = f'od_compliance_{status}'
                self.inventory.add_group(group_name)
                self.inventory.add_child(group_name, hostname)

            # Group by device status
            if 'status' in groups_by:
                status = device.get('status', 'unknown')
                group_name = f'od_status_{status}'
                self.inventory.add_group(group_name)
                self.inventory.add_child(group_name, hostname)

    def _fetch_devices(self, api_url, api_key):
        """Fetch devices from OpenDirectory API."""
        url = f"{api_url.rstrip('/')}/api/devices"
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/json'
        }

        try:
            req = Request(url, headers=headers)
            response = urlopen(req, timeout=30)
            data = json.loads(response.read().decode('utf-8'))
            return data.get('data', data) if isinstance(data, dict) else data
        except HTTPError as e:
            raise Exception(f'Failed to fetch devices from OpenDirectory: {e.code} {e.reason}')
        except Exception as e:
            raise Exception(f'Failed to connect to OpenDirectory: {str(e)}')
