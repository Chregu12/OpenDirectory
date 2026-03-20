#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module for deploying WiFi profiles to OpenDirectory-managed devices.
"""

DOCUMENTATION = r'''
---
module: od_wifi_profile
short_description: Deploy WiFi profiles to managed devices
description:
    - Deploy or remove WiFi profiles on devices managed by OpenDirectory.
    - Profiles are deployed via the agent dispatch system (platform-agnostic).
version_added: "1.0.0"
author: "OpenDirectory Team"
options:
    api_url:
        description: OpenDirectory API URL
        required: true
        type: str
    api_key:
        description: OpenDirectory API key
        required: true
        type: str
        no_log: true
    device_id:
        description: Target device ID
        required: true
        type: str
    ssid:
        description: WiFi network SSID
        type: str
    security:
        description: Security type
        type: str
        choices: ['WPA2-Personal', 'WPA2-Enterprise', 'WPA3-Personal', 'WPA3-Enterprise', 'Open']
    eap_type:
        description: EAP type (for Enterprise security)
        type: str
        choices: ['TLS', 'TTLS', 'PEAP']
    password:
        description: WiFi password (for Personal security)
        type: str
        no_log: true
    cert_id:
        description: Certificate ID (for Enterprise security)
        type: str
    auto_connect:
        description: Auto-connect to this network
        type: bool
        default: true
    profile_id:
        description: Profile ID (for removal)
        type: str
    state:
        description: Desired state
        type: str
        default: present
        choices: ['present', 'absent']
'''

EXAMPLES = r'''
- name: Deploy corporate WiFi
  opendirectory.core.od_wifi_profile:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    device_id: "dev-12345"
    ssid: "Corp-WiFi"
    security: "WPA2-Enterprise"
    eap_type: "TLS"
    cert_id: "cert-abc123"
    auto_connect: true
    state: present

- name: Remove WiFi profile
  opendirectory.core.od_wifi_profile:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    device_id: "dev-12345"
    profile_id: "wifi-12345"
    ssid: "Corp-WiFi"
    state: absent
'''

RETURN = r'''
result:
    description: Command result from agent
    type: dict
    returned: success
'''

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'module_utils'))

from ansible.module_utils.basic import AnsibleModule

try:
    from ansible_collections.opendirectory.core.plugins.module_utils.od_api import OpenDirectoryAPI, OpenDirectoryAPIError
except ImportError:
    from od_api import OpenDirectoryAPI, OpenDirectoryAPIError


def run_module():
    module_args = dict(
        api_url=dict(type='str', required=True),
        api_key=dict(type='str', required=True, no_log=True),
        device_id=dict(type='str', required=True),
        ssid=dict(type='str', required=False),
        security=dict(type='str', required=False, choices=['WPA2-Personal', 'WPA2-Enterprise', 'WPA3-Personal', 'WPA3-Enterprise', 'Open']),
        eap_type=dict(type='str', required=False, choices=['TLS', 'TTLS', 'PEAP']),
        password=dict(type='str', required=False, no_log=True),
        cert_id=dict(type='str', required=False),
        auto_connect=dict(type='bool', default=True),
        profile_id=dict(type='str', required=False),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )

    result = dict(changed=False, result={})
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    api = OpenDirectoryAPI(module.params['api_url'], module.params['api_key'])
    state = module.params['state']
    device_id = module.params['device_id']

    try:
        if state == 'present':
            if not module.params.get('ssid'):
                module.fail_json(msg='ssid is required for state=present')

            profile = {
                'ssid': module.params['ssid'],
                'security': module.params.get('security', 'WPA2-Personal'),
                'autoConnect': module.params.get('auto_connect', True)
            }
            if module.params.get('eap_type'):
                profile['eapType'] = module.params['eap_type']
            if module.params.get('password'):
                profile['password'] = module.params['password']
            if module.params.get('cert_id'):
                profile['certId'] = module.params['cert_id']

            if module.check_mode:
                result['changed'] = True
                module.exit_json(**result)

            resp = api.configure_wifi(device_id, profile)
            result['result'] = resp
            result['changed'] = True

        elif state == 'absent':
            profile_id = module.params.get('profile_id', '')
            ssid = module.params.get('ssid')

            if module.check_mode:
                result['changed'] = True
                module.exit_json(**result)

            resp = api.remove_wifi(device_id, profile_id, ssid)
            result['result'] = resp
            result['changed'] = True

    except OpenDirectoryAPIError as e:
        module.fail_json(msg=str(e), status_code=e.status_code)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
