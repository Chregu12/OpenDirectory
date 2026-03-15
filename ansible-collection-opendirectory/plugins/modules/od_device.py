#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module for managing OpenDirectory devices.
"""

DOCUMENTATION = r'''
---
module: od_device
short_description: Manage OpenDirectory devices
description:
    - Create, update, or delete devices in OpenDirectory.
    - Can also trigger compliance checks and remote actions.
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
        description: Device ID (required for update/delete/absent)
        type: str
    name:
        description: Device name
        type: str
    platform:
        description: Device platform (windows, macos, linux)
        type: str
        choices: ['windows', 'macos', 'linux', 'ios', 'android']
    owner:
        description: Device owner user ID
        type: str
    state:
        description: Desired state of the device
        type: str
        default: present
        choices: ['present', 'absent', 'compliant']
'''

EXAMPLES = r'''
- name: Enroll a new device
  opendirectory.core.od_device:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    name: "laptop-jdoe-01"
    platform: "windows"
    owner: "jdoe"
    state: present

- name: Check device compliance
  opendirectory.core.od_device:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    device_id: "dev-12345"
    state: compliant

- name: Remove a device
  opendirectory.core.od_device:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    device_id: "dev-12345"
    state: absent
'''

RETURN = r'''
device:
    description: Device information
    type: dict
    returned: success
compliance:
    description: Compliance check result (when state=compliant)
    type: dict
    returned: when state is compliant
'''

import json
import sys
import os

# Add module_utils to path
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
        device_id=dict(type='str', required=False),
        name=dict(type='str', required=False),
        platform=dict(type='str', required=False, choices=['windows', 'macos', 'linux', 'ios', 'android']),
        owner=dict(type='str', required=False),
        state=dict(type='str', default='present', choices=['present', 'absent', 'compliant']),
    )

    result = dict(changed=False, device={}, compliance={})
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    api = OpenDirectoryAPI(module.params['api_url'], module.params['api_key'])
    state = module.params['state']
    device_id = module.params.get('device_id')

    try:
        if state == 'present':
            device_data = {}
            if module.params.get('name'):
                device_data['name'] = module.params['name']
            if module.params.get('platform'):
                device_data['platform'] = module.params['platform']
            if module.params.get('owner'):
                device_data['owner'] = module.params['owner']

            if module.check_mode:
                result['changed'] = True
                module.exit_json(**result)

            if device_id:
                resp = api.update_device(device_id, device_data)
                result['device'] = resp.get('data', resp)
                result['changed'] = True
            else:
                resp = api.create_device(device_data)
                result['device'] = resp.get('data', resp)
                result['changed'] = True

        elif state == 'absent':
            if not device_id:
                module.fail_json(msg='device_id is required for state=absent')

            if module.check_mode:
                result['changed'] = True
                module.exit_json(**result)

            api.delete_device(device_id)
            result['changed'] = True

        elif state == 'compliant':
            if not device_id:
                module.fail_json(msg='device_id is required for state=compliant')

            resp = api.check_compliance(device_id)
            result['compliance'] = resp.get('data', resp)

    except OpenDirectoryAPIError as e:
        module.fail_json(msg=str(e), status_code=e.status_code)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
