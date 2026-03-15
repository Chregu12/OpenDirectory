#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module for OpenDirectory compliance checks.
"""

DOCUMENTATION = r'''
---
module: od_compliance
short_description: Check and enforce device compliance
description:
    - Run compliance checks on OpenDirectory-managed devices.
    - Can also query analytics for threats and anomalies.
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
        description: Device ID to check
        type: str
    action:
        description: Action to perform
        required: true
        type: str
        choices: ['check', 'threats', 'dashboard']
    severity:
        description: Filter threats by severity
        type: str
        choices: ['critical', 'warning', 'info']
'''

EXAMPLES = r'''
- name: Check device compliance
  opendirectory.core.od_compliance:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    device_id: "dev-12345"
    action: check
  register: compliance_result

- name: Get active threats
  opendirectory.core.od_compliance:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    action: threats
    severity: critical
  register: threats

- name: Get dashboard overview
  opendirectory.core.od_compliance:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    action: dashboard
  register: dashboard
'''

RETURN = r'''
result:
    description: Compliance check or query result
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
        device_id=dict(type='str', required=False),
        action=dict(type='str', required=True, choices=['check', 'threats', 'dashboard']),
        severity=dict(type='str', required=False, choices=['critical', 'warning', 'info']),
    )

    result = dict(changed=False, result={})
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    api = OpenDirectoryAPI(module.params['api_url'], module.params['api_key'])
    action = module.params['action']

    try:
        if action == 'check':
            if not module.params.get('device_id'):
                module.fail_json(msg='device_id is required for action=check')
            resp = api.check_compliance(module.params['device_id'])
            result['result'] = resp.get('data', resp)

        elif action == 'threats':
            resp = api.get_threats(severity=module.params.get('severity'))
            result['result'] = resp.get('data', resp)

        elif action == 'dashboard':
            resp = api.get_dashboard()
            result['result'] = resp.get('data', resp)

    except OpenDirectoryAPIError as e:
        module.fail_json(msg=str(e), status_code=e.status_code)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
