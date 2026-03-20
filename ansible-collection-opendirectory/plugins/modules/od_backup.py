#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module for OpenDirectory backup operations.
"""

DOCUMENTATION = r'''
---
module: od_backup
short_description: Manage OpenDirectory backups
description:
    - Trigger backups, check status, and manage disaster recovery.
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
    action:
        description: Backup action to perform
        required: true
        type: str
        choices: ['trigger', 'status', 'dr_health', 'dr_test']
    backup_type:
        description: Type of backup (for trigger action)
        type: str
        default: incremental
        choices: ['full', 'incremental', 'differential']
'''

EXAMPLES = r'''
- name: Trigger a full backup
  opendirectory.core.od_backup:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    action: trigger
    backup_type: full

- name: Check backup status
  opendirectory.core.od_backup:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    action: status

- name: Run DR drill
  opendirectory.core.od_backup:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    action: dr_test
'''

RETURN = r'''
backup:
    description: Backup job info or status
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
        action=dict(type='str', required=True, choices=['trigger', 'status', 'dr_health', 'dr_test']),
        backup_type=dict(type='str', default='incremental', choices=['full', 'incremental', 'differential']),
    )

    result = dict(changed=False, backup={})
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    api = OpenDirectoryAPI(module.params['api_url'], module.params['api_key'])
    action = module.params['action']

    try:
        if action == 'trigger':
            if module.check_mode:
                result['changed'] = True
                module.exit_json(**result)

            resp = api.trigger_backup(module.params['backup_type'])
            result['backup'] = resp
            result['changed'] = True

        elif action == 'status':
            resp = api.get_backup_status()
            result['backup'] = resp.get('data', resp)

        elif action == 'dr_health':
            resp = api.get_dr_health()
            result['backup'] = resp.get('data', resp)

        elif action == 'dr_test':
            if module.check_mode:
                result['changed'] = True
                module.exit_json(**result)

            resp = api.post('/api/dr/failover/test')
            result['backup'] = resp
            result['changed'] = True

    except OpenDirectoryAPIError as e:
        module.fail_json(msg=str(e), status_code=e.status_code)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
