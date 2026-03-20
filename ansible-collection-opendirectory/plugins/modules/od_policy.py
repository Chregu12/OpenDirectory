#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module for managing OpenDirectory policies.
"""

DOCUMENTATION = r'''
---
module: od_policy
short_description: Manage OpenDirectory policies
description:
    - Create, update, or delete policies in OpenDirectory.
    - Policies define security baselines, update rules, and compliance requirements.
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
    policy_id:
        description: Policy ID (for update/delete)
        type: str
    name:
        description: Policy name
        type: str
    policy_type:
        description: Policy type
        type: str
        choices: ['security', 'compliance', 'update', 'network', 'encryption']
    settings:
        description: Policy settings dictionary
        type: dict
    targets:
        description: Target device groups
        type: list
        elements: str
    state:
        description: Desired state
        type: str
        default: present
        choices: ['present', 'absent']
'''

EXAMPLES = r'''
- name: Create a security baseline policy
  opendirectory.core.od_policy:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    name: "Security Baseline"
    policy_type: "security"
    settings:
      firewall_enabled: true
      encryption_required: true
      min_password_length: 12
      screen_lock_timeout: 300
    targets:
      - "all-managed-devices"
    state: present

- name: Remove a policy
  opendirectory.core.od_policy:
    api_url: "https://od.example.com"
    api_key: "{{ od_api_key }}"
    policy_id: "pol-12345"
    state: absent
'''

RETURN = r'''
policy:
    description: Policy information
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
        policy_id=dict(type='str', required=False),
        name=dict(type='str', required=False),
        policy_type=dict(type='str', required=False, choices=['security', 'compliance', 'update', 'network', 'encryption']),
        settings=dict(type='dict', required=False, default={}),
        targets=dict(type='list', elements='str', required=False, default=[]),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )

    result = dict(changed=False, policy={})
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    api = OpenDirectoryAPI(module.params['api_url'], module.params['api_key'])
    state = module.params['state']
    policy_id = module.params.get('policy_id')

    try:
        if state == 'present':
            policy_data = {
                'name': module.params.get('name'),
                'type': module.params.get('policy_type'),
                'settings': module.params.get('settings', {}),
                'targets': module.params.get('targets', [])
            }
            policy_data = {k: v for k, v in policy_data.items() if v is not None}

            if module.check_mode:
                result['changed'] = True
                module.exit_json(**result)

            if policy_id:
                resp = api.update_policy(policy_id, policy_data)
            else:
                resp = api.create_policy(policy_data)

            result['policy'] = resp.get('data', resp)
            result['changed'] = True

        elif state == 'absent':
            if not policy_id:
                module.fail_json(msg='policy_id is required for state=absent')

            if module.check_mode:
                result['changed'] = True
                module.exit_json(**result)

            api.delete_policy(policy_id)
            result['changed'] = True

    except OpenDirectoryAPIError as e:
        module.fail_json(msg=str(e), status_code=e.status_code)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
