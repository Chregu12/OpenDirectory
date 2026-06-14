'use strict';

const DeviceEvents = {
  DEVICE_ENROLLED:       'device.enrolled',
  DEVICE_COMPLIANT:      'device.compliant',
  DEVICE_NON_COMPLIANT:  'device.non_compliant',
  DEVICE_RETIRED:        'device.retired',
  DEVICE_SEEN:           'device.seen',
  DEVICE_LOCKED:         'device.locked',
  DEVICE_WIPED:          'device.wiped',
  DEVICE_ISOLATED:       'device.isolated',
  DEVICE_RECONNECTED:    'device.reconnected',
  INSTALL_JOB_CREATED:   'device.install.created',
  INSTALL_JOB_COMPLETED: 'device.install.completed',
  INSTALL_JOB_FAILED:    'device.install.failed',
};

module.exports = { DeviceEvents };
