'use strict';

const {
  DEVICE_FIELDS, DEVICE_CLASSES, INVENTORY_PERMISSIONS,
  validateDeviceValues, validateDeviceAssignment, deviceEtag, validateDeviceEtag,
} = require('../../../../../packages/device-inventory-contract');

const deviceId = '123e4567-e89b-12d3-a456-426614174000';
const requiredValues = {
  assetId: 'ASSET-1', serialNumber: 'SERIAL-1', manufacturer: 'Example', model: 'Model 1',
  deviceClass: 'laptop', platform: 'macos',
};
const defaultValues = { osVersion: '', ownership: 'corporate', purchaseDate: '', warrantyEnd: '', description: '' };
const textFields = [['assetId', 120], ['serialNumber', 120], ['manufacturer', 120], ['model', 120], ['osVersion', 120], ['description', 2000]];

describe('device inventory values', () => {
  test('exports immutable field, class and permission lists', () => {
    expect(DEVICE_FIELDS).toEqual([
      'assetId', 'serialNumber', 'manufacturer', 'model', 'deviceClass', 'platform',
      'osVersion', 'ownership', 'purchaseDate', 'warrantyEnd', 'description',
    ]);
    expect(DEVICE_CLASSES).toEqual(['smartphone', 'tablet', 'laptop', 'desktop', 'shared', 'kiosk', 'other']);
    expect(INVENTORY_PERMISSIONS).toEqual(['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign']);
    expect([DEVICE_FIELDS, DEVICE_CLASSES, INVENTORY_PERMISSIONS].every(Object.isFrozen)).toBe(true);
  });

  test('returns complete normalized values without mutating the input', () => {
    const input = Object.freeze({ ...requiredValues, assetId: '  ASSET-1  ', description: '  Gerät  ' });
    const values = validateDeviceValues(input);
    expect(values).toEqual({ ...requiredValues, ...defaultValues, description: 'Gerät' });
    expect(Object.keys(values)).toEqual(DEVICE_FIELDS);
    expect(input.assetId).toBe('  ASSET-1  ');
    expect(Object.keys(input)).toHaveLength(7);
  });

  test('defaults only omitted fields and accepts explicit empty optional strings', () => {
    expect(validateDeviceValues(requiredValues)).toEqual({ ...requiredValues, ...defaultValues });
    expect(validateDeviceValues({ ...requiredValues, ...defaultValues })).toEqual({ ...requiredValues, ...defaultValues });
    expect(validateDeviceValues(Object.assign(Object.create(null), requiredValues))).toEqual({ ...requiredValues, ...defaultValues });
  });

  test.each([null, undefined, false, 1, 'device', [], {}, new Date(), Object.create(requiredValues)])('rejects malformed create input %p', input => {
    expect(() => validateDeviceValues(input)).toThrow(expect.objectContaining({ status: 400 }));
  });

  test.each(Object.keys(requiredValues))('requires an own %s value', field => {
    const input = { ...requiredValues };
    delete input[field];
    expect(() => validateDeviceValues(input)).toThrow(expect.objectContaining({ status: 400 }));
  });

  test.each([
    'tenantId', 'tenant_id', 'status', 'provider', 'providerId', 'providerDeviceId', 'compliance', 'complianceStatus',
    'isCompliant', 'userId', 'assignedUserId', 'actorUserId', 'callerId', 'createdBy', 'id', 'deviceId', 'revision',
    'hostname', '__proto__', 'constructor', 'unknown', Symbol('hidden'),
  ])('rejects extra create field %p', field => {
    expect(() => validateDeviceValues({ ...requiredValues, [field]: 'forged' })).toThrow(expect.objectContaining({ status: 400 }));
  });

  test('also rejects nonenumerable extra fields', () => {
    const input = Object.defineProperty({ ...requiredValues }, 'tenantId', { value: 'forged' });
    expect(() => validateDeviceValues(input)).toThrow(expect.objectContaining({ status: 400 }));
  });

  test.each(DEVICE_FIELDS)('requires a string for any supplied %s', field => {
    for (const value of [undefined, null, 123, true, [], {}, new String('value')]) {
      expect(() => validateDeviceValues({ ...requiredValues, [field]: value })).toThrow(expect.objectContaining({ status: 400 }));
    }
  });

  test.each(textFields)('trims %s and enforces its exact maximum of %i Unicode characters', (field, maximum) => {
    expect(validateDeviceValues({ ...requiredValues, [field]: `  ${'🙂'.repeat(maximum)}  ` })[field]).toBe('🙂'.repeat(maximum));
    expect(() => validateDeviceValues({ ...requiredValues, [field]: '🙂'.repeat(maximum + 1) })).toThrow(expect.objectContaining({ status: 400 }));
    expect(validateDeviceValues({ ...requiredValues, [field]: ' x ' })[field]).toBe('x');
    if (Object.hasOwn(defaultValues, field)) {
      expect(validateDeviceValues({ ...requiredValues, [field]: '   ' })[field]).toBe('');
    } else {
      expect(() => validateDeviceValues({ ...requiredValues, [field]: '   ' })).toThrow(expect.objectContaining({ status: 400 }));
    }
  });

  test.each(DEVICE_FIELDS)('rejects control characters in %s before trimming', field => {
    const controls = Array.from({ length: 32 }, (unused, index) => String.fromCharCode(index))
      .concat(Array.from({ length: 33 }, (unused, index) => String.fromCharCode(127 + index)));
    for (const control of controls) {
      expect(() => validateDeviceValues({ ...requiredValues, [field]: `${control}value${control}` })).toThrow(expect.objectContaining({ status: 400 }));
    }
  });

  test.each(DEVICE_CLASSES)('accepts device class %s', deviceClass => {
    expect(validateDeviceValues({ ...requiredValues, deviceClass }).deviceClass).toBe(deviceClass);
  });

  test.each(['macos', 'ios', 'ipados', 'windows', 'linux', 'android', 'other'])('accepts platform %s', platform => {
    expect(validateDeviceValues({ ...requiredValues, platform }).platform).toBe(platform);
  });

  test.each(['corporate', 'byod', 'shared'])('accepts ownership %s', ownership => {
    expect(validateDeviceValues({ ...requiredValues, ownership }).ownership).toBe(ownership);
  });

  test.each([
    ['deviceClass', 'server'], ['deviceClass', 'Laptop'], ['deviceClass', ' laptop '], ['deviceClass', ''],
    ['platform', 'chromeos'], ['platform', 'MacOS'], ['platform', ' macos '], ['platform', ''],
    ['ownership', 'personal'], ['ownership', 'Corporate'], ['ownership', ' corporate '], ['ownership', ''],
  ])('rejects invalid %s enum %p', (field, value) => {
    expect(() => validateDeviceValues({ ...requiredValues, [field]: value })).toThrow(expect.objectContaining({ status: 400 }));
  });

  test.each(['purchaseDate', 'warrantyEnd'])('validates real calendar dates in %s', field => {
    for (const value of ['', '0001-01-01', '2000-02-29', '2024-02-29', '9999-12-31']) {
      expect(validateDeviceValues({ ...requiredValues, [field]: value })[field]).toBe(value);
    }
    for (const value of ['0000-01-01', '2023-02-29', '1900-02-29', '2024-02-30', '2024-04-31', '2024-13-01', '2024-00-01', '2024-01-00', '2024-01-32', '2024-1-01', '24-01-01', '10000-01-01', '2024-01-01T00:00:00Z', ' 2024-01-01 ', ' ']) {
      expect(() => validateDeviceValues({ ...requiredValues, [field]: value })).toThrow(expect.objectContaining({ status: 400 }));
    }
  });

  test('allows equal or later warranty dates and rejects earlier warranty dates', () => {
    for (const warrantyEnd of ['', '2024-02-29', '2025-02-28']) {
      expect(validateDeviceValues({ ...requiredValues, purchaseDate: '2024-02-29', warrantyEnd }).warrantyEnd).toBe(warrantyEnd);
    }
    expect(validateDeviceValues({ ...requiredValues, warrantyEnd: '2024-02-28' }).purchaseDate).toBe('');
    expect(() => validateDeviceValues({ ...requiredValues, purchaseDate: '2024-02-29', warrantyEnd: '2024-02-28' })).toThrow(expect.objectContaining({ status: 400 }));
  });
});

describe('device inventory assignment', () => {
  test.each([deviceId, null])('returns only the explicitly supplied userId %p', userId => {
    const input = Object.freeze({ userId });
    expect(validateDeviceAssignment(input)).toEqual({ userId });
    expect(validateDeviceAssignment(input)).not.toBe(input);
  });

  test.each([
    null, undefined, false, [], 'user', {}, { userId: undefined }, { userId: '' }, { userId: 123 },
    { userId: true }, { userId: [] }, { userId: {} }, { userId: deviceId.toUpperCase() },
    { userId: ` ${deviceId}` }, { userId: `${deviceId}\n` }, { userId: deviceId.replaceAll('-', '') },
    { userId: '{123e4567-e89b-12d3-a456-426614174000}' }, { userId: '123e4567-e89b-12d3-a456-42661417400g' },
    { userId: deviceId, tenantId: deviceId }, { userId: null, provision: true },
    { userId: deviceId, actorUserId: deviceId }, { userId: deviceId, [Symbol('hidden')]: true },
    Object.create({ userId: deviceId }),
  ])('rejects malformed assignment %p', input => {
    expect(() => validateDeviceAssignment(input)).toThrow(expect.objectContaining({ status: 400 }));
  });
});

describe('device inventory ETags', () => {
  test.each(['1', '9007199254740993', '9223372036854775807'])('preserves exact revision %s in a strong ETag', revision => {
    const device = Object.freeze({ id: deviceId, revision });
    const etag = `"device-${deviceId}-${revision}"`;
    expect(deviceEtag(device)).toBe(etag);
    expect(validateDeviceEtag(etag)).toBe(etag);
  });

  test.each([undefined, null, ''])('requires a missing ETag with status 428: %p', value => {
    expect(() => validateDeviceEtag(value)).toThrow(expect.objectContaining({ status: 428 }));
  });

  test.each([
    '0', '-1', '+1', '01', '1.0', '1e1', ' 1', '1 ', '1\n', '9223372036854775808', '99999999999999999999',
    '', undefined, null, 1, 9007199254740992, 1n, {}, [],
  ])('rejects noncanonical or out-of-range device revision %p', revision => {
    expect(() => deviceEtag({ id: deviceId, revision })).toThrow(expect.objectContaining({ status: 400 }));
    if (typeof revision === 'string') {
      expect(() => validateDeviceEtag(`"device-${deviceId}-${revision}"`)).toThrow(expect.objectContaining({ status: 400 }));
    }
  });

  test.each([null, undefined, [], {}, { id: deviceId }, { id: deviceId.toUpperCase(), revision: '1' }, { id: `${deviceId}\n`, revision: '1' }, { id: 'device-1', revision: '1' }, { id: null, revision: '1' }])('rejects a malformed ETag source %p', device => {
    expect(() => deviceEtag(device)).toThrow(expect.objectContaining({ status: 400 }));
  });

  test.each([
    '*', 'W/"device-123e4567-e89b-12d3-a456-426614174000-1"', ' ', false, 0, 1, [], {},
    `device-${deviceId}-1`, `'device-${deviceId}-1'`, `"device-${deviceId.toUpperCase()}-1"`,
    `"device-${deviceId}-1", "device-${deviceId}-2"`, ` "device-${deviceId}-1"`,
    `"device-${deviceId}-1" `, `"device-${deviceId}-1"\n`, `"device-${deviceId}-1"\r\n`,
    `"device-${deviceId}-1"\u0000`, `"other-${deviceId}-1"`, '"device-device-1-1"',
  ])('rejects malformed, weak or multiple ETags %p', value => {
    expect(() => validateDeviceEtag(value)).toThrow(expect.objectContaining({ status: 400 }));
  });
});
