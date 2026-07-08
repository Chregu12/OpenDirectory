'use strict';

// Behaviour tests for @opendirectory/driver-catalog.
// Runs with Node's built-in test runner (no dependencies):
//   node --test packages/driver-catalog/test/

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  DriverCatalog,
  LinuxMatcher,
  WindowsMatcher,
  scoreMatch,
  normalizeVendor,
  normalizeOs,
} = require('../src');

// ─── scoring ──────────────────────────────────────────────────────────────────

test('scoreMatch: exact model match scores 20', () => {
  assert.equal(scoreMatch({ models: ['OptiPlex 7090'] }, { model: 'OptiPlex 7090' }), 20);
});

test('scoreMatch: partial token match (generation code) scores 20', () => {
  assert.equal(scoreMatch({ models: ['EliteBook 840 G9'] }, { model: 'G9' }), 20);
  assert.equal(scoreMatch({ models: ['ThinkPad T14 Gen 3'] }, { model: 'T14' }), 20);
});

test('scoreMatch: single-character tokens never match', () => {
  assert.equal(scoreMatch({ models: ['ThinkPad T16 Gen 1'] }, { model: '1' }), 0);
});

test('scoreMatch: distinct models do not match on prefix ("T1" vs "T16")', () => {
  assert.equal(scoreMatch({ models: ['ThinkPad T16 Gen 1'] }, { model: 'T1' }), 0);
});

test('scoreMatch: OS match adds 10', () => {
  assert.equal(scoreMatch({ models: [], os: ['windows'] }, { os: 'windows' }), 10);
  assert.equal(
    scoreMatch({ models: ['OptiPlex 7090'], os: ['windows'] }, { model: 'OptiPlex 7090', os: 'windows' }),
    30
  );
});

test('normalizeVendor: canonical vendor keys', () => {
  assert.equal(normalizeVendor('Dell Inc.'), 'dell');
  assert.equal(normalizeVendor('Hewlett-Packard'), 'hp');
  assert.equal(normalizeVendor('LENOVO'), 'lenovo');
  assert.equal(normalizeVendor(null), null);
});

test('normalizeOs: label detection', () => {
  assert.equal(normalizeOs('Microsoft Windows 11 Pro'), 'windows');
  assert.equal(normalizeOs('Ubuntu 24.04 LTS'), 'linux');
  assert.equal(normalizeOs('Darwin'), 'macos');
  assert.equal(normalizeOs('BeOS'), null);
});

// ─── LinuxMatcher: parsing ────────────────────────────────────────────────────

test('LinuxMatcher: lspci entries with class hint parse as PCI', () => {
  const p = LinuxMatcher.parseHardwareIds([{ deviceId: '8086:9a49', class: '0300' }]);
  assert.equal(p.pciDevices.length, 1);
  assert.deepEqual(p.pciDevices[0], { vendorId: '8086', deviceId: '9a49', classId: '0300' });
  assert.equal(p.usbVendors.length, 0);
});

test('LinuxMatcher: lsusb entries with class "usb" parse as USB, never PCI', () => {
  const p = LinuxMatcher.parseHardwareIds([{ deviceId: '0bda:8153', class: 'usb' }]);
  assert.equal(p.pciDevices.length, 0);
  assert.deepEqual(p.usbVendors, ['0bda']);
});

test('LinuxMatcher: Windows PnP IDs are accepted cross-platform', () => {
  const p = LinuxMatcher.parseHardwareIds([
    'PCI\\VEN_10DE&DEV_2484&CC_030000',
    'USB\\VID_0CF3&PID_E009',
  ]);
  assert.equal(p.pciDevices.length, 1);
  assert.equal(p.pciDevices[0].vendorId, '10de');
  assert.equal(p.pciDevices[0].classId, '0300');
  assert.deepEqual(p.usbVendors, ['0cf3']);
});

// ─── LinuxMatcher: matching ───────────────────────────────────────────────────

test('LinuxMatcher: known PCI class matches only that category (no fan-out)', () => {
  const m = LinuxMatcher.matchFromHardware(
    { pciDevices: [{ vendorId: '8086', classId: '0300' }], usbVendors: [] }, {}
  );
  assert.equal(m.length, 1);
  assert.equal(m[0].aptPackage, 'intel-media-va-driver');
  assert.equal(m[0].matchScore, 15);
  assert.equal(m[0].matchedVia, 'pci-id');
});

test('LinuxMatcher: missing PCI class falls back to vendor match at score 8', () => {
  const m = LinuxMatcher.matchFromHardware(
    { pciDevices: [{ vendorId: '8086', classId: null }], usbVendors: [] }, {}
  );
  assert.ok(m.length > 0, 'must not be silent without class info');
  assert.ok(m.every(x => x.matchScore === 8 && x.matchedVia === 'pci-vendor'));
});

test('LinuxMatcher: USB vendor rules match', () => {
  const m = LinuxMatcher.matchFromHardware({ pciDevices: [], usbVendors: ['0bda'] }, {});
  assert.ok(m.some(x => x.aptPackage === 'firmware-realtek'));
});

// ─── WindowsMatcher ───────────────────────────────────────────────────────────

test('WindowsMatcher: parses PnP PCI/USB/HDAUDIO IDs', () => {
  const p = WindowsMatcher.parseHardwareIds([
    'PCI\\VEN_8086&DEV_1502&CC_020000',
    'USB\\VID_0BDA&PID_8179',
    'HDAUDIO\\FUNC_01&VEN_10EC&DEV_0269',
  ]);
  assert.equal(p.pciDevices.length, 1);
  assert.equal(p.pciDevices[0].classId, '0200');
  assert.equal(p.usbDevices.length, 1);
  assert.equal(p.hdaDevices.length, 1);
  assert.equal(p.hdaDevices[0].vendorId, '10ec');
});

// ─── DriverCatalog orchestration ──────────────────────────────────────────────

test('DriverCatalog: Dell provider is NOT queried without vendor and model', async () => {
  let calls = 0;
  const cat = new DriverCatalog();
  cat.registerProvider('dell', async () => { calls++; return []; });
  await cat.matchDrivers({ manufacturer: null, model: null, os: 'windows' });
  assert.equal(calls, 0);
});

test('DriverCatalog: Dell provider IS queried for a Dell with a model', async () => {
  let calls = 0;
  const cat = new DriverCatalog();
  cat.registerProvider('dell', async () => {
    calls++;
    return [{ id: 'dell-x', name: 'X', os: ['windows'], models: ['OptiPlex 7090'], deviceType: 'other', format: 'exe' }];
  });
  const r = await cat.matchDrivers({ manufacturer: 'Dell Inc.', model: 'OptiPlex 7090', os: 'windows' });
  assert.equal(calls, 1);
  const hit = r.find(x => x.id === 'dell-x');
  assert.ok(hit);
  assert.equal(hit.matchedVia, 'dell-catalog');
  assert.equal(hit.matchScore, 30); // model 20 + os 10
});

test('DriverCatalog: a failing Dell provider degrades gracefully', async () => {
  const cat = new DriverCatalog();
  cat.registerProvider('dell', async () => { throw new Error('network down'); });
  const r = await cat.matchDrivers({ manufacturer: 'Dell Inc.', model: 'OptiPlex 7090', os: 'windows' });
  assert.ok(Array.isArray(r)); // no throw, static results still possible
});

test('DriverCatalog: Lenovo Linux with hardware IDs yields apt packages, deduped', async () => {
  const cat = new DriverCatalog();
  const r = await cat.matchDrivers({
    manufacturer: 'LENOVO',
    model: 'ThinkPad T14 Gen 3',
    os: 'linux',
    hardwareIds: [
      { deviceId: '8086:a0f0', class: '0280' },
      { deviceId: '0bda:8153', class: 'usb' },
    ],
  });
  const pkgs = r.map(x => x.aptPackage).filter(Boolean);
  assert.ok(pkgs.includes('firmware-iwlwifi'));
  assert.ok(pkgs.includes('firmware-realtek'));
  assert.equal(pkgs.length, new Set(pkgs).size, 'no duplicate apt packages');
});

test('DriverCatalog: OS filter excludes non-matching static entries', async () => {
  const cat = new DriverCatalog();
  const r = await cat.matchDrivers({ manufacturer: 'LENOVO', model: 'ThinkPad T14 Gen 3', os: 'windows' });
  assert.ok(r.length > 0);
  assert.ok(r.every(x => x.os.includes('windows')));
});
