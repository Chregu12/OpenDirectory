'use strict';

// ─── Windows Hardware Matcher ─────────────────────────────────────────────────
//
// Parses Windows PnP device IDs (from Win32_PnPEntity / hardwareIds array)
// and extracts structured identifiers for driver lookup.
//
// Windows PnP ID formats:
//   PCI\VEN_8086&DEV_1502&SUBSYS_21F917AA&REV_04&CC_020000
//   USB\VID_0BDA&PID_8179&REV_0300
//   HDAUDIO\FUNC_01&VEN_10EC&DEV_0269&SUBSYS_17AA21F3&REV_1001
//   ACPI\INT3400\2&DABA3FF&0

const RE_PCI_VEN = /ven_([0-9a-f]{4})/i;
const RE_PCI_DEV = /dev_([0-9a-f]{4})/i;
const RE_PCI_CC  = /cc_([0-9a-f]{4,6})/i;
const RE_USB_VID = /vid_([0-9a-f]{4})/i;
const RE_USB_PID = /pid_([0-9a-f]{4})/i;
const RE_HDA_VEN = /ven_([0-9a-f]{4})/i;

/**
 * Parse an array of Windows PnP device entry objects into normalised identifiers.
 *
 * Each entry may be:
 *   - A string (the raw deviceId)
 *   - An object with { deviceId, class, description }
 *
 * @param {Array<string|object>} hardwareIds
 * @returns {{ pciDevices: PciDevice[], usbDevices: UsbDevice[], hdaDevices: HdaDevice[] }}
 */
function parseHardwareIds(hardwareIds = []) {
  const pciDevices = [];
  const usbDevices = [];
  const hdaDevices = [];

  for (const entry of hardwareIds) {
    const rawId = (typeof entry === 'string' ? entry : (entry.deviceId || entry.id || '')).toString();
    const id = rawId.toLowerCase();

    if (id.startsWith('pci\\')) {
      const ven = RE_PCI_VEN.exec(id)?.[1] || null;
      const dev = RE_PCI_DEV.exec(id)?.[1] || null;
      const cls = RE_PCI_CC.exec(id)?.[1]?.substring(0, 4) || null;
      if (ven) pciDevices.push({ vendorId: ven, deviceId: dev, classId: cls, raw: rawId });
    } else if (id.startsWith('usb\\')) {
      const vid = RE_USB_VID.exec(id)?.[1] || null;
      const pid = RE_USB_PID.exec(id)?.[1] || null;
      if (vid) usbDevices.push({ vendorId: vid, productId: pid, raw: rawId });
    } else if (id.startsWith('hdaudio\\')) {
      const ven = RE_HDA_VEN.exec(id)?.[1] || null;
      if (ven) hdaDevices.push({ vendorId: ven, raw: rawId });
    }
  }

  return { pciDevices, usbDevices, hdaDevices };
}

/**
 * Decide whether a driver entry is applicable on Windows.
 *
 * @param {{ os: string[], format?: string }} driver
 * @returns {boolean}
 */
function isWindowsCompatible(driver) {
  if (!driver.os || !Array.isArray(driver.os)) return false;
  return driver.os.includes('windows');
}

/**
 * Preferred download formats on Windows (ordered by preference).
 */
const WINDOWS_FORMATS = ['exe', 'msi', 'inf', 'zip', 'cab'];

function preferredFormat(driver) {
  return WINDOWS_FORMATS.indexOf(driver.format || '') !== -1
    ? WINDOWS_FORMATS.indexOf(driver.format)
    : WINDOWS_FORMATS.length;
}

module.exports = { parseHardwareIds, isWindowsCompatible, preferredFormat };
