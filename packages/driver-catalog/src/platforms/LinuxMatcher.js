'use strict';

// ─── Linux Hardware Matcher ───────────────────────────────────────────────────
//
// Parses Linux hardware identifiers from lspci -n and lsusb, then maps them
// to apt package names and kernel driver names.
//
// lspci -n line format (field 3 = vendorId:deviceId, field 2 = classId):
//   00:02.0 0300 8086:9a49 (rev 01)
//
// lsusb line format:
//   Bus 002 Device 003: ID 0bda:8153 Realtek Semiconductor Corp. RTL8153...
//
// Both Windows PnP IDs are also accepted (for cross-platform reports):
//   PCI\VEN_8086&DEV_9A49&CC_030000
//   USB\VID_0BDA&PID_8153

// ─── PCI class → device type mapping ─────────────────────────────────────────

const PCI_CLASS_TO_TYPE = {
  '0200': 'network',
  '0280': 'network',
  '0300': 'display',
  '0302': 'display',
  '0403': 'audio',
  '0c03': 'usb',
  '0c0a': 'usb',   // Thunderbolt
  '0108': 'storage',
  '0101': 'storage',
};

// ─── PCI/USB vendor → driver rules ───────────────────────────────────────────
//
// Each rule may match on pciVendor + optional pciClass prefix (first 2 digits),
// or on usbVendor.

const PCI_RULES = [
  // Intel WiFi (iwlwifi)
  { pciVendor: '8086', pciClass: '02', aptPackage: 'firmware-iwlwifi',       kernelModule: 'iwlwifi',     name: 'Intel Wireless Firmware (iwlwifi)', deviceType: 'network', tags: ['wifi', 'intel', 'iwlwifi'] },
  // Intel Ethernet (e1000e / igb / ice — kernel built-in, but needs firmware)
  { pciVendor: '8086', pciClass: '02', aptPackage: 'linux-firmware',          kernelModule: 'e1000e',      name: 'Intel Ethernet Firmware', deviceType: 'network', tags: ['ethernet', 'intel', 'e1000e'] },
  // Intel iGPU
  { pciVendor: '8086', pciClass: '03', aptPackage: 'intel-media-va-driver',   kernelModule: 'i915',        name: 'Intel GPU Media Driver (VA-API)', deviceType: 'display', tags: ['intel', 'gpu', 'vaapi', 'i915'] },
  // Intel HD Audio (in-kernel snd_hda_intel)
  { pciVendor: '8086', pciClass: '04', aptPackage: 'alsa-firmware-loaders',   kernelModule: 'snd_hda_intel', name: 'Intel HD Audio Firmware', deviceType: 'audio', tags: ['audio', 'intel', 'hda', 'alsa'] },
  // Intel Thunderbolt
  { pciVendor: '8086', pciClass: '0c', aptPackage: 'bolt',                    kernelModule: 'thunderbolt', name: 'Thunderbolt Device Manager (bolt)', deviceType: 'usb', tags: ['thunderbolt', 'bolt', 'intel'] },
  // NVIDIA GPU
  { pciVendor: '10de', pciClass: '03', aptPackage: 'nvidia-driver',           kernelModule: 'nvidia',      name: 'NVIDIA Graphics Driver', deviceType: 'display', tags: ['nvidia', 'gpu', 'cuda'] },
  // AMD / ATI GPU
  { pciVendor: '1002', pciClass: '03', aptPackage: 'firmware-amd-graphics',   kernelModule: 'amdgpu',      name: 'AMD Radeon Firmware (amdgpu)', deviceType: 'display', tags: ['amd', 'radeon', 'amdgpu'] },
  // Broadcom WiFi
  { pciVendor: '14e4', pciClass: '02', aptPackage: 'broadcom-sta-dkms',       kernelModule: 'wl',          name: 'Broadcom STA Wireless Driver', deviceType: 'network', tags: ['broadcom', 'wifi', 'wl', 'dkms'] },
  { pciVendor: '14e4', pciClass: '02', aptPackage: 'firmware-brcm80211',      kernelModule: 'brcmfmac',    name: 'Broadcom brcmfmac Firmware', deviceType: 'network', tags: ['broadcom', 'wifi', 'brcmfmac'] },
  // Qualcomm / Atheros WiFi
  { pciVendor: '168c', pciClass: '02', aptPackage: 'firmware-atheros',        kernelModule: 'ath10k_pci',  name: 'Qualcomm Atheros Wireless Firmware (ath10k)', deviceType: 'network', tags: ['atheros', 'qualcomm', 'ath10k', 'wifi'] },
  // Realtek WiFi (PCI)
  { pciVendor: '10ec', pciClass: '02', aptPackage: 'firmware-realtek',        kernelModule: 'rtl8821ce',   name: 'Realtek Wireless Firmware', deviceType: 'network', tags: ['realtek', 'wifi', 'rtl8821'] },
  // Realtek Ethernet (PCI)
  { pciVendor: '10ec', pciClass: '02', aptPackage: 'firmware-realtek',        kernelModule: 'r8169',       name: 'Realtek Ethernet Firmware', deviceType: 'network', tags: ['realtek', 'ethernet', 'r8169'] },
  // Realtek HD Audio
  { pciVendor: '10ec', pciClass: '04', aptPackage: 'alsa-firmware-loaders',   kernelModule: 'snd_hda_codec_realtek', name: 'Realtek HD Audio Firmware', deviceType: 'audio', tags: ['realtek', 'audio', 'hda', 'alsa'] },
  // Samsung NVMe
  { pciVendor: '144d', pciClass: '01', aptPackage: 'nvme-cli',                kernelModule: 'nvme',        name: 'Samsung NVMe Tools', deviceType: 'storage', tags: ['samsung', 'nvme', 'ssd'] },
  // WD / SanDisk NVMe
  { pciVendor: '15b7', pciClass: '01', aptPackage: 'nvme-cli',                kernelModule: 'nvme',        name: 'WD / SanDisk NVMe Tools', deviceType: 'storage', tags: ['wd', 'sandisk', 'nvme'] },
  // Marvell SATA
  { pciVendor: '1b4b', pciClass: '01', aptPackage: 'linux-firmware',          kernelModule: 'ahci',        name: 'Marvell SATA Firmware', deviceType: 'storage', tags: ['marvell', 'sata', 'ahci'] },
];

const USB_RULES = [
  { usbVendor: '0bda', aptPackage: 'firmware-realtek',   name: 'Realtek USB Firmware',                    deviceType: 'network', tags: ['realtek', 'usb', 'wifi', 'ethernet'] },
  { usbVendor: '0cf3', aptPackage: 'firmware-atheros',   name: 'Atheros USB Wireless Firmware',           deviceType: 'network', tags: ['atheros', 'usb', 'wifi'] },
  { usbVendor: '148f', aptPackage: 'firmware-ralink',    name: 'Ralink / MediaTek USB Wireless Firmware', deviceType: 'network', tags: ['ralink', 'mediatek', 'usb', 'wifi'] },
  { usbVendor: '0a5c', aptPackage: 'firmware-brcm80211', name: 'Broadcom USB Bluetooth/WiFi Firmware',    deviceType: 'network', tags: ['broadcom', 'bluetooth', 'usb'] },
  { usbVendor: '8087', aptPackage: 'firmware-iwlwifi',   name: 'Intel USB Bluetooth Firmware',            deviceType: 'network', tags: ['intel', 'bluetooth', 'usb'] },
  { usbVendor: '04b4', aptPackage: 'linux-firmware',     name: 'Cypress USB Firmware',                    deviceType: 'usb',     tags: ['cypress', 'usb'] },
];

// ─── Universal Linux firmware (always recommended on Linux) ──────────────────

const UNIVERSAL_LINUX = [
  {
    id: 'linux-firmware',
    name: 'linux-firmware (comprehensive firmware collection)',
    version: 'latest',
    vendor: 'Linux',
    os: ['linux'],
    deviceType: 'firmware',
    format: 'deb',
    architecture: 'universal',
    description: 'Firmware blobs for WiFi, Bluetooth, GPU, NIC and more — covers most hardware',
    downloadUrl: '',
    aptPackage: 'linux-firmware',
    tags: ['firmware', 'universal', 'linux'],
    licenseType: 'open-source',
  },
  {
    id: 'fwupd',
    name: 'fwupd (LVFS firmware updater)',
    version: 'latest',
    vendor: 'Linux',
    os: ['linux'],
    deviceType: 'firmware',
    format: 'deb',
    architecture: 'universal',
    description: 'Update BIOS, EC and device firmware from Dell, HP, Lenovo and 100+ vendors via LVFS',
    downloadUrl: '',
    aptPackage: 'fwupd',
    tags: ['firmware', 'fwupd', 'lvfs', 'bios'],
    licenseType: 'open-source',
  },
];

// ─── Parser ───────────────────────────────────────────────────────────────────

/**
 * Parse hardware IDs from lspci -n and lsusb output lines, or from
 * Windows PnP ID strings (cross-platform hardware report).
 *
 * @param {Array<string|object>} hardwareIds
 * @returns {{ pciDevices: PciDevice[], usbVendors: string[] }}
 */
function parseHardwareIds(hardwareIds = []) {
  const pciDevices = [];
  const usbVendors = new Set();

  for (const entry of hardwareIds) {
    const isObject = typeof entry === 'object' && entry !== null;
    const rawId = (isObject ? (entry.deviceId || entry.id || '') : entry).toString();
    const id = rawId.toLowerCase().trim();

    // Bus/class hint from the agent's report ("usb" for lsusb entries,
    // a 4-hex-digit PCI class like "0300" for lspci entries).
    const entryClass = isObject ? String(entry.class || '').toLowerCase().replace(/:$/, '') : '';
    const isUsbEntry = entryClass === 'usb';
    const pciClassHint = /^[0-9a-f]{4}$/.test(entryClass) ? entryClass : null;

    // Windows PnP PCI format: PCI\VEN_8086&DEV_9A49&CC_030000
    if (id.startsWith('pci\\')) {
      const ven = id.match(/ven_([0-9a-f]{4})/)?.[1];
      const cls = id.match(/cc_([0-9a-f]{4,6})/)?.[1]?.substring(0, 4);
      if (ven) pciDevices.push({ vendorId: ven, classId: cls || null });
      continue;
    }

    // Windows PnP USB format: USB\VID_0BDA&PID_8153
    if (id.startsWith('usb\\')) {
      const vid = id.match(/vid_([0-9a-f]{4})/)?.[1];
      if (vid) usbVendors.add(vid);
      continue;
    }

    // Bare "vendor:device" pairs from lspci -n / lsusb — the shape is
    // identical for PCI and USB, so the entry's class field decides.
    const pair = id.match(/(?:^|id\s+)([0-9a-f]{4}):([0-9a-f]{4})(?:\s+\(?([0-9a-f]{4})\)?)?/);
    if (!pair) continue;

    if (isUsbEntry) {
      usbVendors.add(pair[1]);
    } else {
      pciDevices.push({
        vendorId: pair[1],
        deviceId: pair[2],
        classId:  pciClassHint || (pair[3] ? pair[3].substring(0, 4) : null),
      });
    }
  }

  return { pciDevices, usbVendors: [...usbVendors] };
}

/**
 * Match hardware IDs to driver packages.
 * Returns an array of driver entries (with aptPackage, kernelModule, matchedVia).
 *
 * @param {{ pciDevices, usbVendors }}  parsed   — from parseHardwareIds()
 * @param {{ manufacturer?, model? }}   device
 * @returns {DriverEntry[]}
 */
function matchFromHardware({ pciDevices, usbVendors }, device = {}) {
  const results = [];
  const seen = new Set();

  const push = (rule, matchedVia, score) => {
    const key = rule.aptPackage;
    if (seen.has(key)) return;
    seen.add(key);
    results.push({
      id:           `linux-${rule.aptPackage}`,
      name:         rule.name,
      version:      'latest',
      vendor:       device.manufacturer || 'Linux',
      os:           ['linux'],
      deviceType:   rule.deviceType,
      format:       'deb',
      architecture: 'universal',
      description:  `apt install ${rule.aptPackage}` + (rule.kernelModule ? ` (kernel: ${rule.kernelModule})` : ''),
      downloadUrl:  '',
      aptPackage:   rule.aptPackage,
      kernelModule: rule.kernelModule || null,
      models:       [],
      tags:         rule.tags || [],
      licenseType:  'open-source',
      matchScore:   score,
      matchedVia,
    });
  };

  for (const pci of pciDevices) {
    for (const rule of PCI_RULES) {
      if (rule.pciVendor !== pci.vendorId) continue;
      if (rule.pciClass && pci.classId && !pci.classId.startsWith(rule.pciClass)) continue;
      push(rule, 'pci-id', 15);
    }
  }

  for (const vid of usbVendors) {
    for (const rule of USB_RULES) {
      if (rule.usbVendor !== vid) continue;
      push(rule, 'usb-id', 12);
    }
  }

  return results;
}

/**
 * Universal Linux recommendations (always added regardless of hardware).
 */
function universalRecommendations() {
  return UNIVERSAL_LINUX.map(d => ({ ...d, matchScore: 5, matchedVia: 'universal-linux' }));
}

/**
 * Check if a driver entry is Linux-compatible.
 */
function isLinuxCompatible(driver) {
  return Array.isArray(driver.os) && driver.os.includes('linux');
}

module.exports = { parseHardwareIds, matchFromHardware, universalRecommendations, isLinuxCompatible, PCI_CLASS_TO_TYPE };
