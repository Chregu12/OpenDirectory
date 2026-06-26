'use strict';

const https = require('https');
const http = require('http');
const winston = require('winston');

const PRINTER_SERVICE_URL = (process.env.PRINTER_SERVICE_URL || 'http://printer-service:3006').replace(/\/$/, '');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

// ─── PCI vendor ID → kernel driver / apt package mapping ─────────────────────
// Covers the most common hardware encountered in corporate Linux environments.
// pciId format: "vendorId:deviceId" or "vendorId:*" for all devices of a vendor.
const PCI_DRIVER_MAP = [
  // ── Intel WiFi / iwlwifi ──
  { pciVendor: '8086', pciClass: '0280', aptPackage: 'firmware-iwlwifi', name: 'Intel Wireless Firmware (iwlwifi)', deviceType: 'network', os: ['linux'], tags: ['wifi', 'intel', 'iwlwifi', 'firmware'] },
  // ── Broadcom WiFi ──
  { pciVendor: '14e4', pciClass: '0280', aptPackage: 'broadcom-sta-dkms', name: 'Broadcom STA Wireless Driver (DKMS)', deviceType: 'network', os: ['linux'], tags: ['wifi', 'broadcom', 'wlan', 'dkms'] },
  { pciVendor: '14e4', pciClass: '0280', aptPackage: 'firmware-brcm80211', name: 'Broadcom 802.11 Firmware', deviceType: 'network', os: ['linux'], tags: ['wifi', 'broadcom', 'brcmfmac'] },
  // ── Atheros / Qualcomm WiFi ──
  { pciVendor: '168c', pciClass: '0280', aptPackage: 'firmware-atheros', name: 'Atheros / Qualcomm Wireless Firmware', deviceType: 'network', os: ['linux'], tags: ['wifi', 'atheros', 'ath10k', 'ath11k'] },
  // ── Realtek WiFi ──
  { pciVendor: '10ec', pciClass: '0280', aptPackage: 'firmware-realtek', name: 'Realtek Wireless Firmware', deviceType: 'network', os: ['linux'], tags: ['wifi', 'realtek', 'rtl8821', 'rtl8822'] },
  // ── Realtek Ethernet ──
  { pciVendor: '10ec', pciClass: '0200', aptPackage: 'firmware-realtek', name: 'Realtek Ethernet Firmware', deviceType: 'network', os: ['linux'], tags: ['ethernet', 'realtek', 'r8169'] },
  // ── Intel Ethernet (e1000e / igb / ice — in-kernel, but firmware needed) ──
  { pciVendor: '8086', pciClass: '0200', aptPackage: 'linux-firmware', name: 'Intel Ethernet Firmware (linux-firmware)', deviceType: 'network', os: ['linux'], tags: ['ethernet', 'intel', 'e1000e', 'igb', 'ice'] },
  // ── NVIDIA GPU ──
  { pciVendor: '10de', pciClass: '0300', aptPackage: 'nvidia-driver', name: 'NVIDIA Graphics Driver', deviceType: 'display', os: ['linux'], tags: ['nvidia', 'gpu', 'cuda', 'display'] },
  { pciVendor: '10de', pciClass: '0302', aptPackage: 'nvidia-driver', name: 'NVIDIA 3D Controller Driver', deviceType: 'display', os: ['linux'], tags: ['nvidia', 'gpu', 'optimus'] },
  // ── AMD / ATI GPU ──
  { pciVendor: '1002', pciClass: '0300', aptPackage: 'firmware-amd-graphics', name: 'AMD / ATI Radeon Firmware (amdgpu)', deviceType: 'display', os: ['linux'], tags: ['amd', 'radeon', 'amdgpu', 'firmware'] },
  // ── Intel HD / UHD / Iris (in-kernel i915) ──
  { pciVendor: '8086', pciClass: '0300', aptPackage: 'intel-media-va-driver', name: 'Intel Media VA Driver (hardware video accel)', deviceType: 'display', os: ['linux'], tags: ['intel', 'uhd', 'iris', 'vaapi', 'media'] },
  // ── Realtek HD Audio ──
  { pciVendor: '10ec', pciClass: '0403', aptPackage: 'alsa-firmware-loaders', name: 'Realtek HD Audio Firmware', deviceType: 'audio', os: ['linux'], tags: ['audio', 'realtek', 'hda', 'alsa'] },
  // ── Intel HDA ──
  { pciVendor: '8086', pciClass: '0403', aptPackage: 'alsa-firmware-loaders', name: 'Intel HD Audio Firmware', deviceType: 'audio', os: ['linux'], tags: ['audio', 'intel', 'hda', 'alsa'] },
  // ── NVMe SSD ──
  { pciVendor: '144d', pciClass: '0108', aptPackage: 'nvme-cli', name: 'Samsung NVMe Tools (nvme-cli)', deviceType: 'storage', os: ['linux'], tags: ['nvme', 'samsung', 'ssd'] },
  { pciVendor: '15b7', pciClass: '0108', aptPackage: 'nvme-cli', name: 'WD / SanDisk NVMe Tools (nvme-cli)', deviceType: 'storage', os: ['linux'], tags: ['nvme', 'wd', 'ssd'] },
  // ── Thunderbolt ──
  { pciVendor: '8086', pciClass: '0c0a', aptPackage: 'bolt', name: 'Thunderbolt Device Manager (bolt)', deviceType: 'usb', os: ['linux'], tags: ['thunderbolt', 'intel', 'bolt'] },
];

// ─── USB vendor ID → driver mapping ──────────────────────────────────────────
const USB_DRIVER_MAP = [
  { usbVendor: '0bda', aptPackage: 'firmware-realtek', name: 'Realtek USB Firmware', deviceType: 'network', os: ['linux'], tags: ['realtek', 'usb', 'wifi', 'ethernet'] },
  { usbVendor: '0cf3', aptPackage: 'firmware-atheros', name: 'Atheros USB Wireless Firmware', deviceType: 'network', os: ['linux'], tags: ['atheros', 'usb', 'wifi'] },
  { usbVendor: '148f', aptPackage: 'firmware-ralink', name: 'Ralink / MediaTek USB Wireless Firmware', deviceType: 'network', os: ['linux'], tags: ['ralink', 'mediatek', 'usb', 'wifi'] },
  { usbVendor: '0a5c', aptPackage: 'firmware-brcm80211', name: 'Broadcom USB Bluetooth / WiFi Firmware', deviceType: 'network', os: ['linux'], tags: ['broadcom', 'bluetooth', 'usb'] },
];

// ─── Universal Linux firmware packages (always recommended) ──────────────────
const LINUX_UNIVERSAL = [
  { id: 'linux-firmware-universal', name: 'linux-firmware (comprehensive firmware collection)', version: 'latest', vendor: 'Linux', os: ['linux'], deviceType: 'firmware', format: 'deb', architecture: 'universal', description: 'Meta-package providing firmware for a wide range of hardware (WiFi, Bluetooth, GPU, NIC)', downloadUrl: '', aptPackage: 'linux-firmware', tags: ['firmware', 'universal', 'linux'], licenseType: 'open-source' },
  { id: 'fwupd', name: 'fwupd (LVFS firmware updater)', version: 'latest', vendor: 'Linux', os: ['linux'], deviceType: 'firmware', format: 'deb', architecture: 'universal', description: 'Firmware update daemon — supports Dell, HP, Lenovo, and 100+ other vendors via LVFS', downloadUrl: '', aptPackage: 'fwupd', tags: ['firmware', 'fwupd', 'lvfs', 'uefi', 'update'], licenseType: 'open-source' },
];

// ─── Vendor-specific Linux entries ────────────────────────────────────────────
const STATIC_CATALOG = {
  hp: [
    // Windows
    { id: 'hp-net-broadcom-win', name: 'HP Broadcom NetXtreme Gigabit Network Driver', version: '22.4.0.0', vendor: 'HP', os: ['windows'], deviceType: 'network', format: 'exe', architecture: 'x86_64', description: 'Broadcom NetXtreme Gigabit Ethernet driver for HP workstations', downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp138452.exe', models: ['Z4 G4', 'Z6 G4', 'Z8 G4'], fileSize: 9437184, tags: ['network', 'broadcom', 'gigabit'], licenseType: 'freeware' },
    { id: 'hp-audio-conexant-win', name: 'HP Conexant SmartAudio Driver', version: '9.0.232.0', vendor: 'HP', os: ['windows'], deviceType: 'audio', format: 'exe', architecture: 'x86_64', description: 'Conexant SmartAudio driver for HP EliteBook / ProBook series', downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp138000.exe', models: ['EliteBook 840 G9', 'ProBook 450 G9'], fileSize: 52428800, tags: ['audio', 'conexant'], licenseType: 'freeware' },
    { id: 'hp-display-intel-win', name: 'HP Intel Iris Xe Graphics Driver', version: '31.0.101.2115', vendor: 'HP', os: ['windows'], deviceType: 'display', format: 'exe', architecture: 'x86_64', description: 'Intel Iris Xe graphics driver for HP EliteBook 12th gen', downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp139000.exe', models: ['EliteBook 840 G9', 'EliteBook 1040 G9'], fileSize: 167772160, tags: ['display', 'intel', 'iris'], licenseType: 'freeware' },
    // Linux
    { id: 'hp-hplip-linux', name: 'HPLIP (HP Linux Imaging and Printing)', version: '3.23.3', vendor: 'HP', os: ['linux'], deviceType: 'printer', format: 'deb', architecture: 'x86_64', description: 'HP Linux Imaging and Printing — supports 3000+ HP printers and scanners', downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/printers/hpijs/hplip-3.23.3.run', models: ['LaserJet Pro', 'OfficeJet Pro', 'DeskJet', 'ENVY'], aptPackage: 'hplip', tags: ['hplip', 'linux', 'cups', 'printer'], licenseType: 'open-source' },
    { id: 'hp-firmware-linux', name: 'HP Firmware Update (fwupd / LVFS)', version: 'latest', vendor: 'HP', os: ['linux'], deviceType: 'firmware', format: 'deb', architecture: 'universal', description: 'HP firmware updates via LVFS — BIOS, network, storage controller', downloadUrl: '', models: ['EliteBook', 'ProBook', 'ZBook', 'EliteDesk'], aptPackage: 'fwupd', tags: ['firmware', 'fwupd', 'lvfs', 'hp'], licenseType: 'open-source' },
    { id: 'hp-net-linux', name: 'HP Network Driver (iwlwifi / bnx2)', version: 'latest', vendor: 'HP', os: ['linux'], deviceType: 'network', format: 'deb', architecture: 'x86_64', description: 'Firmware for Intel and Broadcom NICs found in HP workstations', downloadUrl: '', models: ['Z4 G4', 'Z6 G4', 'EliteBook 840 G9'], aptPackage: 'firmware-iwlwifi', tags: ['network', 'intel', 'broadcom', 'linux'], licenseType: 'open-source' },
  ],
  lenovo: [
    // Windows
    { id: 'lenovo-net-i219-win', name: 'Lenovo ThinkPad Intel I219-LM Ethernet Driver', version: '12.19.2.36', vendor: 'Lenovo', os: ['windows'], deviceType: 'network', format: 'exe', architecture: 'x86_64', description: 'Intel I219-LM Gigabit Ethernet driver for ThinkPad', downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r0xne05w.exe', models: ['ThinkPad T14 Gen 3', 'ThinkPad L14 Gen 3'], fileSize: 8388608, tags: ['network', 'ethernet', 'intel'], licenseType: 'freeware' },
    { id: 'lenovo-audio-realtek-win', name: 'Lenovo ThinkPad Realtek Audio Driver', version: '6.0.9374.1', vendor: 'Lenovo', os: ['windows'], deviceType: 'audio', format: 'exe', architecture: 'x86_64', description: 'Realtek HD Audio driver for ThinkPad', downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r0xau12w.exe', models: ['ThinkPad T14 Gen 3', 'ThinkPad X1 Carbon Gen 10'], fileSize: 262144000, tags: ['audio', 'realtek'], licenseType: 'freeware' },
    { id: 'lenovo-display-iris-win', name: 'Lenovo ThinkPad Intel Iris Xe Graphics Driver', version: '31.0.101.2115', vendor: 'Lenovo', os: ['windows'], deviceType: 'display', format: 'exe', architecture: 'x86_64', description: 'Intel Iris Xe Graphics driver for ThinkPad 12th gen', downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r1xvd04w.exe', models: ['ThinkPad X1 Carbon Gen 10', 'ThinkPad T14s Gen 3'], fileSize: 167772160, tags: ['display', 'intel', 'iris'], licenseType: 'freeware' },
    // Linux
    { id: 'lenovo-firmware-linux', name: 'Lenovo Firmware Update (fwupd / LVFS)', version: 'latest', vendor: 'Lenovo', os: ['linux'], deviceType: 'firmware', format: 'deb', architecture: 'universal', description: 'BIOS, EC and embedded controller updates via LVFS — ThinkPad / IdeaPad / Legion', downloadUrl: '', models: ['ThinkPad T14 Gen 3', 'ThinkPad X1 Carbon Gen 10', 'ThinkPad L14 Gen 3'], aptPackage: 'fwupd', tags: ['firmware', 'fwupd', 'lvfs', 'thinkpad'], licenseType: 'open-source' },
    { id: 'lenovo-wifi-linux', name: 'Lenovo ThinkPad Intel WiFi Firmware (iwlwifi)', version: 'latest', vendor: 'Lenovo', os: ['linux'], deviceType: 'network', format: 'deb', architecture: 'universal', description: 'Intel iwlwifi firmware for ThinkPad wireless adapters (AX200 / AX210 / AX211)', downloadUrl: '', models: ['ThinkPad X1 Carbon Gen 10', 'ThinkPad T14s Gen 3', 'ThinkPad T14 Gen 3'], aptPackage: 'firmware-iwlwifi', tags: ['wifi', 'intel', 'iwlwifi', 'ax210', 'ax211', 'linux'], licenseType: 'open-source' },
    { id: 'lenovo-throttling-linux', name: 'ThinkPad Throttling Fix (thinkpad-acpi)', version: 'latest', vendor: 'Lenovo', os: ['linux'], deviceType: 'other', format: 'deb', architecture: 'universal', description: 'thinkpad-acpi kernel module fixes CPU throttling on ThinkPad models running Linux', downloadUrl: '', models: ['ThinkPad T14 Gen 3', 'ThinkPad X1 Carbon Gen 10'], aptPackage: 'tp-smapi-dkms', tags: ['thinkpad', 'acpi', 'power', 'linux'], licenseType: 'open-source' },
    { id: 'lenovo-audio-linux', name: 'Lenovo ThinkPad HD Audio (ALSA / snd-hda)', version: 'latest', vendor: 'Lenovo', os: ['linux'], deviceType: 'audio', format: 'deb', architecture: 'universal', description: 'ALSA firmware for Realtek / Conexant audio on ThinkPad', downloadUrl: '', models: ['ThinkPad T14 Gen 3', 'ThinkPad X1 Carbon Gen 10'], aptPackage: 'alsa-firmware-loaders', tags: ['audio', 'realtek', 'alsa', 'thinkpad', 'linux'], licenseType: 'open-source' },
  ],
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normalizeVendor(raw) {
  if (!raw) return null;
  const v = raw.toLowerCase();
  if (v.includes('dell')) return 'dell';
  if (v.includes('hp') || v.includes('hewlett')) return 'hp';
  if (v.includes('lenovo')) return 'lenovo';
  if (v.includes('microsoft')) return 'microsoft';
  if (v.includes('apple')) return 'apple';
  if (v.includes('asus')) return 'asus';
  if (v.includes('acer')) return 'acer';
  if (v.includes('toshiba')) return 'toshiba';
  if (v.includes('fujitsu')) return 'fujitsu';
  return v;
}

function scoreMatch(driver, { model, os }) {
  let score = 0;
  if (model && driver.models) {
    const m = model.toLowerCase();
    for (const dm of driver.models) {
      if (dm.toLowerCase().includes(m) || m.includes(dm.toLowerCase())) {
        score += 20;
        break;
      }
    }
  }
  if (os && driver.os && driver.os.includes(os.toLowerCase())) score += 10;
  return score;
}

function fetchJson(url, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const proto = url.startsWith('https') ? https : http;
    const req = proto.get(url, { headers: { 'User-Agent': 'OpenDirectory/1.0' } }, res => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return fetchJson(res.headers.location, timeoutMs).then(resolve).catch(reject);
      }
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(new Error('Invalid JSON')); }
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('Timeout')); });
    req.on('error', reject);
  });
}

// ─── Main service ─────────────────────────────────────────────────────────────

class DriverMatchingService {
  async matchDrivers({ manufacturer, model, os, hardwareIds = [] }) {
    const vendor = normalizeVendor(manufacturer);
    const osLabel = this._normalizeOs(os);

    logger.info('Driver matching', { vendor, model, osLabel, pciDevices: hardwareIds.length });

    const results = [];
    const seen = new Set();

    const push = (driver, extra = {}) => {
      const key = driver.id || driver.aptPackage || driver.name;
      if (seen.has(key)) return;
      seen.add(key);
      results.push({ ...driver, ...extra });
    };

    // ── Dell: live catalog ──
    if (vendor === 'dell') {
      try {
        const q   = model ? encodeURIComponent(model) : '';
        const sm  = model ? `&systemModel=${encodeURIComponent(model)}` : '';
        const osp = osLabel ? `&os=${osLabel}` : '';
        const url = `${PRINTER_SERVICE_URL}/api/printer/catalog/dell?q=${q}${sm}${osp}`;
        const data = await fetchJson(url, 15000);
        if (data && Array.isArray(data.results)) {
          for (const d of data.results) {
            push(d, { matchScore: scoreMatch(d, { model, os: osLabel }), matchedVia: 'dell-catalog' });
          }
        }
      } catch (err) {
        logger.warn('Dell catalog query failed', { message: err.message });
      }
    }

    // ── Static catalog (HP, Lenovo, …) ──
    const staticEntries = STATIC_CATALOG[vendor] || [];
    for (const d of staticEntries) {
      if (osLabel && !d.os.includes(osLabel)) continue;
      push(d, { matchScore: scoreMatch(d, { model, os: osLabel }), matchedVia: 'static-catalog' });
    }

    // ── Linux: PCI-ID-based matching ──
    if (osLabel === 'linux' && hardwareIds.length > 0) {
      const pciIds  = this._extractPciIds(hardwareIds);
      const usbIds  = this._extractUsbIds(hardwareIds);

      for (const { vendorId, classId } of pciIds) {
        for (const rule of PCI_DRIVER_MAP) {
          if (rule.pciVendor !== vendorId) continue;
          if (rule.pciClass && classId && !classId.startsWith(rule.pciClass.substring(0, 2))) continue;
          push({
            id: `pci-${vendorId}-${rule.aptPackage}`,
            name: rule.name,
            version: 'latest',
            vendor: manufacturer || 'Linux',
            os: rule.os,
            deviceType: rule.deviceType,
            format: 'deb',
            architecture: 'universal',
            description: `apt install ${rule.aptPackage}`,
            downloadUrl: '',
            aptPackage: rule.aptPackage,
            models: [],
            tags: rule.tags,
            licenseType: 'open-source',
          }, { matchScore: 15, matchedVia: 'pci-id' });
        }
      }

      for (const usbVendorId of usbIds) {
        for (const rule of USB_DRIVER_MAP) {
          if (rule.usbVendor !== usbVendorId) continue;
          push({
            id: `usb-${usbVendorId}-${rule.aptPackage}`,
            name: rule.name,
            version: 'latest',
            vendor: manufacturer || 'Linux',
            os: rule.os,
            deviceType: rule.deviceType,
            format: 'deb',
            architecture: 'universal',
            description: `apt install ${rule.aptPackage}`,
            downloadUrl: '',
            aptPackage: rule.aptPackage,
            models: [],
            tags: rule.tags,
            licenseType: 'open-source',
          }, { matchScore: 12, matchedVia: 'usb-id' });
        }
      }

      // Always recommend universal firmware on Linux
      for (const u of LINUX_UNIVERSAL) {
        push({ ...u, matchScore: 5, matchedVia: 'universal-linux' });
      }
    }

    results.sort((a, b) => (b.matchScore || 0) - (a.matchScore || 0));
    return results;
  }

  // Parse PCI IDs from hardwareIds array.
  // Expected formats: "PCI\\VEN_8086&DEV_1502&..." (Windows) or "8086:1502 0200" (lspci -n)
  _extractPciIds(hardwareIds) {
    const ids = [];
    for (const entry of hardwareIds) {
      const devId = (entry.deviceId || entry.id || entry || '').toString().toLowerCase();

      // Windows PnP format: PCI\VEN_8086&DEV_1502&CC_020000
      const winMatch = devId.match(/ven_([0-9a-f]{4}).*cc_([0-9a-f]{4,6})/);
      if (winMatch) {
        ids.push({ vendorId: winMatch[1], classId: winMatch[2].substring(0, 4) });
        continue;
      }

      // Linux lspci -n format: "8086:1502 (0200)" or just "8086:1502"
      const linuxMatch = devId.match(/^([0-9a-f]{4}):([0-9a-f]{4})(?:\s+\(?([0-9a-f]{4})\)?)?/);
      if (linuxMatch) {
        ids.push({ vendorId: linuxMatch[1], deviceId: linuxMatch[2], classId: linuxMatch[3] || null });
      }
    }
    return ids;
  }

  // Parse USB vendor IDs.
  // Expected: "USB\VID_0BDA&PID_8179" (Windows) or "0bda:8179" (lsusb)
  _extractUsbIds(hardwareIds) {
    const vendors = new Set();
    for (const entry of hardwareIds) {
      const devId = (entry.deviceId || entry.id || entry || '').toString().toLowerCase();
      const winMatch  = devId.match(/vid_([0-9a-f]{4})/);
      if (winMatch)  { vendors.add(winMatch[1]); continue; }
      const linMatch  = devId.match(/^([0-9a-f]{4}):[0-9a-f]{4}/);
      if (linMatch)  vendors.add(linMatch[1]);
    }
    return [...vendors];
  }

  _normalizeOs(raw) {
    if (!raw) return null;
    const s = (raw || '').toLowerCase();
    if (s.includes('windows')) return 'windows';
    if (s.includes('linux')) return 'linux';
    if (s.includes('mac') || s.includes('darwin')) return 'macos';
    return null;
  }
}

module.exports = new DriverMatchingService();
