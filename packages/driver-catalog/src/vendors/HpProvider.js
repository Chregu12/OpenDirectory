'use strict';

// ─── HP Driver Provider ───────────────────────────────────────────────────────
// All HP device driver entries — both Windows (exe/msi) and Linux (deb/apt).
// Platform-specific filtering is done by the DriverCatalog orchestrator.

const DRIVERS = [
  // ── Windows ──────────────────────────────────────────────────────────────────

  {
    id: 'hp-net-broadcom-win',
    name: 'HP Broadcom NetXtreme Gigabit Network Driver',
    version: '22.4.0.0',
    vendor: 'HP',
    os: ['windows'],
    deviceType: 'network',
    format: 'exe',
    architecture: 'x86_64',
    description: 'Broadcom NetXtreme Gigabit Ethernet driver for HP workstations',
    downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp138452.exe',
    models: ['Z4 G4', 'Z6 G4', 'Z8 G4', 'EliteDesk 800 G9'],
    tags: ['network', 'broadcom', 'gigabit', 'workstation'],
    licenseType: 'freeware',
  },
  {
    id: 'hp-audio-conexant-win',
    name: 'HP Conexant SmartAudio Driver',
    version: '9.0.232.0',
    vendor: 'HP',
    os: ['windows'],
    deviceType: 'audio',
    format: 'exe',
    architecture: 'x86_64',
    description: 'Conexant SmartAudio HD driver for HP EliteBook and ProBook',
    downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp138000.exe',
    models: ['EliteBook 840 G9', 'EliteBook 860 G9', 'ProBook 450 G9', 'ProBook 640 G8'],
    tags: ['audio', 'conexant', 'hda'],
    licenseType: 'freeware',
  },
  {
    id: 'hp-display-intel-win',
    name: 'HP Intel Iris Xe Graphics Driver',
    version: '31.0.101.2115',
    vendor: 'HP',
    os: ['windows'],
    deviceType: 'display',
    format: 'exe',
    architecture: 'x86_64',
    description: 'Intel Iris Xe iGPU driver optimised for HP EliteBook 12th generation',
    downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp139000.exe',
    models: ['EliteBook 840 G9', 'EliteBook 1040 G9', 'ZBook Firefly 14 G9'],
    tags: ['display', 'intel', 'iris', 'xe', 'igpu'],
    licenseType: 'freeware',
  },
  {
    id: 'hp-wifi-intel-ax211-win',
    name: 'HP Intel Wi-Fi 6E AX211 Driver',
    version: '22.230.0.8',
    vendor: 'HP',
    os: ['windows'],
    deviceType: 'network',
    format: 'exe',
    architecture: 'x86_64',
    description: 'Intel Wi-Fi 6E AX211 wireless adapter driver for HP EliteBook',
    downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp140000.exe',
    models: ['EliteBook 840 G9', 'EliteBook 850 G9', 'ZBook Firefly 14 G9'],
    tags: ['wifi', 'intel', 'ax211', '6e', 'wireless'],
    licenseType: 'freeware',
  },
  {
    id: 'hp-bios-elitebook840g9-win',
    name: 'HP EliteBook 840 G9 BIOS Update',
    version: 'T87 Ver. 01.10.00',
    vendor: 'HP',
    os: ['windows'],
    deviceType: 'firmware',
    format: 'exe',
    architecture: 'x86_64',
    description: 'System BIOS update for HP EliteBook 840 G9 — security patches and stability',
    downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp141000.exe',
    models: ['EliteBook 840 G9'],
    tags: ['bios', 'firmware', 'elitebook'],
    licenseType: 'freeware',
  },

  // ── Linux ─────────────────────────────────────────────────────────────────────

  {
    id: 'hp-hplip-linux',
    name: 'HPLIP (HP Linux Imaging and Printing)',
    version: '3.23.3',
    vendor: 'HP',
    os: ['linux'],
    deviceType: 'printer',
    // downloadUrl is a self-extracting .run installer, not a .deb package —
    // keep this in sync with the same id in printer-service's
    // driverCatalogManager.js MANUFACTURER_CATALOG.hp (see comment there).
    format: 'run',
    architecture: 'x86_64',
    description: 'Supports 3000+ HP printers and scanners on Linux via CUPS',
    downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/printers/hpijs/hplip-3.23.3.run',
    models: ['LaserJet Pro', 'OfficeJet Pro', 'DeskJet', 'ENVY', 'Color LaserJet'],
    aptPackage: 'hplip',
    tags: ['hplip', 'linux', 'cups', 'printer', 'scanner'],
    licenseType: 'open-source',
  },
  {
    id: 'hp-fwupd-linux',
    name: 'HP Firmware Update (fwupd / LVFS)',
    version: 'latest',
    vendor: 'HP',
    os: ['linux'],
    deviceType: 'firmware',
    format: 'deb',
    architecture: 'universal',
    description: 'HP BIOS, network adapter and storage controller firmware via LVFS',
    downloadUrl: '',
    models: ['EliteBook', 'ProBook', 'ZBook', 'EliteDesk', 'ProDesk'],
    aptPackage: 'fwupd',
    tags: ['firmware', 'fwupd', 'lvfs', 'bios', 'hp'],
    licenseType: 'open-source',
  },
  {
    id: 'hp-wifi-linux',
    name: 'HP Intel WiFi Firmware (iwlwifi)',
    version: 'latest',
    vendor: 'HP',
    os: ['linux'],
    deviceType: 'network',
    format: 'deb',
    architecture: 'universal',
    description: 'iwlwifi firmware for Intel WiFi cards in HP EliteBook / ZBook',
    downloadUrl: '',
    models: ['EliteBook 840 G9', 'EliteBook 850 G9', 'ZBook Firefly 14 G9'],
    aptPackage: 'firmware-iwlwifi',
    tags: ['wifi', 'intel', 'iwlwifi', 'linux'],
    licenseType: 'open-source',
  },
  {
    id: 'hp-audio-alsa-linux',
    name: 'HP Conexant HD Audio (ALSA)',
    version: 'latest',
    vendor: 'HP',
    os: ['linux'],
    deviceType: 'audio',
    format: 'deb',
    architecture: 'universal',
    description: 'ALSA firmware for Conexant SmartAudio on HP EliteBook',
    downloadUrl: '',
    models: ['EliteBook 840 G9', 'ProBook 450 G9'],
    aptPackage: 'alsa-firmware-loaders',
    tags: ['audio', 'conexant', 'alsa', 'linux'],
    licenseType: 'open-source',
  },
];

/**
 * Return all HP driver entries.
 * @returns {DriverEntry[]}
 */
function getDrivers() {
  return DRIVERS;
}

module.exports = { getDrivers };
