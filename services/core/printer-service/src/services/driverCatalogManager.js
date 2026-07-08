'use strict';

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const https = require('https');
const http = require('http');
const { execFile } = require('child_process');
const crypto = require('crypto');
const winston = require('winston');

const dellCatalog = require('./dellCatalogService');

// ─── Logger ──────────────────────────────────────────────────────────────────

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'printer-service.log' }),
  ],
});

// ─── Storage paths ────────────────────────────────────────────────────────────

const PRINTER_DRIVER_DIR = process.env.PRINTER_DRIVERS_DIR || '/var/lib/opendirectory/printer-drivers';
const DEVICE_DRIVER_DIR  = process.env.DEVICE_DRIVERS_DIR || '/var/lib/opendirectory/device-drivers';

// ─── Manufacturer Catalog ─────────────────────────────────────────────────────

// Dell entries come from the live DellCatalogService (dellCatalogService.js).
// Static entries below cover HP, Lenovo, Brother, Canon, Epson, and Generic only.

const MANUFACTURER_CATALOG = {

  hp: [
    {
      id: 'hp-upd-pcl6-win',
      name: 'HP Universal Print Driver for Windows (PCL6)',
      version: '7.0.1.24923',
      vendor: 'HP',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'HP Universal Print Driver (UPD) PCL6 — supports hundreds of HP printers on Windows',
      downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/printers/UPD/upd-pcl6-x64-7.0.1.24923.exe',
      models: ['Universal — all HP LaserJet/OfficeJet Pro/Color LaserJet'],
      fileSize: 52428800,
      tags: ['universal', 'pcl6', 'upd', 'laserjet'],
      licenseType: 'freeware',
    },
    {
      id: 'hp-upd-ps-win',
      name: 'HP Universal Print Driver for Windows (PostScript)',
      version: '7.0.1.24923',
      vendor: 'HP',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'HP Universal Print Driver (UPD) PostScript — ideal for graphics-intensive printing',
      downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/printers/UPD/upd-ps-x64-7.0.1.24923.exe',
      models: ['Universal — all HP PostScript-capable printers'],
      fileSize: 47185920,
      tags: ['universal', 'postscript', 'upd', 'laserjet'],
      licenseType: 'freeware',
    },
    {
      id: 'hp-laserjet-p1005-ppd',
      name: 'HP LaserJet P1005 PPD (Linux/macOS)',
      version: '20230301',
      vendor: 'HP',
      os: ['linux', 'macos'],
      deviceType: 'printer',
      format: 'ppd',
      architecture: 'universal',
      description: 'CUPS PPD for HP LaserJet P1005 — monochrome A4/Letter laser printer',
      downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/printers/hpijs/hplip-3.23.3.run',
      models: ['LaserJet P1005', 'LaserJet P1006'],
      fileSize: 16777216,
      tags: ['ppd', 'cups', 'hplip', 'laserjet', 'mono'],
      licenseType: 'open-source',
    },
    {
      id: 'hp-hplip-linux',
      name: 'HPLIP (HP Linux Imaging and Printing)',
      version: '3.23.3',
      vendor: 'HP',
      os: ['linux'],
      deviceType: 'printer',
      format: 'run',
      architecture: 'x86_64',
      description: 'HP Linux Imaging and Printing — supports 3000+ HP printers under Linux',
      downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/printers/hpijs/hplip-3.23.3.run',
      models: ['LaserJet Pro', 'OfficeJet Pro', 'DeskJet', 'ENVY'],
      fileSize: 25165824,
      tags: ['hplip', 'linux', 'cups', 'universal'],
      licenseType: 'open-source',
    },
    {
      id: 'hp-color-laserjet-m452',
      name: 'HP Color LaserJet Pro M452 Driver',
      version: '15.0.15249.1348',
      vendor: 'HP',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Full feature driver for HP Color LaserJet Pro M452 series',
      downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/printers/CL/CLJ_M452/M452-Full-Solution.exe',
      models: ['Color LaserJet Pro M452dn', 'Color LaserJet Pro M452dw', 'Color LaserJet Pro M452nw'],
      fileSize: 78643200,
      tags: ['color', 'laserjet', 'pcl6', 'postscript'],
      licenseType: 'freeware',
    },
    {
      id: 'hp-officejet-8710-win',
      name: 'HP OfficeJet Pro 8710 Full Feature Driver',
      version: '48.4.4545',
      vendor: 'HP',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Full feature driver and software for HP OfficeJet Pro 8710 multifunction printer',
      downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/printers/OJ/OJP8710/OJP8710-Full-Solution.exe',
      models: ['OfficeJet Pro 8710', 'OfficeJet Pro 8720'],
      fileSize: 94371840,
      tags: ['officejet', 'inkjet', 'multifunction', 'scan'],
      licenseType: 'freeware',
    },
    {
      id: 'hp-network-broadcom',
      name: 'HP Broadcom NetXtreme Gigabit Network Driver',
      version: '22.4.0.0',
      vendor: 'HP',
      os: ['windows'],
      deviceType: 'network',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Broadcom NetXtreme Gigabit Ethernet driver for HP workstations',
      downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/workstation/Z4G4/sp138452.exe',
      models: ['Z4 G4', 'Z6 G4', 'Z8 G4'],
      fileSize: 9437184,
      tags: ['network', 'broadcom', 'gigabit', 'workstation'],
      licenseType: 'freeware',
    },
    {
      id: 'hp-laserjet-m428-ppd',
      name: 'HP LaserJet Pro M428 PPD (CUPS)',
      version: '20230301',
      vendor: 'HP',
      os: ['linux', 'macos'],
      deviceType: 'printer',
      format: 'ppd',
      architecture: 'universal',
      description: 'CUPS PPD for HP LaserJet Pro M428 multifunction printer',
      downloadUrl: 'https://ftp.hp.com/pub/softlib/software13/printers/hpijs/hplip-3.23.3.run',
      models: ['LaserJet Pro M428dw', 'LaserJet Pro M428fdn'],
      fileSize: 16777216,
      tags: ['ppd', 'cups', 'hplip', 'laserjet', 'mfp'],
      licenseType: 'open-source',
    },
  ],

  lenovo: [
    {
      id: 'lenovo-thinkpad-audio',
      name: 'Lenovo ThinkPad Realtek Audio Driver',
      version: '6.0.9374.1',
      vendor: 'Lenovo',
      os: ['windows'],
      deviceType: 'audio',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Realtek HD Audio driver for ThinkPad series laptops',
      downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r0xau12w.exe',
      models: ['ThinkPad T14 Gen 3', 'ThinkPad X1 Carbon Gen 10', 'ThinkPad L14 Gen 3'],
      fileSize: 262144000,
      tags: ['audio', 'realtek', 'thinkpad'],
      licenseType: 'freeware',
    },
    {
      id: 'lenovo-thinkpad-wifi-ax211',
      name: 'Lenovo ThinkPad Intel Wi-Fi 6E AX211 Driver',
      version: '22.230.0.8',
      vendor: 'Lenovo',
      os: ['windows'],
      deviceType: 'network',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Intel Wi-Fi 6E AX211 driver for ThinkPad models with 6 GHz band support',
      downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r1xwf10w.exe',
      models: ['ThinkPad X1 Carbon Gen 10', 'ThinkPad T14s Gen 3', 'ThinkPad T16 Gen 1'],
      fileSize: 15728640,
      tags: ['wifi', 'wireless', 'ax211', '6ghz', 'thinkpad'],
      licenseType: 'freeware',
    },
    {
      id: 'lenovo-thinkpad-ethernet-i219',
      name: 'Lenovo ThinkPad Intel I219-LM Ethernet Driver',
      version: '12.19.2.36',
      vendor: 'Lenovo',
      os: ['windows'],
      deviceType: 'network',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Intel I219-LM Gigabit Ethernet driver for ThinkPad docking and LAN',
      downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r0xne05w.exe',
      models: ['ThinkPad T14 Gen 3', 'ThinkPad L14 Gen 3', 'ThinkPad E14 Gen 4'],
      fileSize: 8388608,
      tags: ['network', 'ethernet', 'intel', 'i219', 'thinkpad'],
      licenseType: 'freeware',
    },
    {
      id: 'lenovo-thinkpad-display-iris',
      name: 'Lenovo ThinkPad Intel Iris Xe Graphics Driver',
      version: '31.0.101.2115',
      vendor: 'Lenovo',
      os: ['windows'],
      deviceType: 'display',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Intel Iris Xe Graphics driver optimised for ThinkPad 12th gen Intel platforms',
      downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r1xvd04w.exe',
      models: ['ThinkPad X1 Carbon Gen 10', 'ThinkPad T14s Gen 3', 'ThinkPad T14 Gen 3'],
      fileSize: 167772160,
      tags: ['display', 'graphics', 'iris', 'xe', 'thinkpad'],
      licenseType: 'freeware',
    },
    {
      id: 'lenovo-thinkpad-fingerprint',
      name: 'Lenovo ThinkPad Fingerprint Reader Driver',
      version: '10.0.19041.10027',
      vendor: 'Lenovo',
      os: ['windows'],
      deviceType: 'biometric',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Synaptics fingerprint reader driver for ThinkPad security chip',
      downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r0xfp04w.exe',
      models: ['ThinkPad T14 Gen 3', 'ThinkPad X1 Carbon Gen 10', 'ThinkPad T16 Gen 1'],
      fileSize: 20971520,
      tags: ['fingerprint', 'biometric', 'synaptics', 'security'],
      licenseType: 'freeware',
    },
    {
      id: 'lenovo-thinkpad-bios-t14g3',
      name: 'Lenovo ThinkPad T14 Gen 3 BIOS Update',
      version: '1.47',
      vendor: 'Lenovo',
      os: ['windows'],
      deviceType: 'firmware',
      format: 'exe',
      architecture: 'x86_64',
      description: 'BIOS update for ThinkPad T14 Gen 3 (AMD) — security and stability improvements',
      downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r1xuj19w.exe',
      models: ['ThinkPad T14 Gen 3'],
      fileSize: 31457280,
      tags: ['bios', 'firmware', 'thinkpad', 'security'],
      licenseType: 'freeware',
    },
    {
      id: 'lenovo-thinkpad-thunderbolt4',
      name: 'Lenovo ThinkPad Thunderbolt 4 Dock Driver',
      version: '1.0.5.1',
      vendor: 'Lenovo',
      os: ['windows'],
      deviceType: 'usb',
      format: 'exe',
      architecture: 'x86_64',
      description: 'ThinkPad Thunderbolt 4 Dock (40B0) driver and firmware package',
      downloadUrl: 'https://download.lenovo.com/pccbbs/options/tp4dock_fw_v1.0.5.1.exe',
      models: ['ThinkPad Thunderbolt 4 Dock Gen 2'],
      fileSize: 52428800,
      tags: ['thunderbolt', 'dock', 'usb4', 'hub'],
      licenseType: 'freeware',
    },
    {
      id: 'lenovo-thinkpad-camera',
      name: 'Lenovo ThinkPad IR & RGB Camera Driver',
      version: '11.3.6.2021',
      vendor: 'Lenovo',
      os: ['windows'],
      deviceType: 'camera',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Integrated IR and RGB webcam driver for ThinkPad facial recognition (Windows Hello)',
      downloadUrl: 'https://download.lenovo.com/pccbbs/mobiles/r0xcm09w.exe',
      models: ['ThinkPad X1 Carbon Gen 10', 'ThinkPad T14 Gen 3', 'ThinkPad T14s Gen 3'],
      fileSize: 13631488,
      tags: ['camera', 'webcam', 'ir', 'windows-hello'],
      licenseType: 'freeware',
    },
  ],

  brother: [
    {
      id: 'brother-mfc-l3770-win',
      name: 'Brother MFC-L3770CDW Driver Package (Windows)',
      version: 'D1',
      vendor: 'Brother',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Full driver and software package for Brother MFC-L3770CDW color laser MFP',
      downloadUrl: 'https://download.brother.com/welcome/dlf006893/MFC-L3770CDW-inst-win-D1.EXE',
      models: ['MFC-L3770CDW'],
      fileSize: 104857600,
      tags: ['color', 'laser', 'mfp', 'multifunction'],
      licenseType: 'freeware',
    },
    {
      id: 'brother-mfc-l3770-linux',
      name: 'Brother MFC-L3770CDW LPR + CUPS Wrapper (Linux)',
      version: '3.5.1',
      vendor: 'Brother',
      os: ['linux'],
      deviceType: 'printer',
      format: 'deb',
      architecture: 'x86_64',
      description: 'LPR driver and CUPS wrapper for Brother MFC-L3770CDW on Debian/Ubuntu',
      downloadUrl: 'https://download.brother.com/welcome/dlf006891/mfcl3770cdwlpr-3.5.1-1.i386.deb',
      models: ['MFC-L3770CDW'],
      fileSize: 10485760,
      tags: ['linux', 'cups', 'lpr', 'debian', 'ubuntu'],
      licenseType: 'freeware',
    },
    {
      id: 'brother-hl-l2370-ppd',
      name: 'Brother HL-L2370DN PPD (Linux/macOS)',
      version: '1.0.4',
      vendor: 'Brother',
      os: ['linux', 'macos'],
      deviceType: 'printer',
      format: 'ppd',
      architecture: 'universal',
      description: 'CUPS PPD file for Brother HL-L2370DN mono laser printer',
      downloadUrl: 'https://download.brother.com/welcome/dlf006887/brhll2370dlpr-3.5.0-1.i386.deb',
      models: ['HL-L2370DN', 'HL-L2370DW'],
      fileSize: 5242880,
      tags: ['ppd', 'cups', 'mono', 'laser'],
      licenseType: 'freeware',
    },
    {
      id: 'brother-dcp-l2550-win',
      name: 'Brother DCP-L2550DN Driver (Windows)',
      version: 'D1',
      vendor: 'Brother',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Full driver package for Brother DCP-L2550DN mono laser multifunction printer',
      downloadUrl: 'https://download.brother.com/welcome/dlf006895/DCPL2550DN-inst-win-D1.EXE',
      models: ['DCP-L2550DN'],
      fileSize: 78643200,
      tags: ['mono', 'laser', 'dcp', 'mfp'],
      licenseType: 'freeware',
    },
    {
      id: 'brother-hl-l3230-macos',
      name: 'Brother HL-L3230CDW Driver (macOS)',
      version: '1.0.2',
      vendor: 'Brother',
      os: ['macos'],
      deviceType: 'printer',
      format: 'pkg',
      architecture: 'universal',
      description: 'macOS CUPS driver package for Brother HL-L3230CDW color laser printer',
      downloadUrl: 'https://download.brother.com/welcome/dlf006789/Brother_PrinterDrivers_ColorLaser_1.0.2.pkg',
      models: ['HL-L3230CDW', 'HL-L3270CDW'],
      fileSize: 26214400,
      tags: ['color', 'laser', 'macos', 'pkg'],
      licenseType: 'freeware',
    },
    {
      id: 'brother-mfc-j995-win',
      name: 'Brother MFC-J995DW Driver Package (Windows)',
      version: 'D1',
      vendor: 'Brother',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Full driver and software for Brother MFC-J995DW ink tank MFP',
      downloadUrl: 'https://download.brother.com/welcome/dlf006901/MFCJ995DW-inst-win-D1.EXE',
      models: ['MFC-J995DW'],
      fileSize: 94371840,
      tags: ['inkjet', 'inktank', 'mfp', 'color'],
      licenseType: 'freeware',
    },
    {
      id: 'brother-hl-l2395-linux',
      name: 'Brother HL-L2395DW CUPS Wrapper (Linux)',
      version: '3.5.0',
      vendor: 'Brother',
      os: ['linux'],
      deviceType: 'printer',
      format: 'deb',
      architecture: 'x86_64',
      description: 'CUPS wrapper driver for Brother HL-L2395DW wireless mono laser printer',
      downloadUrl: 'https://download.brother.com/welcome/dlf006880/brhll2395dwcupswrapper-3.5.0-1.i386.deb',
      models: ['HL-L2395DW'],
      fileSize: 4194304,
      tags: ['cups', 'linux', 'mono', 'laser', 'wireless'],
      licenseType: 'freeware',
    },
    {
      id: 'brother-mfc-l8900-ppd',
      name: 'Brother MFC-L8900CDW PPD (Linux)',
      version: '3.5.1',
      vendor: 'Brother',
      os: ['linux'],
      deviceType: 'printer',
      format: 'deb',
      architecture: 'x86_64',
      description: 'LPR driver package for Brother MFC-L8900CDW enterprise color laser MFP',
      downloadUrl: 'https://download.brother.com/welcome/dlf006921/mfcl8900cdwlpr-3.5.1-1.i386.deb',
      models: ['MFC-L8900CDW'],
      fileSize: 10485760,
      tags: ['color', 'laser', 'enterprise', 'cups', 'linux'],
      licenseType: 'freeware',
    },
  ],

  canon: [
    {
      id: 'canon-imagerunner-ufr2-win',
      name: 'Canon imageRUNNER UFR II Driver (Windows)',
      version: '32.00',
      vendor: 'Canon',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Canon UFR II printer driver for imageRUNNER Advance series MFP on Windows',
      downloadUrl: 'https://gdlp01.c-wss.com/gds/1/0300025311/01/UFR_II_Printer_Driver_v3200_W64_EN.exe',
      models: ['imageRUNNER ADVANCE 4545i', 'imageRUNNER ADVANCE C5560i', 'imageRUNNER C3230'],
      fileSize: 52428800,
      tags: ['ufr2', 'imagerunner', 'mfp', 'enterprise'],
      licenseType: 'freeware',
    },
    {
      id: 'canon-pixma-mg3600-win',
      name: 'Canon PIXMA MG3600 Driver (Windows)',
      version: '1.03',
      vendor: 'Canon',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Full driver and software for Canon PIXMA MG3600 inkjet MFP',
      downloadUrl: 'https://gdlp01.c-wss.com/gds/8/0300030648/04/mg3600-win-driver-1_03-ea38.exe',
      models: ['PIXMA MG3600', 'PIXMA MG3620'],
      fileSize: 62914560,
      tags: ['inkjet', 'pixma', 'mfp', 'color'],
      licenseType: 'freeware',
    },
    {
      id: 'canon-imageclass-lbp6230-win',
      name: 'Canon imageCLASS LBP6230dn Driver (Windows)',
      version: '22.00',
      vendor: 'Canon',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'UFR II driver for Canon imageCLASS LBP6230dn mono laser printer',
      downloadUrl: 'https://gdlp01.c-wss.com/gds/6/0300029586/02/LBP6230_6200-UFRII-W64-EN.exe',
      models: ['imageCLASS LBP6230dn', 'imageCLASS LBP6200d'],
      fileSize: 26214400,
      tags: ['mono', 'laser', 'imageclass', 'ufr2'],
      licenseType: 'freeware',
    },
    {
      id: 'canon-imagerunner-linux-ppd',
      name: 'Canon imageRUNNER CUPS Driver (Linux)',
      version: '5.90',
      vendor: 'Canon',
      os: ['linux'],
      deviceType: 'printer',
      format: 'deb',
      architecture: 'x86_64',
      description: 'Canon UFRII CUPS driver (cndrvcups-common + cndrvcups-ufr2) for Linux',
      downloadUrl: 'https://gdlp01.c-wss.com/gds/7/0100007834/05/linux-UFRII-drv-v590-uken-09.tar.gz',
      models: ['imageRUNNER ADVANCE', 'imageRUNNER C series'],
      fileSize: 20971520,
      tags: ['cups', 'linux', 'ufr2', 'imagerunner'],
      licenseType: 'freeware',
    },
    {
      id: 'canon-pixma-tr8620-win',
      name: 'Canon PIXMA TR8620 Driver (Windows)',
      version: '1.01',
      vendor: 'Canon',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Full driver for Canon PIXMA TR8620 wireless all-in-one inkjet printer',
      downloadUrl: 'https://gdlp01.c-wss.com/gds/1/0300036411/01/TR8620-TR8622-win-driver-1_01-ea2_2.exe',
      models: ['PIXMA TR8620', 'PIXMA TR8622'],
      fileSize: 78643200,
      tags: ['inkjet', 'wireless', 'aio', 'pixma'],
      licenseType: 'freeware',
    },
    {
      id: 'canon-mf641c-linux',
      name: 'Canon MF641C CUPS/UFR2 Driver (Linux)',
      version: '5.90',
      vendor: 'Canon',
      os: ['linux'],
      deviceType: 'printer',
      format: 'deb',
      architecture: 'x86_64',
      description: 'CUPS driver for Canon imageCLASS MF641Cw color laser MFP on Linux',
      downloadUrl: 'https://gdlp01.c-wss.com/gds/7/0100007834/05/linux-UFRII-drv-v590-uken-09.tar.gz',
      models: ['imageCLASS MF641Cw', 'imageCLASS MF642Cdw'],
      fileSize: 20971520,
      tags: ['cups', 'linux', 'color', 'laser'],
      licenseType: 'freeware',
    },
    {
      id: 'canon-g6020-macos',
      name: 'Canon PIXMA G6020 Driver (macOS)',
      version: '9.0.1.0',
      vendor: 'Canon',
      os: ['macos'],
      deviceType: 'printer',
      format: 'pkg',
      architecture: 'universal',
      description: 'macOS driver for Canon PIXMA G6020 MegaTank wireless inkjet printer',
      downloadUrl: 'https://gdlp01.c-wss.com/gds/5/0300033685/01/G6000-mac-driver-9_0_1_0-ea24_3.dmg',
      models: ['PIXMA G6020'],
      fileSize: 41943040,
      tags: ['inkjet', 'megatank', 'wireless', 'macos'],
      licenseType: 'freeware',
    },
    {
      id: 'canon-ps-generic-ppd',
      name: 'Canon Generic Plus PS3 PPD',
      version: '5.90',
      vendor: 'Canon',
      os: ['linux', 'macos'],
      deviceType: 'printer',
      format: 'ppd',
      architecture: 'universal',
      description: 'Generic Canon PostScript 3 PPD for CUPS — works with most Canon PS-capable printers',
      downloadUrl: 'https://gdlp01.c-wss.com/gds/9/0100007831/06/linux-LIPS4-drv-v590-uken.tar.gz',
      models: ['imageRUNNER', 'imageCLASS', 'PIXMA (PS models)'],
      fileSize: 15728640,
      tags: ['ppd', 'postscript', 'generic', 'cups'],
      licenseType: 'freeware',
    },
  ],

  epson: [
    {
      id: 'epson-workforce-wf-7720-win',
      name: 'Epson WorkForce WF-7720 Driver (Windows)',
      version: '2.62',
      vendor: 'Epson',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Full driver package for Epson WorkForce WF-7720 wide-format inkjet MFP',
      downloadUrl: 'https://download.ebz.epson.net/dsc/op/stable/windows/printer/WorkForceWF-7720Series/x64/WorkForce_WF-7720_Series_Printer_Driver.exe',
      models: ['WorkForce WF-7720', 'WorkForce WF-7710'],
      fileSize: 31457280,
      tags: ['inkjet', 'wide-format', 'a3', 'mfp'],
      licenseType: 'freeware',
    },
    {
      id: 'epson-ecotank-et-4760-win',
      name: 'Epson EcoTank ET-4760 Driver (Windows)',
      version: '2.71.00',
      vendor: 'Epson',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Full driver and software for Epson EcoTank ET-4760 supertank inkjet MFP',
      downloadUrl: 'https://download.ebz.epson.net/dsc/op/stable/windows/printer/ET-4760Series/x64/Epson-ET-4760-Series-Printer-Driver.exe',
      models: ['EcoTank ET-4760', 'EcoTank ET-4700'],
      fileSize: 47185920,
      tags: ['ecotank', 'supertank', 'inkjet', 'mfp'],
      licenseType: 'freeware',
    },
    {
      id: 'epson-escp-linux',
      name: 'Epson ESC/P-R Filter (Linux)',
      version: '1.0.17',
      vendor: 'Epson',
      os: ['linux'],
      deviceType: 'printer',
      format: 'deb',
      architecture: 'x86_64',
      description: 'Epson ESC/P-R CUPS filter for Linux — supports most Epson inkjet printers',
      downloadUrl: 'https://download.ebz.epson.net/dsc/op/stable/linux/lsb3x/x86_64/epson-inkjet-printer-escpr_1.7.8-1lsb3.2_amd64.deb',
      models: ['L series', 'ET series', 'WorkForce', 'Expression'],
      fileSize: 3145728,
      tags: ['linux', 'cups', 'escpr', 'inkjet'],
      licenseType: 'open-source',
    },
    {
      id: 'epson-l3150-linux',
      name: 'Epson L3150 ESC/P-R Driver (Linux)',
      version: '1.0.0',
      vendor: 'Epson',
      os: ['linux'],
      deviceType: 'printer',
      format: 'deb',
      architecture: 'x86_64',
      description: 'Epson L3150 multi-function inkjet Linux CUPS driver',
      downloadUrl: 'https://download.ebz.epson.net/dsc/op/stable/linux/lsb3x/x86_64/epson-inkjet-printer-l3150_1.0.0-1lsb3.2_amd64.deb',
      models: ['L3150', 'L3110'],
      fileSize: 2097152,
      tags: ['linux', 'cups', 'inkjet', 'ecotank'],
      licenseType: 'open-source',
    },
    {
      id: 'epson-surecolor-p800-win',
      name: 'Epson SureColor P800 Driver (Windows)',
      version: '8.74EA',
      vendor: 'Epson',
      os: ['windows'],
      deviceType: 'printer',
      format: 'exe',
      architecture: 'x86_64',
      description: 'Professional photo printing driver for Epson SureColor P800 wide-format printer',
      downloadUrl: 'https://download.ebz.epson.net/dsc/op/stable/windows/printer/SC-P800Series/x64/SureColorP800-Driver.exe',
      models: ['SureColor P800'],
      fileSize: 62914560,
      tags: ['photo', 'wide-format', 'professional', 'pigment'],
      licenseType: 'freeware',
    },
    {
      id: 'epson-xp-7100-macos',
      name: 'Epson Expression Photo XP-7100 Driver (macOS)',
      version: '9.87',
      vendor: 'Epson',
      os: ['macos'],
      deviceType: 'printer',
      format: 'dmg',
      architecture: 'universal',
      description: 'macOS driver for Epson Expression Photo XP-7100 wireless inkjet printer',
      downloadUrl: 'https://download.ebz.epson.net/dsc/op/stable/macos/printer/XP-7100/Epson-XP-7100-macOS.dmg',
      models: ['Expression Photo XP-7100'],
      fileSize: 41943040,
      tags: ['photo', 'inkjet', 'wireless', 'macos'],
      licenseType: 'freeware',
    },
    {
      id: 'epson-tm-t88vi-linux',
      name: 'Epson TM-T88VI Receipt Printer Driver (Linux)',
      version: '1.7.8',
      vendor: 'Epson',
      os: ['linux'],
      deviceType: 'printer',
      format: 'deb',
      architecture: 'x86_64',
      description: 'CUPS driver for Epson TM-T88VI thermal receipt printer on Linux',
      downloadUrl: 'https://download.ebz.epson.net/dsc/op/stable/linux/lsb3x/x86_64/epson-inkjet-printer-escpr_1.7.8-1lsb3.2_amd64.deb',
      models: ['TM-T88VI'],
      fileSize: 3145728,
      tags: ['thermal', 'receipt', 'pos', 'linux'],
      licenseType: 'freeware',
    },
    {
      id: 'epson-wf-c5790-ppd',
      name: 'Epson WorkForce Pro WF-C5790 PPD (Linux)',
      version: '1.7.8',
      vendor: 'Epson',
      os: ['linux'],
      deviceType: 'printer',
      format: 'ppd',
      architecture: 'universal',
      description: 'CUPS PPD for Epson WorkForce Pro WF-C5790 business inkjet MFP',
      downloadUrl: 'https://download.ebz.epson.net/dsc/op/stable/linux/lsb3x/x86_64/epson-inkjet-printer-escpr_1.7.8-1lsb3.2_amd64.deb',
      models: ['WorkForce Pro WF-C5790', 'WorkForce Pro WF-C5710'],
      fileSize: 3145728,
      tags: ['ppd', 'cups', 'business', 'inkjet'],
      licenseType: 'open-source',
    },
  ],

  generic: [
    {
      id: 'cups-generic-postscript',
      name: 'Generic PostScript Printer',
      version: '2023.1',
      vendor: 'Generic',
      os: ['linux', 'macos'],
      deviceType: 'printer',
      format: 'ppd',
      architecture: 'universal',
      description: 'Generic PostScript PPD — works with any PS-capable printer via CUPS',
      downloadUrl: 'https://www.openprinting.org/ppd/Generic/Generic-PostScript_Printer.ppd',
      models: ['Any PostScript printer'],
      fileSize: 32768,
      tags: ['generic', 'postscript', 'cups', 'universal'],
      licenseType: 'open-source',
    },
    {
      id: 'cups-generic-pcl5',
      name: 'Generic PCL 5 Printer',
      version: '2023.1',
      vendor: 'Generic',
      os: ['linux', 'macos'],
      deviceType: 'printer',
      format: 'ppd',
      architecture: 'universal',
      description: 'Generic PCL 5 PPD — compatible with most PCL5 laser printers via CUPS',
      downloadUrl: 'https://www.openprinting.org/ppd/Generic/Generic-PCL_5_Printer.ppd',
      models: ['Any PCL5 printer'],
      fileSize: 24576,
      tags: ['generic', 'pcl5', 'cups', 'universal', 'laser'],
      licenseType: 'open-source',
    },
    {
      id: 'cups-generic-pcl6',
      name: 'Generic PCL 6/XL Printer',
      version: '2023.1',
      vendor: 'Generic',
      os: ['linux', 'macos'],
      deviceType: 'printer',
      format: 'ppd',
      architecture: 'universal',
      description: 'Generic PCL 6/XL PPD — works with modern PCL6 laser printers via CUPS',
      downloadUrl: 'https://www.openprinting.org/ppd/Generic/Generic-PCL_6_Printer.ppd',
      models: ['Any PCL6 printer'],
      fileSize: 28672,
      tags: ['generic', 'pcl6', 'cups', 'universal', 'laser'],
      licenseType: 'open-source',
    },
    {
      id: 'cups-ipp-everywhere',
      name: 'IPP Everywhere / Apple AirPrint',
      version: '2.0',
      vendor: 'Generic',
      os: ['linux', 'macos', 'windows'],
      deviceType: 'printer',
      format: 'ppd',
      architecture: 'universal',
      description: 'Driverless IPP Everywhere printing — built into modern OS. No download needed.',
      downloadUrl: '',
      models: ['Any IPP Everywhere / AirPrint compatible printer'],
      fileSize: 0,
      tags: ['ipp', 'everywhere', 'airprint', 'driverless', 'cups'],
      licenseType: 'open-source',
    },
    {
      id: 'gutenprint-cups',
      name: 'Gutenprint CUPS Drivers',
      version: '5.3.4',
      vendor: 'Generic',
      os: ['linux', 'macos'],
      deviceType: 'printer',
      format: 'pkg',
      architecture: 'universal',
      description: 'High-quality open-source CUPS drivers for Epson, Canon, HP and others via Gutenprint',
      downloadUrl: 'https://prdownloads.sourceforge.net/gimp-print/gutenprint-5.3.4.tar.bz2',
      models: ['Epson, Canon, HP, Lexmark (many models)'],
      fileSize: 16777216,
      tags: ['gutenprint', 'cups', 'open-source', 'photo'],
      licenseType: 'open-source',
    },
    {
      id: 'ghostscript-ps-filter',
      name: 'Ghostscript PostScript/PDF Filter',
      version: '10.02.1',
      vendor: 'Generic',
      os: ['linux', 'macos'],
      deviceType: 'printer',
      format: 'pkg',
      architecture: 'universal',
      description: 'Ghostscript rasterizer for PostScript and PDF — enables CUPS to drive most printers',
      downloadUrl: 'https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs10021/ghostscript-10.02.1.tar.gz',
      models: ['CUPS filter (all printers)'],
      fileSize: 33554432,
      tags: ['ghostscript', 'postscript', 'pdf', 'raster', 'filter'],
      licenseType: 'open-source',
    },
    {
      id: 'cups-pdf-virtual',
      name: 'CUPS-PDF Virtual PDF Printer',
      version: '3.0.1',
      vendor: 'Generic',
      os: ['linux'],
      deviceType: 'printer',
      format: 'deb',
      architecture: 'x86_64',
      description: 'Virtual PDF printer backend for CUPS — prints documents to PDF files',
      downloadUrl: 'https://www.cups-pdf.de/download/cups-pdf_3.0.1-1_amd64.deb',
      models: ['Virtual PDF printer'],
      fileSize: 49152,
      tags: ['pdf', 'virtual', 'cups', 'linux'],
      licenseType: 'open-source',
    },
  ],
};

// ─── Helper: download a file ──────────────────────────────────────────────────

async function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    if (!url) return reject(new Error('No download URL provided'));
    const proto = url.startsWith('https') ? https : http;
    const file = fs.createWriteStream(destPath);
    // On any failure, close and remove the (possibly partially written)
    // file so a failed import never leaves a half-written driver on disk.
    const fail = (err) => { file.close(() => fs.unlink(destPath, () => reject(err))); };
    proto.get(url, { headers: { 'User-Agent': 'OpenDirectory/1.0' } }, (response) => {
      if (response.statusCode === 301 || response.statusCode === 302) {
        response.resume();
        if (!response.headers.location) return fail(new Error('Redirect with no Location header'));
        const nextUrl = new URL(response.headers.location, url).toString();
        file.close(() => fs.unlink(destPath, () => downloadFile(nextUrl, destPath).then(resolve).catch(reject)));
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        return fail(new Error(`HTTP ${response.statusCode} from ${url}`));
      }
      response.on('error', fail);
      file.on('error', fail);
      response.pipe(file);
      file.on('finish', () => file.close(resolve));
    }).on('error', fail);
  });
}

// ─── Helper: simple HTTPS GET returning text ──────────────────────────────────

function httpsGet(url, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const proto = url.startsWith('https') ? https : http;
    const req = proto.get(url, { headers: { 'User-Agent': 'OpenDirectory/1.0' } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        if (!res.headers.location) return reject(new Error('Redirect with no Location header'));
        const nextUrl = new URL(res.headers.location, url).toString();
        return httpsGet(nextUrl, timeoutMs).then(resolve).catch(reject);
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('Request timed out')); });
    req.on('error', reject);
  });
}

// ─── DriverCatalogManager class ───────────────────────────────────────────────

class DriverCatalogManager {
  constructor() {
    this.catalog = MANUFACTURER_CATALOG;

    // Build a flat list from static vendors (Dell comes from live catalog)
    this._staticEntries = Object.entries(this.catalog).flatMap(([vendor, entries]) =>
      entries.map((e) => ({ ...e, source: vendor }))
    );
  }

  // ── Catalog search ──────────────────────────────────────────────────────────

  async searchCatalog(query, filters = {}) {
    const q = (query || '').toLowerCase().trim();
    const vendorFilter = (filters.vendor || '').toLowerCase();

    // Decide which sources to query
    const wantDell    = !vendorFilter || vendorFilter === 'dell';
    const wantStatic  = !vendorFilter || vendorFilter !== 'dell';
    const wantOpenPrinting = filters.source === 'openprinting' || filters.includeOpenPrinting;

    let results = [];

    // Static catalog entries (non-Dell)
    if (wantStatic) {
      const staticMatches = this._staticEntries.filter((entry) => {
        if (q) {
          const haystack = [
            entry.name, entry.description, entry.vendor,
            ...(entry.models || []), ...(entry.tags || []),
          ].join(' ').toLowerCase();
          if (!haystack.includes(q)) return false;
        }
        if (vendorFilter && entry.vendor.toLowerCase() !== vendorFilter) return false;
        if (filters.os) {
          const oses = Array.isArray(filters.os) ? filters.os : [filters.os];
          if (!oses.some((o) => entry.os.includes(o.toLowerCase()))) return false;
        }
        if (filters.deviceType && entry.deviceType !== filters.deviceType) return false;
        if (filters.source && filters.source !== 'dell' && entry.source !== filters.source) return false;
        return true;
      });
      results = [...results, ...staticMatches];
    }

    // Live Dell catalog — only with a search term; an empty query would
    // merge the entire catalog (tens of thousands of entries) into the
    // response. Results are capped to keep payloads bounded.
    if (wantDell && q && filters.source !== 'openprinting') {
      try {
        const dellFilters = {};
        if (filters.os)         dellFilters.os         = Array.isArray(filters.os) ? filters.os[0] : filters.os;
        if (filters.deviceType) dellFilters.deviceType = filters.deviceType;
        if (filters.systemModel) dellFilters.systemModel = filters.systemModel;

        const dellResults = await dellCatalog.search(q, dellFilters);
        results = [...results, ...dellResults.slice(0, 500)];
      } catch (err) {
        logger.warn('Dell catalog search failed, skipping:', { message: err.message });
      }
    }

    // OpenPrinting
    if (wantOpenPrinting) {
      try {
        const opResults = await this.searchOpenPrinting(query);
        results = [...results, ...opResults];
      } catch (err) {
        logger.warn('OpenPrinting search failed, skipping:', { message: err.message });
      }
    }

    return results;
  }

  // ── OpenPrinting API ────────────────────────────────────────────────────────

  async searchOpenPrinting(query) {
    const encoded = encodeURIComponent(query || '');
    const url = `https://www.openprinting.org/ajax.php?op=searchPrinters&make=&model=${encoded}`;

    let raw;
    try {
      raw = await httpsGet(url, 12000);
    } catch (err) {
      logger.warn('OpenPrinting request error:', { message: err.message });
      return [];
    }

    let data;
    try {
      data = JSON.parse(raw);
    } catch (_) {
      logger.warn('OpenPrinting returned non-JSON response');
      return [];
    }

    // OpenPrinting returns an object keyed by printer name
    if (!data || typeof data !== 'object') return [];

    const entries = [];
    for (const [printerKey, info] of Object.entries(data)) {
      if (!info || typeof info !== 'object') continue;
      const make  = info.manufacturer || info.make || '';
      const model = info.model || printerKey || '';
      entries.push({
        id: `openprinting-${printerKey.replace(/[^a-z0-9]/gi, '-').toLowerCase()}`,
        source: 'openprinting',
        name: `${make} ${model}`.trim(),
        version: '',
        vendor: make,
        os: ['linux', 'macos'],
        deviceType: 'printer',
        format: 'ppd',
        architecture: 'universal',
        description: info.pnpdescription || info.functionality || `${make} ${model} driver from OpenPrinting`,
        downloadUrl: info.driver ? `https://www.openprinting.org/download/PPD/${info.driver}` : '',
        models: [model],
        fileSize: 0,
        tags: ['openprinting', 'ppd', make.toLowerCase()].filter(Boolean),
        licenseType: 'open-source',
      });
    }

    return entries;
  }

  // ── OpenPrinting PPD fetch ──────────────────────────────────────────────────

  async getOpenPrintingPPD(printerModel) {
    const encoded = encodeURIComponent(printerModel);
    const url = `https://www.openprinting.org/ajax.php?op=searchPrinters&make=&model=${encoded}`;

    let raw;
    try {
      raw = await httpsGet(url, 12000);
    } catch (err) {
      throw new Error(`OpenPrinting API unreachable: ${err.message}`);
    }

    let data;
    try {
      data = JSON.parse(raw);
    } catch (_) {
      throw new Error('OpenPrinting returned invalid JSON');
    }

    const printers = Object.values(data || {});
    if (!printers.length) throw new Error(`No printers found for "${printerModel}" on OpenPrinting`);

    const printer = printers[0];
    const driverKey = printer.driver;
    if (!driverKey) throw new Error('No driver available for this printer on OpenPrinting');

    const ppdUrl = `https://www.openprinting.org/download/PPD/${driverKey}`;
    const ppd = await httpsGet(ppdUrl, 15000);
    return { ppdContent: ppd, driverKey, printer };
  }

  // ── Linux apt-cache search ──────────────────────────────────────────────────

  async searchLinuxPackages(query) {
    return new Promise((resolve) => {
      execFile('apt-cache', ['search', '--names-only', query], { timeout: 10000 }, (err, stdout) => {
        if (err) {
          logger.info('apt-cache search not available or failed, skipping', { message: err.message });
          return resolve([]);
        }
        const lines = (stdout || '').split('\n').filter(Boolean);
        const results = lines.map((line) => {
          const [packageName, ...descParts] = line.split(' - ');
          return {
            id: `apt-${(packageName || '').trim()}`,
            source: 'linux-packages',
            name: (packageName || '').trim(),
            description: descParts.join(' - ').trim(),
            packageName: (packageName || '').trim(),
            os: ['linux'],
            deviceType: 'driver',
            format: 'deb',
            architecture: 'universal',
            version: '',
            vendor: 'Linux Package',
            downloadUrl: '',
            models: [],
            fileSize: 0,
            tags: ['apt', 'debian', 'ubuntu'],
            licenseType: 'open-source',
          };
        });
        resolve(results);
      });
    });
  }

  // ── Vendor list ─────────────────────────────────────────────────────────────

  async getVendors() {
    const counts = {};
    for (const [vendor, entries] of Object.entries(this.catalog)) {
      counts[vendor] = entries.length;
    }
    // Add Dell from live catalog
    try {
      const stats = await dellCatalog.getStats();
      counts['dell'] = stats.count || 0;
    } catch (_) {
      counts['dell'] = 0;
    }
    return counts;
  }

  // ── Import from catalog entry ───────────────────────────────────────────────

  async importFromCatalog(entry) {
    if (!entry || !entry.id) throw new Error('Invalid catalog entry');
    if (!entry.downloadUrl) throw new Error('This entry has no download URL');

    const storageDir = entry.deviceType === 'printer' ? PRINTER_DRIVER_DIR : DEVICE_DRIVER_DIR;
    await fsp.mkdir(storageDir, { recursive: true });

    const ext = this._guessExtension(entry.downloadUrl, entry.format);
    const safeId = entry.id.replace(/[^a-z0-9_-]/gi, '_');
    const safeVersion = String(entry.version || 'unknown').replace(/[^a-z0-9_.-]/gi, '_');
    const fileName = `${safeId}-${safeVersion}${ext}`;
    const destPath = path.join(storageDir, fileName);

    logger.info(`Downloading catalog entry "${entry.name}" → ${destPath}`);

    try {
      await downloadFile(entry.downloadUrl, destPath);
    } catch (err) {
      throw new Error(`Failed to download driver: ${err.message}`);
    }

    const stat = await fsp.stat(destPath);
    const record = {
      id: entry.id,
      name: entry.name,
      version: entry.version || '',
      vendor: entry.vendor,
      os: entry.os,
      deviceType: entry.deviceType,
      format: entry.format,
      architecture: entry.architecture || 'universal',
      description: entry.description || '',
      downloadUrl: entry.downloadUrl,
      models: entry.models || [],
      tags: entry.tags || [],
      licenseType: entry.licenseType || 'freeware',
      localPath: destPath,
      fileSize: stat.size,
      importedAt: new Date().toISOString(),
    };

    logger.info(`Driver imported: ${entry.name} (${stat.size} bytes)`);
    return record;
  }

  // ── Import from arbitrary URL ───────────────────────────────────────────────

  async importFromUrl(url, metadata = {}) {
    if (!url) throw new Error('url is required');

    const storageDir = (metadata.deviceType === 'printer') ? PRINTER_DRIVER_DIR : DEVICE_DRIVER_DIR;
    await fsp.mkdir(storageDir, { recursive: true });

    const ext = this._guessExtension(url, metadata.format);
    const hash = crypto.createHash('md5').update(url).digest('hex').slice(0, 8);
    const safeName = (metadata.name || 'driver').replace(/[^a-z0-9_-]/gi, '_');
    const fileName = `${safeName}-${hash}${ext}`;
    const destPath = path.join(storageDir, fileName);

    logger.info(`Downloading from URL "${url}" → ${destPath}`);

    try {
      await downloadFile(url, destPath);
    } catch (err) {
      throw new Error(`Failed to download from URL: ${err.message}`);
    }

    const stat = await fsp.stat(destPath);
    const record = {
      id: `url-${hash}`,
      name: metadata.name || fileName,
      version: metadata.version || '',
      vendor: metadata.vendor || 'Unknown',
      os: metadata.os ? (Array.isArray(metadata.os) ? metadata.os : [metadata.os]) : [],
      deviceType: metadata.deviceType || 'generic',
      format: metadata.format || ext.replace('.', ''),
      architecture: metadata.architecture || 'universal',
      description: metadata.description || `Imported from ${url}`,
      downloadUrl: url,
      models: metadata.models || [],
      tags: metadata.tags || [],
      licenseType: metadata.licenseType || 'freeware',
      localPath: destPath,
      fileSize: stat.size,
      importedAt: new Date().toISOString(),
    };

    logger.info(`Driver imported from URL: ${url} (${stat.size} bytes)`);
    return record;
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  _guessExtension(url, formatHint) {
    if (formatHint) {
      // Strip anything but alphanumerics so a crafted format value (e.g.
      // containing "/" or "..") can't be used to escape the storage dir.
      const clean = String(formatHint).replace(/^\./, '').replace(/[^a-z0-9]/gi, '');
      if (clean) return `.${clean}`;
    }
    const match = (url || '').match(/\.([a-z0-9]{1,8})(?:[?#]|$)/i);
    return match ? `.${match[1].toLowerCase()}` : '.bin';
  }
}

module.exports = DriverCatalogManager;
