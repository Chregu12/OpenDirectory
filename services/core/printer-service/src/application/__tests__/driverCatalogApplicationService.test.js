'use strict';

// Unit tests for DriverCatalogApplicationService with fully mocked
// dependencies (driver repository, catalog manager, Dell catalog, and the
// raw HTTP download helper) — no real network access, no real driver
// repository implementation involved.
//
//   npx jest src/application/__tests__/driverCatalogApplicationService.test.js

const os = require('os');
const fs = require('fs');
const path = require('path');

// Isolated storage for the (real, on-disk) import destination paths —
// must be set BEFORE the module under test is required, since it reads
// PRINTER_DRIVERS_DIR/DEVICE_DRIVERS_DIR once at module load time.
const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'driver-appservice-'));
process.env.PRINTER_DRIVERS_DIR = path.join(TMP_ROOT, 'printer-drivers');
process.env.DEVICE_DRIVERS_DIR = path.join(TMP_ROOT, 'device-drivers');

jest.mock('../../infrastructure/httpDownload');
const { downloadFile } = require('../../infrastructure/httpDownload');

const { DriverCatalogApplicationService } = require('../DriverCatalogApplicationService');

function makeMockRepo() {
  return {
    add: jest.fn(),
    remove: jest.fn().mockResolvedValue(true),
    list: jest.fn(),
    get: jest.fn(),
    assignToPrinter: jest.fn(),
    unassignFromPrinter: jest.fn(),
    getForPrinter: jest.fn(),
    ensureStorage: jest.fn(),
    FILES_DIR: path.join(TMP_ROOT, 'files'),
  };
}

afterAll(() => {
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
});

afterEach(() => {
  jest.clearAllMocks();
});

describe('DriverCatalogApplicationService — import rollback', () => {
  test('importCatalogEntry: a download failure never touches the driver repository', async () => {
    downloadFile.mockRejectedValue(new Error('connection refused'));
    const driverRepo = makeMockRepo();
    const svc = new DriverCatalogApplicationService({ driverRepo, catalogManager: {}, dellCatalog: {} });

    const entry = {
      id: 'catalog-entry-1', name: 'Test Driver', version: '1.0', vendor: 'Acme',
      os: ['linux'], deviceType: 'printer', format: 'ppd',
      downloadUrl: 'http://example.invalid/driver.ppd',
    };

    await expect(svc.importCatalogEntry(entry)).rejects.toThrow('Failed to download driver');
    expect(driverRepo.add).not.toHaveBeenCalled();
  });

  test('importFromUrl: a post-download rename failure rolls back the repo record and the downloaded file', async () => {
    let capturedDestPath;
    downloadFile.mockImplementation(async (url, destPath) => {
      capturedDestPath = destPath;
      fs.writeFileSync(destPath, 'fake-driver-bytes');
    });

    const driverRepo = makeMockRepo();
    // filePath points at a directory that doesn't exist, so fs.rename() fails with ENOENT.
    driverRepo.add.mockResolvedValue({ id: 'created-1', filePath: path.join(TMP_ROOT, 'no-such-dir', 'driver.bin') });

    const svc = new DriverCatalogApplicationService({ driverRepo, catalogManager: {}, dellCatalog: {} });

    await expect(
      svc.importFromUrl('http://example.invalid/driver.ppd', { name: 'Bad Rename' })
    ).rejects.toThrow();

    expect(driverRepo.add).toHaveBeenCalledTimes(1);
    expect(driverRepo.remove).toHaveBeenCalledWith('created-1');
    expect(fs.existsSync(capturedDestPath)).toBe(false); // downloaded file cleaned up too
  });

  test('uploadDriver: a post-add rename failure rolls back the repo record and the temp upload', async () => {
    const driverRepo = makeMockRepo();
    driverRepo.add.mockResolvedValue({ id: 'up-1', filePath: path.join(TMP_ROOT, 'no-such-dir', 'driver.bin') });

    const svc = new DriverCatalogApplicationService({ driverRepo, catalogManager: {}, dellCatalog: {} });

    const tmpFile = path.join(TMP_ROOT, 'upload-tmp.bin');
    fs.writeFileSync(tmpFile, 'data');

    await expect(
      svc.uploadDriver(tmpFile, { originalname: 'x.ppd', size: 4 }, {})
    ).rejects.toThrow();

    expect(driverRepo.remove).toHaveBeenCalledWith('up-1');
    expect(fs.existsSync(tmpFile)).toBe(false);
  });
});

describe('DriverCatalogApplicationService — os normalization', () => {
  test('importFromUrl collapses a multi-entry os array to "universal"', async () => {
    downloadFile.mockImplementation(async (url, destPath) => fs.writeFileSync(destPath, 'x'));
    const driverRepo = makeMockRepo();
    driverRepo.add.mockImplementation(async (params) => ({
      ...params, id: 'norm-1', filePath: path.join(TMP_ROOT, 'norm-1-file.bin'),
    }));

    const svc = new DriverCatalogApplicationService({ driverRepo, catalogManager: {}, dellCatalog: {} });
    await svc.importFromUrl('http://example.invalid/driver.ppd', { name: 'Multi OS', os: ['linux', 'macos'] });

    expect(driverRepo.add).toHaveBeenCalledWith(expect.objectContaining({ os: 'universal' }));
  });

  test('importFromUrl collapses a single-entry os array to that value', async () => {
    downloadFile.mockImplementation(async (url, destPath) => fs.writeFileSync(destPath, 'x'));
    const driverRepo = makeMockRepo();
    driverRepo.add.mockImplementation(async (params) => ({
      ...params, id: 'norm-2', filePath: path.join(TMP_ROOT, 'norm-2-file.bin'),
    }));

    const svc = new DriverCatalogApplicationService({ driverRepo, catalogManager: {}, dellCatalog: {} });
    await svc.importFromUrl('http://example.invalid/driver.ppd', { name: 'Single OS', os: ['windows'] });

    expect(driverRepo.add).toHaveBeenCalledWith(expect.objectContaining({ os: 'windows' }));
  });
});

describe('DriverCatalogApplicationService — Dell search', () => {
  test('searchDell caps results at the requested limit but reports the full match count', async () => {
    const dellCatalog = { search: jest.fn().mockResolvedValue([{ id: 1 }, { id: 2 }, { id: 3 }]) };
    const svc = new DriverCatalogApplicationService({ driverRepo: makeMockRepo(), catalogManager: {}, dellCatalog });

    const { count, results } = await svc.searchDell('optiplex', {}, 2);

    expect(dellCatalog.search).toHaveBeenCalledWith('optiplex', {});
    expect(count).toBe(3);
    expect(results).toHaveLength(2);
  });
});
