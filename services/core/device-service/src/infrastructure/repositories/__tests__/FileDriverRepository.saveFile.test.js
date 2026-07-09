'use strict';

// Unit tests for the path-traversal fix in FileDriverRepository#saveFile.
// filename originates from an untrusted multipart originalname (upload) or
// a URL-derived basename (import-url) — saveFile() must never let it place
// the file outside this._filesDir.

const os = require('os');
const fs = require('fs');
const path = require('path');

const FileDriverRepository = require('../FileDriverRepository');

let tmpRoot;
let repo;

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'file-driver-repo-'));
  repo = new FileDriverRepository(tmpRoot);
});

afterEach(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

describe('FileDriverRepository#saveFile — path traversal', () => {
  test('a "../" filename is confined to the files dir (basename stripped)', async () => {
    const { filePath, destFilename } = await repo.saveFile(
      'drv-1', '../../../../etc/evil.inf', Buffer.from('payload')
    );

    expect(destFilename).not.toContain('..');
    expect(destFilename).not.toContain('/');
    expect(filePath).toBe(path.join(tmpRoot, 'files', destFilename));

    // Nothing was written outside the files dir.
    expect(fs.existsSync(path.join(tmpRoot, 'etc', 'evil.inf'))).toBe(false);
    expect(fs.existsSync(path.resolve(tmpRoot, '..', '..', '..', '..', 'etc', 'evil.inf'))).toBe(false);
    // The file landed exactly where saveFile() reported.
    expect(fs.readFileSync(filePath, 'utf8')).toBe('payload');
  });

  test('an absolute-path filename is also confined (basename stripped)', async () => {
    const { filePath, destFilename } = await repo.saveFile(
      'drv-2', '/etc/passwd', Buffer.from('x')
    );
    expect(destFilename).toBe('drv-2-passwd');
    expect(filePath).toBe(path.join(tmpRoot, 'files', 'drv-2-passwd'));
  });

  test('a plain filename is unaffected', async () => {
    const { destFilename } = await repo.saveFile('drv-3', 'chipset.inf', Buffer.from('x'));
    expect(destFilename).toBe('drv-3-chipset.inf');
  });
});
