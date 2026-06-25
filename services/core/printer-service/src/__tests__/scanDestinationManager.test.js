'use strict';

const ScanDestinationManager = require('../services/scanDestinationManager');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeDb(rows = []) {
  return {
    query: jest.fn().mockResolvedValue({ rows, rowCount: rows.length }),
  };
}

function makeDest(overrides = {}) {
  return {
    id: 'dest-1',
    entityType: 'group',
    entityId: 'all-users',
    type: 'smb',
    smbServer: '192.168.1.10',
    smbShare: 'scans',
    smbPath: 'scanner/@{username}',
    smbUsername: 'scanuser',
    smbPassword: null,
    smbDomain: null,
    localPath: null,
    label: 'All Users',
    isDefault: false,
    ...overrides,
  };
}

// ─── _resolveVariables ────────────────────────────────────────────────────────

describe('ScanDestinationManager._resolveVariables', () => {
  let mgr;

  beforeEach(() => {
    mgr = new ScanDestinationManager({ db: makeDb() });
  });

  test('replaces @{username} with the login part of an email userId', () => {
    const dest   = makeDest({ smbPath: 'scanner/@{username}' });
    const result = mgr._resolveVariables(dest, 'jdoe@corp.com');
    expect(result.smbPath).toBe('scanner/jdoe');
  });

  test('replaces @{username} when userId is a plain login (no @)', () => {
    const dest   = makeDest({ smbPath: 'scanner/@{username}' });
    const result = mgr._resolveVariables(dest, 'jdoe');
    expect(result.smbPath).toBe('scanner/jdoe');
  });

  test('replaces @{email} with the full email address', () => {
    const dest   = makeDest({ smbPath: 'by-email/@{email}' });
    const result = mgr._resolveVariables(dest, 'jdoe@corp.com');
    expect(result.smbPath).toBe('by-email/jdoe@corp.com');
  });

  test('@{email} for a plain userId becomes username@opendirectory.local', () => {
    const dest   = makeDest({ smbPath: 'mail/@{email}' });
    const result = mgr._resolveVariables(dest, 'jdoe');
    expect(result.smbPath).toBe('mail/jdoe@opendirectory.local');
  });

  test('replaces %U (Samba-style) with username', () => {
    const dest   = makeDest({ smbPath: 'home/%U' });
    const result = mgr._resolveVariables(dest, 'msmith@example.com');
    expect(result.smbPath).toBe('home/msmith');
  });

  test('replaces %u (lowercase) with username', () => {
    const dest   = makeDest({ smbPath: 'home/%u' });
    const result = mgr._resolveVariables(dest, 'msmith@example.com');
    expect(result.smbPath).toBe('home/msmith');
  });

  test('replaces variables in localPath as well', () => {
    const dest   = makeDest({ smbPath: null, localPath: '/mnt/scans/@{username}' });
    const result = mgr._resolveVariables(dest, 'alice@company.org');
    expect(result.localPath).toBe('/mnt/scans/alice');
  });

  test('replaces variables in both smbPath and localPath simultaneously', () => {
    const dest   = makeDest({ smbPath: 'smb/@{username}', localPath: '/local/@{username}' });
    const result = mgr._resolveVariables(dest, 'bob@test.com');
    expect(result.smbPath).toBe('smb/bob');
    expect(result.localPath).toBe('/local/bob');
  });

  test('replaces multiple occurrences of @{username} in the same path', () => {
    const dest   = makeDest({ smbPath: '@{username}/inbox/@{username}' });
    const result = mgr._resolveVariables(dest, 'carol@test.com');
    expect(result.smbPath).toBe('carol/inbox/carol');
  });

  test('leaves paths without variables unchanged', () => {
    const dest   = makeDest({ smbPath: 'Marketing/Incoming' });
    const result = mgr._resolveVariables(dest, 'jdoe@corp.com');
    expect(result.smbPath).toBe('Marketing/Incoming');
  });

  test('handles null smbPath gracefully', () => {
    const dest   = makeDest({ smbPath: null });
    const result = mgr._resolveVariables(dest, 'jdoe@corp.com');
    expect(result.smbPath).toBeNull();
  });

  test('handles undefined localPath gracefully', () => {
    const dest   = makeDest({ localPath: undefined });
    const result = mgr._resolveVariables(dest, 'jdoe@corp.com');
    expect(result.localPath).toBeUndefined();
  });

  test('returns null when dest is null', () => {
    expect(mgr._resolveVariables(null, 'jdoe@corp.com')).toBeNull();
  });

  test('returns dest unchanged when userId is null', () => {
    const dest   = makeDest({ smbPath: 'scanner/@{username}' });
    const result = mgr._resolveVariables(dest, null);
    // userId is null → no substitution possible, returns dest as-is
    expect(result).toBe(dest);
  });

  test('does not mutate the original destination object', () => {
    const dest   = makeDest({ smbPath: 'scanner/@{username}' });
    const original = dest.smbPath;
    mgr._resolveVariables(dest, 'jdoe@corp.com');
    expect(dest.smbPath).toBe(original);
  });

  test('unknown variables are left unchanged', () => {
    const dest   = makeDest({ smbPath: 'folder/@{department}' });
    const result = mgr._resolveVariables(dest, 'jdoe@corp.com');
    expect(result.smbPath).toBe('folder/@{department}');
  });
});

// ─── resolveDestination ───────────────────────────────────────────────────────

describe('ScanDestinationManager.resolveDestination', () => {
  function makeRow(overrides = {}) {
    return {
      id: 'row-1',
      entity_type: 'group',
      entity_id: 'all-users',
      destination_type: 'smb',
      smb_server: '192.168.1.10',
      smb_share: 'scans',
      smb_path: 'scanner/@{username}',
      smb_username: 'scanuser',
      smb_password_enc: null,
      smb_domain: null,
      local_path: null,
      label: 'All Users',
      is_default: false,
      created_at: new Date(),
      updated_at: new Date(),
      ...overrides,
    };
  }

  test('returns user destination with @{username} resolved', async () => {
    const db  = makeDb([makeRow({ entity_type: 'user', entity_id: 'jdoe@corp.com', smb_path: 'scanner/@{username}' })]);
    const mgr = new ScanDestinationManager({ db });
    const result = await mgr.resolveDestination('jdoe@corp.com', []);
    expect(result.smbPath).toBe('scanner/jdoe');
  });

  test('returns group destination with @{username} resolved for the requesting user', async () => {
    // First query (user) returns nothing; second query (group) returns the group dest
    const db = { query: jest.fn()
      .mockResolvedValueOnce({ rows: [], rowCount: 0 })         // user lookup
      .mockResolvedValueOnce({ rows: [makeRow()], rowCount: 1 }) // group lookup
    };
    const mgr = new ScanDestinationManager({ db });
    const result = await mgr.resolveDestination('msmith@corp.com', ['all-users']);
    expect(result.smbPath).toBe('scanner/msmith');
  });

  test('group rule with @{username} resolves differently per user', async () => {
    const groupRow = makeRow({ smb_path: 'home/@{username}' });
    const db = { query: jest.fn()
      .mockResolvedValueOnce({ rows: [], rowCount: 0 })
      .mockResolvedValueOnce({ rows: [groupRow], rowCount: 1 })
      .mockResolvedValueOnce({ rows: [], rowCount: 0 })
      .mockResolvedValueOnce({ rows: [groupRow], rowCount: 1 })
    };
    const mgr = new ScanDestinationManager({ db });

    const resultA = await mgr.resolveDestination('alice@corp.com', ['all-users']);
    const resultB = await mgr.resolveDestination('bob@corp.com',   ['all-users']);
    expect(resultA.smbPath).toBe('home/alice');
    expect(resultB.smbPath).toBe('home/bob');
  });

  test('%U in group path is resolved to requesting username', async () => {
    const db = { query: jest.fn()
      .mockResolvedValueOnce({ rows: [], rowCount: 0 })
      .mockResolvedValueOnce({ rows: [makeRow({ smb_path: 'samba/%U' })], rowCount: 1 })
    };
    const mgr = new ScanDestinationManager({ db });
    const result = await mgr.resolveDestination('carol@example.com', ['staff']);
    expect(result.smbPath).toBe('samba/carol');
  });

  test('returns null when neither user nor group destination exists', async () => {
    const db = makeDb([]);
    const mgr = new ScanDestinationManager({ db });
    const result = await mgr.resolveDestination('nobody@corp.com', ['unknown-group']);
    expect(result).toBeNull();
  });

  test('user-specific destination takes priority over group destination', async () => {
    const userRow  = makeRow({ entity_type: 'user', entity_id: 'jdoe@corp.com', smb_path: 'personal/@{username}' });
    const groupRow = makeRow({ smb_path: 'group/@{username}' });
    const db = { query: jest.fn()
      .mockResolvedValueOnce({ rows: [userRow], rowCount: 1 }) // user found → stop
      .mockResolvedValueOnce({ rows: [groupRow], rowCount: 1 }) // should NOT be reached
    };
    const mgr    = new ScanDestinationManager({ db });
    const result = await mgr.resolveDestination('jdoe@corp.com', ['all-users']);
    expect(result.smbPath).toBe('personal/jdoe');
    // db.query was called exactly once (for the user lookup)
    expect(db.query).toHaveBeenCalledTimes(1);
  });

  test('localPath variable is resolved in group destination', async () => {
    const db = { query: jest.fn()
      .mockResolvedValueOnce({ rows: [], rowCount: 0 })
      .mockResolvedValueOnce({ rows: [makeRow({ smb_path: null, smb_server: null, local_path: '/scans/@{username}' })], rowCount: 1 })
    };
    const mgr    = new ScanDestinationManager({ db });
    const result = await mgr.resolveDestination('dave@corp.com', ['team']);
    expect(result.localPath).toBe('/scans/dave');
  });
});
