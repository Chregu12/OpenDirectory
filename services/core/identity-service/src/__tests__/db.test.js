'use strict';

const mockClient = { query: jest.fn(), release: jest.fn() };
const mockPool = { query: jest.fn(), connect: jest.fn(async () => mockClient), on: jest.fn() };
jest.mock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
const db = require('../db');

beforeEach(() => {
  jest.clearAllMocks();
  mockPool.query.mockResolvedValue({ rows: [] });
  mockClient.query.mockResolvedValue({ rows: [] });
});

test('failed migrations never advertise an available authoritative store', async () => {
  mockPool.query.mockImplementation(async sql => {
    if (sql.includes('CREATE SEQUENCE')) throw new Error('migration failed');
    return { rows: [] };
  });
  expect(await db.initDb()).toBe(false);
  expect(db.isAvailable()).toBe(false);
});

test('writes carry the verified actor in a transaction and roll back before releasing a failed client', async () => {
  await db.initDb();
  mockClient.query.mockImplementation(async sql => {
    if (sql === 'INSERT test') throw new Error('write failed');
    return { rows: [] };
  });
  await expect(db.write('INSERT test', [], 'verified-actor')).rejects.toThrow('write failed');
  expect(mockClient.query).toHaveBeenCalledWith("SELECT set_config('opendirectory.actor', $1, true)", ['verified-actor']);
  expect(mockClient.query).toHaveBeenCalledWith('ROLLBACK');
  expect(mockClient.query).not.toHaveBeenCalledWith('COMMIT');
  expect(mockClient.release).toHaveBeenCalledTimes(1);
});

test('original authority is revalidated immediately before physical commit and failed validation rolls back', async () => {
  await db.initDb();
  const beforeCommit = jest.fn(async client => { expect(client).toBe(mockClient); throw new Error('Original authority withdrawn'); });
  await expect(db.transaction(async () => 'receipt', { beforeCommit })).rejects.toThrow('Original authority withdrawn');
  expect(beforeCommit).toHaveBeenCalledTimes(1); expect(mockClient.query).toHaveBeenCalledWith('ROLLBACK'); expect(mockClient.query).not.toHaveBeenCalledWith('COMMIT');
});
