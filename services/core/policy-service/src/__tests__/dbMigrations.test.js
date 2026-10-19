'use strict';
test('migration files cannot end the schema-wide transaction or release its advisory gate',()=>{
 const fs=require('node:fs');const path=require('node:path');const directory=path.join(__dirname,'../db/migrations');for(const file of fs.readdirSync(directory).filter(name=>name.endsWith('.sql')))expect(fs.readFileSync(path.join(directory,file),'utf8')).not.toMatch(/^\s*(?:BEGIN|COMMIT|ROLLBACK)\s*;\s*$/m);
});
jest.mock('pg',()=>({Pool:jest.fn()}));jest.mock('winston',()=>({createLogger:()=>({info:jest.fn(),warn:jest.fn(),debug:jest.fn(),error:jest.fn()}),format:{combine:jest.fn(),timestamp:jest.fn(),json:jest.fn()},transports:{Console:jest.fn()}}));
let database;let client;
beforeEach(()=>{jest.resetModules();client={query:jest.fn(async()=>({rows:[]})),release:jest.fn()};require('pg').Pool.mockImplementation(()=>({connect:jest.fn(async()=>client),on:jest.fn()}));database=require('../db/postgres');});
test('migration replay holds one schema-bound transaction and advisory lock until all wrappers are restored',async()=>{
 await database.runMigrations();const queries=client.query.mock.calls.map(call=>call[0]);expect(queries[0]).toBe('BEGIN');expect(queries[1]).toContain('pg_advisory_xact_lock');expect(queries[1]).toContain('current_schema()');expect(queries.at(-1)).toBe('COMMIT');expect(client.release).toHaveBeenCalledTimes(1);
 expect(queries.some(sql=>sql.includes('CREATE OR REPLACE FUNCTION license_scope_review_allowed'))).toBe(true);const files=require('fs').readdirSync(require('path').join(__dirname,'../db/migrations')).filter(file=>file.endsWith('.sql'));expect(queries.filter(sql=>sql==='SAVEPOINT migration_file')).toHaveLength(files.length);
});
test.each(['42P07','42710'])('duplicate-object %s is recovered through a savepoint, not an aborted transaction',async code=>{
 let first=true;client.query.mockImplementation(async sql=>{if(first&&sql.includes('CREATE TABLE')){first=false;throw Object.assign(new Error('Owned duplicate object'),{code});}return{rows:[]};});await database.runMigrations();expect(client.query).toHaveBeenCalledWith('ROLLBACK TO SAVEPOINT migration_file');expect(client.query).toHaveBeenLastCalledWith('COMMIT');expect(client.release).toHaveBeenCalledTimes(1);
});
test('any other migration failure rolls back the entire authority generation and releases the connection',async()=>{
 client.query.mockImplementation(async sql=>{if(sql.includes('CREATE TABLE'))throw Object.assign(new Error('Owned migration failure'),{code:'42501'});return{rows:[]};});await expect(database.runMigrations()).rejects.toThrow('Owned migration failure');expect(client.query).not.toHaveBeenCalledWith('COMMIT');expect(client.query).toHaveBeenLastCalledWith('ROLLBACK');expect(client.release).toHaveBeenCalledTimes(1);
});
