'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { RustGraphCapacityClient } = require('../fulfillment/RustGraphCapacityClient');

const config = { tenantId: '11111111-1111-4111-8111-111111111111', clientId: '22222222-2222-4222-8222-222222222222', clientSecret: 'fixture-only-secret' };
const sku = { skuId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', skuPartNumber: 'TEST', appliesTo: 'User', capabilityStatus: 'Enabled', prepaidUnits: { enabled: 5, warning: 0, suspended: 0, lockedOut: 0 }, consumedUnits: 2 };
let folder;
beforeEach(() => { folder = fs.mkdtempSync(path.join(os.tmpdir(), 'od-rust-capacity-')); });
afterEach(() => fs.rmSync(folder, { recursive: true, force: true }));
function fixture(source) {
  const binary = path.join(folder, 'connector');
  fs.writeFileSync(binary, `#!${process.execPath}\n${source}`, { mode: 0o700 });
  const client = new RustGraphCapacityClient({ ...config, binary });
  client.tokens.get = jest.fn().mockResolvedValue('fixture-token'); client.tokens.clear = jest.fn();
  return client;
}
test('uses private stdin and accepts only a valid canonical snapshot', async () => {
  const client = fixture(`let data='';process.stdin.on('data',x=>data+=x);process.stdin.on('end',()=>{const v=JSON.parse(data);if(v.accessToken!=='fixture-token'||process.argv.length!==2||process.env.DATABASE_URL||process.env.HOME)process.exit(2);process.stdout.write(JSON.stringify({ok:true,rows:${JSON.stringify([sku])}}));});`);
  expect(await client.inspect()).toEqual([sku]); expect(client.tokens.clear).not.toHaveBeenCalled();
});
test('preserves a bounded provider retry and does not expose process output', async () => {
  const client = fixture(`process.stdin.resume();process.stdin.on('end',()=>process.stdout.write(JSON.stringify({ok:false,code:'graph_capacity_http_429',retryAfter:90})));`);
  await expect(client.inspect()).rejects.toMatchObject({ code: 'graph_capacity_http_429', retryAfter: 90 }); expect(client.tokens.clear).toHaveBeenCalledTimes(1);
});
test('rejects forged success or malformed error data', async () => {
  const client = fixture(`process.stdin.resume();process.stdin.on('end',()=>process.stdout.write(JSON.stringify({ok:true,rows:[],extra:'forged'})));`);
  await expect(client.inspect()).rejects.toMatchObject({ code: 'graph_capacity_invalid_response' });
});
test('cancellation terminates a pending connector without reporting success', async () => {
  const client = fixture(`process.stdin.resume();setTimeout(()=>{},30000);`); const controller = new AbortController();
  const pending = client.inspect(controller.signal); controller.abort();
  await expect(pending).rejects.toMatchObject({ code: 'graph_capacity_incomplete' });
});
