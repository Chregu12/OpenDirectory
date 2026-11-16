import { api } from '@/lib/api';
import { CompanyMicrosoftClient } from '@/lib/companyMicrosoft';
import { microsoftId as id, microsoftContext, microsoftEnvelope, microsoftState, microsoftMappings, microsoftProducts, microsoftPool, microsoftPerson, microsoftResponse as ok } from '../fixtures/companyMicrosoft';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const clients: CompanyMicrosoftClient[] = []; const base = '/api/licenses/company/provider/microsoft';
let state: ReturnType<typeof microsoftState>; let mappings: ReturnType<typeof microsoftMappings>; let products: ReturnType<typeof microsoftProducts>;
beforeEach(() => {
  jest.resetAllMocks(); state = microsoftState(); mappings = microsoftMappings(); products = microsoftProducts(); let sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url.endsWith('/state')) return ok(state);
    if (url.endsWith('/mappings')) return ok(mappings);
    if (url.endsWith('/products')) return ok(products);
    throw new Error('Unexpected Microsoft read');
  });
});
afterEach(() => clients.splice(0).forEach(current => current.dispose()));
function client() { const current = new CompanyMicrosoftClient(microsoftContext); clients.push(current); return current; }
test('pool binding captures the reviewed SKU and exact connection version without rounding bigint', async () => {
  const current = client(), view = await current.state(), inventory = await current.products();
  const intent = current.bindPool(view, inventory, id(8), id(9), 'Reviewed product binding');
  (api.post as jest.Mock).mockResolvedValue(ok({ ...microsoftEnvelope, pool: { ...microsoftPool(), id: intent.operationId }, historical: false }, 201, { etag: `"company-microsoft-pool-${intent.operationId}-1"` }));
  expect(await current.write(intent)).toEqual({ operationId: intent.operationId, action: 'bind_pool', historical: false });
  expect(api.post).toHaveBeenCalledWith(base + '/pools/' + id(8) + '/bind', { reason: 'Reviewed product binding', confirm: true, skuId: id(9), exclusiveDirectManagement: true }, expect.objectContaining({ headers: { 'Idempotency-Key': intent.operationId, 'If-Match': `"company-microsoft-connection-${id(3)}-9007199254740993"` } }));
  expect(Object.isFrozen(intent.body)).toBe(true);
});
test('new connection approval includes exactly the displayed public Microsoft configuration', async () => {
  state.state = 'configured'; state.connection = null; const current = client(), view = await current.state();
  const intent = current.connect(view, 'Reviewed Microsoft directory');
  expect(intent.body).toEqual({ reason: 'Reviewed Microsoft directory', confirm: true, microsoftTenantId: id(4), readClientId: id(5), writeClientId: id(6) });
  expect(intent.path).toBe('/connections'); expect(intent.etag).toBeNull();
});
test('retirement requires an actually captured mapping and keeps its exact revision', async () => {
  const current = client(), view = await current.state(), rows = await current.mappings(id(8));
  const intent = current.retire(view, 'user', rows.users[0], 'Reviewed mapping retirement');
  expect(intent.etag).toBe(`"company-microsoft-user-${id(10)}-1"`); expect(intent.expectedRevision).toBe('2');
  expect(() => current.retire(view, 'user', { ...rows.users[0] }, 'Reviewed mapping retirement')).toThrow();
});
test('an existing connection cannot be renewed onto a different Microsoft directory', async () => {
  state.state = 'review_required'; state.microsoftTenantId = id(99); const current = client(); const view = await current.state();
  expect(() => current.connect(view, 'Reviewed application rotation', true)).toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each(['company', 'actor', 'connection', 'duplicate', 'page'])('unbound %s mappings invalidate all previously captured intents', async kind => {
  const current = client(), view = await current.state(); const intent = current.bindUser(view, id(11), id(12), 'Reviewed account mapping');
  if (kind === 'company') mappings.tenantId = id(99);
  if (kind === 'actor') mappings.actorUserId = id(99);
  if (kind === 'connection') mappings.users[0].connectionId = id(99);
  if (kind === 'duplicate') mappings.users.push(microsoftPerson());
  if (kind === 'page') mappings.page = 2;
  await expect(current.mappings(id(8))).rejects.toThrow(); expect(current.canRetry(intent)).toBe(false); expect(api.post).not.toHaveBeenCalled();
});
test('vendor products from another Microsoft directory cannot become a pool binding', async () => {
  const current = client(); await current.state(); products.microsoftTenantId = id(99); await expect(current.products()).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('an uncertain metadata response never retries automatically and an explicit retry keeps the original key/body', async () => {
  const current = client(), view = await current.state(); const intent = current.bindUser(view, id(11), id(12), 'Reviewed account mapping');
  (api.post as jest.Mock).mockRejectedValueOnce(new Error('lost response'));
  await expect(current.write(intent)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1); expect(current.canRetry(intent)).toBe(true);
  (api.post as jest.Mock).mockResolvedValueOnce(ok({ ...microsoftEnvelope, user: { ...microsoftPerson(), id: intent.operationId }, historical: true }, 200, { etag: `"company-microsoft-user-${intent.operationId}-1"` }));
  expect((await current.write(intent)).historical).toBe(true);
  const calls = (api.post as jest.Mock).mock.calls; expect(calls[1][1]).toBe(calls[0][1]); expect(calls[1][2].headers).toEqual(calls[0][2].headers);
});
test('a session change while a read is pending prevents late results and any write', async () => {
  const current = client(), view = await current.state(); const intent = current.bindUser(view, id(11), id(12), 'Reviewed account mapping'); let resolve!: (value: unknown) => void;
  (api.get as jest.Mock).mockImplementationOnce(() => new Promise(done => { resolve = done; }));
  const pending = current.products(); window.dispatchEvent(new Event('od:session-error')); resolve(ok(products)); await expect(pending).rejects.toThrow();
  await expect(current.write(intent)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
