import { webcrypto } from 'node:crypto';
import { TextEncoder } from 'node:util';
import { generateCodeChallenge, generateCodeVerifier } from '@/lib/pkce';

const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
const encoderDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'TextEncoder');

beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  Object.defineProperty(globalThis, 'TextEncoder', { configurable: true, value: TextEncoder });
});

afterEach(() => jest.restoreAllMocks());

afterAll(() => {
  if (cryptoDescriptor) Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
  else Reflect.deleteProperty(globalThis, 'crypto');
  if (encoderDescriptor) Object.defineProperty(globalThis, 'TextEncoder', encoderDescriptor);
  else Reflect.deleteProperty(globalThis, 'TextEncoder');
});

test('matches the RFC 7636 Appendix B S256 challenge vector', async () => {
  await expect(generateCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'))
    .resolves.toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

test('verifiers encode 32 fresh cryptographic bytes as canonical unpadded base64url', () => {
  const randomValues = jest.spyOn(crypto, 'getRandomValues');
  const weakRandom = jest.spyOn(Math, 'random');
  const verifiers = Array.from({ length: 128 }, () => generateCodeVerifier());
  for (const verifier of verifiers) {
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const bytes = Buffer.from(verifier, 'base64url');
    expect(bytes.length).toBe(32);
    expect(bytes.toString('base64url')).toBe(verifier);
  }
  expect(new Set(verifiers).size).toBe(verifiers.length);
  expect(randomValues).toHaveBeenCalledTimes(verifiers.length);
  for (const [bytes] of randomValues.mock.calls) {
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.byteLength).toBe(32);
  }
  expect(weakRandom).not.toHaveBeenCalled();
});

test('propagates cryptographic RNG failure without a fallback verifier', () => {
  jest.spyOn(crypto, 'getRandomValues').mockImplementation(() => { throw new Error('RNG unavailable'); });
  expect(() => generateCodeVerifier()).toThrow('RNG unavailable');
});

test('propagates digest failure without a substitute challenge', async () => {
  jest.spyOn(crypto.subtle, 'digest').mockRejectedValue(new Error('Digest unavailable'));
  await expect(generateCodeChallenge('verifier')).rejects.toThrow('Digest unavailable');
});
