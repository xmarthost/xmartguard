import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { enrollmentToken, hashPassword, parseEd25519PublicKey, verifyEd25519, verifyPassword } from '../src/security.js';

describe('passwords', () => {
  it('hashes and verifies', async () => {
    const h = await hashPassword('s3cret-password');
    expect(h.startsWith('scrypt$')).toBe(true);
    expect(await verifyPassword('s3cret-password', h)).toBe(true);
    expect(await verifyPassword('wrong', h)).toBe(false);
    expect(await verifyPassword('x', 'garbage')).toBe(false);
  });
});

describe('enrollment tokens', () => {
  it('have the expected shape and are unique', () => {
    const a = enrollmentToken();
    expect(a).toMatch(/^XG-([A-HJ-NP-Z2-9]{4}-){4}[A-HJ-NP-Z2-9]{4}$/);
    expect(enrollmentToken()).not.toBe(a);
  });
});

describe('ed25519', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64');

  it('verifies agent signatures', () => {
    const sig = crypto.sign(null, Buffer.from('msg'), privateKey).toString('base64');
    expect(verifyEd25519(raw, 'msg', sig)).toBe(true);
    expect(verifyEd25519(raw, 'other', sig)).toBe(false);
  });

  it('rejects malformed keys and signatures', () => {
    expect(parseEd25519PublicKey('abc')).toBeNull();
    expect(parseEd25519PublicKey(Buffer.alloc(31).toString('base64'))).toBeNull();
    expect(verifyEd25519(raw, 'msg', 'AAAA')).toBe(false);
  });
});
