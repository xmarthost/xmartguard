import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { createChallenge, randomInt } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';
import { CappedMap, create, deriveHmacKeySecret } from 'altcha-lib/frameworks/fastify';

/**
 * ALTCHA (open source, MIT): a proof-of-work check the visitor's browser
 * solves by itself, run entirely by this portal (no third party). Used
 * alone or when Cloudflare Turnstile cannot load for a visitor.
 *
 * The secrets live only in this process: a restart only makes open checks
 * (valid 5 minutes) fail, and the visitor gets a new one.
 */

const hmacSecret = randomBytes(32).toString('hex');
const keySecretP = deriveHmacKeySecret(hmacSecret);
// Solved checks are accepted once.
const used = new CappedMap<string, boolean>({ maxSize: 50_000 });

/** Proof-of-work cost: about a second in one thread (the widget uses several). */
export const ALTCHA_COST = 1_500;

/** A new check for the widget. */
export async function altchaChallenge() {
  return createChallenge({
    algorithm: 'PBKDF2/SHA-256',
    cost: ALTCHA_COST,
    counter: randomInt(2_000, 5_000),
    deriveKey,
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    hmacSignatureSecret: hmacSecret,
    hmacKeySignatureSecret: await keySecretP,
  });
}

/** Checks a solved payload (base64 JSON from the widget). */
export async function altchaVerify(payload: string): Promise<boolean> {
  if (!payload || payload.length > 8192) return false;
  try {
    const r = await create({ deriveKey, hmacSignatureSecret: hmacSecret }).verify(payload, deriveKey, hmacSecret, await keySecretP, used);
    return !r.error && r.verification?.verified === true;
  } catch {
    return false;
  }
}

/** The widget's script (served from this portal, not a CDN). */
export const altchaScript: Buffer = (() => {
  const require = createRequire(import.meta.url);
  // The package exports its UMD build; the browser bundle is next to it.
  return readFileSync(join(dirname(require.resolve('altcha')), 'altcha.min.js'));
})();
