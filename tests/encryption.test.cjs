const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.DATABASE_URL = 'postgresql://test:test@127.0.0.1:5432/test';
process.env.ENCRYPTION_KEY_V1 = crypto.randomBytes(32).toString('hex');
process.env.ENCRYPTION_KEY_V2 = crypto.randomBytes(32).toString('hex');
const { APP_CONFIG } = require('../dist/constants');
const secret = 'JBSWY3DPEHPK3PXP';

// The original synchronous format must remain readable after changing scheduling.
function legacyEncrypt(version) {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(process.env[`ENCRYPTION_KEY_${version.toUpperCase()}`], salt, 200000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(version));
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]).toString('hex');
  return { encrypted, salt: salt.toString('hex'), iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex') };
}

test('concurrent 2FA crypto uses worker KDFs with the original parameters and ciphertext format', async t => {
  const fixtures = { v1: legacyEncrypt('v1'), v2: legacyEncrypt('v2') };
  const original = crypto.pbkdf2;
  const sync = t.mock.method(crypto, 'pbkdf2Sync');
  const asyncKdf = t.mock.method(crypto, 'pbkdf2', function(...args) { return original.apply(this, args); });
  const encryption = require('../dist/utils/encryption');
  for (const version of ['v1', 'v2']) {
    assert.equal(await encryption.decrypt2FASecret(fixtures[version], version), secret);
  }
  const encrypted = await Promise.all(Array.from({ length: 16 }, () => encryption.encrypt2FASecret(secret)));
  const decrypted = await Promise.all(encrypted.map(({ encryptedData, version }) => encryption.decrypt2FASecret(encryptedData, version)));
  assert.ok(decrypted.every(value => value === secret));
  assert.equal(new Set(encrypted.map(item => item.encryptedData.salt)).size, 16);
  t.diagnostic(`KDF calls for 16 round trips and 2 legacy decryptions: sync=${sync.mock.callCount()}, async=${asyncKdf.mock.callCount()}`);
  assert.equal(sync.mock.callCount(), 0);
  assert.equal(asyncKdf.mock.callCount(), 34);
  for (const { arguments: args } of asyncKdf.mock.calls) {
    assert.equal(args[2], APP_CONFIG.ENCRYPTION.PBKDF2_ITERATIONS);
    assert.equal(args[2], 200000);
    assert.equal(args[3], 32);
    assert.equal(args[4], 'sha256');
  }
  // New ciphertext can still be decrypted with the original synchronous algorithm.
  const { encryptedData, version } = encrypted[0];
  const key = crypto.pbkdf2Sync(process.env.ENCRYPTION_KEY_V1, Buffer.from(encryptedData.salt, 'hex'), 200000, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encryptedData.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
  decipher.setAAD(Buffer.from(version));
  assert.equal(Buffer.concat([decipher.update(encryptedData.encrypted, 'hex'), decipher.final()]).toString('utf8'), secret);
});

test('2FA crypto still rejects tampering, wrong versions and missing keys', async () => {
  const encryption = require('../dist/utils/encryption');
  const { encryptedData } = await encryption.encrypt2FASecret(secret);
  await assert.rejects(async () => encryption.decrypt2FASecret({ ...encryptedData, tag: '00'.repeat(16) }, 'v1'), /Failed to decrypt/);
  await assert.rejects(async () => encryption.decrypt2FASecret(encryptedData, 'v2'), /Failed to decrypt/);
  const key = process.env.ENCRYPTION_KEY_V1;
  delete process.env.ENCRYPTION_KEY_V1;
  try {
    await assert.rejects(async () => encryption.encrypt2FASecret(secret), /not found in environment/);
  } finally {
    process.env.ENCRYPTION_KEY_V1 = key;
  }
});
