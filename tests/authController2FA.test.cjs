const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Module = require('node:module');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');

process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.ENCRYPTION_KEY_V1 = crypto.randomBytes(32).toString('hex');
process.env.ENCRYPTION_VERSION_FOR_NEW_DATA = 'v1';
process.env.DATABASE_URL = 'postgresql://test:test@127.0.0.1:5432/test';

const user = {
  id: 'audit-user', email: 'audit@example.com', password: 'audit-password-hash',
  twoFactorEnabled: false, twoFactorSecret: null, encryptionVersion: 'v1',
};
const tokens = [];
const prisma = {
  user: {
    findUnique: async () => ({ ...user }),
    update: async ({ data }) => Object.assign(user, data),
  },
  refreshToken: { create: async ({ data }) => tokens.push(data) },
};
const load = Module._load;
Module._load = function(name, ...args) {
  if (name === '../generated/prisma') return { PrismaClient: class { constructor() { return prisma; } } };
  return load.call(this, name, ...args);
};
let controller;
try {
  controller = require('../dist/controllers/authController');
} finally {
  Module._load = load;
}
const encryption = require('../dist/utils/encryption');

async function request(handler, body) {
  const res = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
  };
  await handler({ userId: user.id, body }, res);
  return res;
}

test('2FA setup, confirmation, login, existing setup and reset await encryption', async t => {
  const compare = t.mock.method(bcrypt, 'compare', async () => true);
  const setup = await request(controller.generate2FASecret, { password: 'audit-password' });
  assert.equal(setup.statusCode, 200, JSON.stringify(setup.body));
  assert.ok(setup.body.qrCodeDataURL.startsWith('data:image/png;base64,'));
  const savedSecret = user.twoFactorSecret;
  const secret = await encryption.decrypt2FASecret(encryption.deserializeEncryptedData(savedSecret), 'v1');
  const confirmation = await request(controller.confirm2FA, { otp: speakeasy.totp({ secret, encoding: 'base32' }) });
  assert.equal(confirmation.statusCode, 200, JSON.stringify(confirmation.body));
  assert.equal(user.twoFactorEnabled, true);
  const tempToken = jwt.sign({ userId: user.id, temp: true, purpose: '2fa_verification' }, process.env.JWT_SECRET, { expiresIn: '5m' });
  const login = await request(controller.loginWith2FA, { tempToken, otp: speakeasy.totp({ secret, encoding: 'base32' }) });
  assert.equal(login.statusCode, 200, JSON.stringify(login.body));
  assert.equal(jwt.verify(login.body.accessToken, process.env.JWT_SECRET).userId, user.id);
  assert.equal(tokens.length, 1);
  const existing = await request(controller.generate2FASecret, { password: 'audit-password' });
  assert.equal(existing.statusCode, 200, JSON.stringify(existing.body));
  assert.equal(user.twoFactorSecret, savedSecret);
  assert.ok(existing.body.otpauthUrl.startsWith('otpauth://totp/'));
  const reset = await request(controller.reset2FA, { password: 'audit-password' });
  assert.equal(reset.statusCode, 200, JSON.stringify(reset.body));
  assert.equal(user.twoFactorEnabled, false);
  assert.notEqual(user.twoFactorSecret, savedSecret);
  const resetSecret = await encryption.decrypt2FASecret(encryption.deserializeEncryptedData(user.twoFactorSecret), 'v1');
  assert.ok(reset.body.otpauthUrl.includes(resetSecret));
  assert.equal(compare.mock.callCount(), 3);
});

test('invalid OTPs and failed async decryptions do not enable 2FA', async t => {
  const encrypted = await encryption.encrypt2FASecret('JBSWY3DPEHPK3PXP');
  user.twoFactorSecret = encryption.serializeEncryptedData(encrypted.encryptedData);
  user.twoFactorEnabled = false;
  const initialTokens = tokens.length;
  const invalid = await request(controller.confirm2FA, { otp: 'ABCDEF' });
  assert.equal(invalid.statusCode, 400);
  assert.equal(user.twoFactorEnabled, false);
  const data = encryption.deserializeEncryptedData(user.twoFactorSecret);
  user.twoFactorSecret = encryption.serializeEncryptedData({ ...data, tag: '00'.repeat(16) });
  const errors = t.mock.method(console, 'error', () => {});
  const failure = await request(controller.confirm2FA, { otp: '123456' });
  assert.equal(failure.statusCode, 500);
  assert.equal(errors.mock.callCount(), 1);
  assert.equal(user.twoFactorEnabled, false);
  assert.equal(tokens.length, initialTokens);
});
