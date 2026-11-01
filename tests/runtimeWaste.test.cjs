const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Module = require('node:module');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.ENCRYPTION_KEY_V1 = crypto.randomBytes(32).toString('hex');
process.env.DATABASE_URL = 'postgresql://test:test@127.0.0.1:5432/test';

let constructions = 0;
let lookups = [];
let writes = [];
let storedToken = { userId: 'audit-user', expiresAt: new Date('2100-01-01') };
const prisma = {
  refreshToken: {
    findUnique: async args => { lookups.push(args); return storedToken; },
    delete: async args => { writes.push(args); return {}; },
    create: async args => { writes.push(args); return {}; },
  },
  $transaction: operations => Promise.all(operations),
};
const load = Module._load;
Module._load = function(name, ...args) {
  if (name === '../generated/prisma') {
    return { PrismaClient: class { constructor() { constructions++; return prisma; } }, DeviceType: {} };
  }
  return load.call(this, name, ...args);
};
let auth, verifyToken;
try {
  auth = require('../dist/controllers/authController');
  require('../dist/controllers/passkeyController');
  require('../dist/services/cleanupService');
  ({ verifyToken } = require('../dist/middleware/authMiddleware'));
} finally {
  Module._load = load;
}

function response() {
  return {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

test('auth, passkeys and cleanup share one Prisma client', t => {
  t.diagnostic(`Prisma client constructions: ${constructions}`);
  assert.equal(constructions, 1);
});

test('100 refresh requests load no user relations and preserve rotation', async t => {
  for (let i = 0; i < 100; i++) {
    const res = response();
    await auth.refreshTokenHandler({ body: { refreshToken: `audit-token-${i}` } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(jwt.verify(res.body.accessToken, process.env.JWT_SECRET).userId, 'audit-user');
    assert.ok(res.body.refreshToken);
  }
  t.diagnostic(`Refresh lookups: ${lookups.length}; user relation fetches requested: ${lookups.filter(args => args.include?.user).length}`);
  assert.equal(lookups.length, 100);
  assert.equal(writes.length, 200);
  assert.ok(lookups.every(args => !args.include?.user));
});

test('invalid and expired refresh tokens still reject without writes', async () => {
  for (const [token, status] of [[null, 401], [{ expiresAt: new Date('2000-01-01') }, 403]]) {
    storedToken = token;
    writes = [];
    const res = response();
    await auth.refreshTokenHandler({ body: { refreshToken: 'audit-token' } }, res);
    assert.equal(res.statusCode, status);
    assert.equal(writes.length, 0);
  }
});

test('1000 access-token checks do no database work or client construction', () => {
  lookups = [];
  const before = constructions;
  const token = jwt.sign({ userId: 'audit-user' }, process.env.JWT_SECRET);
  let continued = 0;
  for (let i = 0; i < 1000; i++) {
    verifyToken({ headers: { authorization: `Bearer ${token}` } }, response(), () => continued++);
  }
  assert.equal(continued, 1000);
  assert.equal(lookups.length, 0);
  assert.equal(constructions, before);
});
