const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.DATABASE_URL = 'postgresql://test:test@127.0.0.1:5432/test';
process.env.ENCRYPTION_KEY_V1 = crypto.randomBytes(32).toString('hex');
const { verifyToken } = require('../dist/middleware/authMiddleware');

function authenticate(payload) {
  const token = jwt.sign(payload, process.env.JWT_SECRET);
  const req = { headers: { authorization: `Bearer ${token}` } };
  const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  let continued = false;
  verifyToken(req, res, () => { continued = true; });
  return { req, res, continued };
}

test('accepts a signed access token', () => {
  const result = authenticate({ userId: 'test-user' });
  assert.equal(result.continued, true);
  assert.equal(result.req.userId, 'test-user');
});

for (const payload of [
  { userId: 'test-user', temp: true, purpose: '2fa_verification' },
  { userId: 'test-user', temp: true },
  { userId: 'test-user', purpose: '2fa_verification' },
  { email: 'test@example.com' },
  { userId: null },
  { userId: '' },
  { userId: '   ' },
  { userId: 42 },
  'signed string',
]) {
  test(`rejects non-access payload ${JSON.stringify(payload)}`, () => {
    const result = authenticate(payload);
    assert.equal(result.res.statusCode, 401);
    assert.equal(result.continued, false);
    assert.equal(result.req.userId, undefined);
  });
}
