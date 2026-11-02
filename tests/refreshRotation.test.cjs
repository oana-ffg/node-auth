const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Module = require('node:module');
const express = require('express');
const jwt = require('jsonwebtoken');

// Opt in with an empty disposable database; ordinary tests never use DATABASE_URL.
const databaseUrl = process.env.REFRESH_TEST_DATABASE_URL;

test('refresh rotation against disposable PostgreSQL', {
  skip: databaseUrl ? false : 'Set REFRESH_TEST_DATABASE_URL to a migrated disposable node_auth_refresh_test database',
  timeout: 30000,
}, async t => {
  const url = new URL(databaseUrl);
  assert.equal(url.protocol, 'postgresql:');
  assert.ok(['127.0.0.1', '[::1]'].includes(url.hostname));
  assert.equal(url.pathname, '/node_auth_refresh_test');
  assert.equal(url.search, '', 'Do not redirect the test to another schema or host');
  process.env.DATABASE_URL = url.href;
  process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
  process.env.ENCRYPTION_KEY_V1 = crypto.randomBytes(32).toString('hex');
  process.env.ENCRYPTION_VERSION_FOR_NEW_DATA = 'v1';
  process.env.JWT_EXPIRES_IN = '15m';
  process.env.JWT_REFRESH_EXPIRES_IN = '7d';

  const { PrismaClient } = require('../src/generated/prisma');
  const prisma = new PrismaClient({ log: [{ level: 'query', emit: 'event' }] });
  t.after(() => prisma.$disconnect());
  const queries = [];
  prisma.$on('query', event => queries.push(event.query));
  let afterLookup;
  const runtimeClient = prisma.$extends({
    query: {
      refreshToken: {
        async findUnique({ args, query }) {
          const token = await query(args);
          if (afterLookup) await afterLookup();
          return token;
        },
      },
    },
  });

  const load = Module._load;
  Module._load = function(name, ...args) {
    if (name === '../services/prisma') return { prisma: runtimeClient };
    return load.call(this, name, ...args);
  };
  let refreshTokenHandler;
  try {
    ({ refreshTokenHandler } = require('../dist/controllers/authController'));
  } finally {
    Module._load = load;
  }

  const app = express();
  app.use(express.json());
  app.post('/refresh', refreshTokenHandler);
  const server = await new Promise((resolve, reject) => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
    instance.once('error', reject);
  });
  t.after(() => new Promise((resolve, reject) => {
    server.closeAllConnections();
    server.close(error => error ? reject(error) : resolve());
  }));
  const endpoint = `http://127.0.0.1:${server.address().port}/refresh`;

  async function fixture(subtest, expiresAt = new Date('2100-01-01')) {
    const user = await prisma.user.create({
      data: { email: `${crypto.randomUUID()}@example.com`, password: 'unused-test-password' },
    });
    subtest.after(() => prisma.user.delete({ where: { id: user.id } }));
    const token = await prisma.refreshToken.create({
      data: { token: crypto.randomUUID(), userId: user.id, expiresAt },
    });
    return { user, token };
  }

  async function refresh(token) {
    const response = await fetch(endpoint, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: token }),
      signal: AbortSignal.timeout(5000),
    });
    return { status: response.status, body: await response.json() };
  }

  function statements() {
    return queries.map(sql => sql.trim().split(/\s+/)[0]);
  }

  function assertLogin(response, userId, oldToken) {
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(response.body).sort(), ['accessToken', 'message', 'refreshToken']);
    assert.equal(response.body.message, 'Token refreshed successfully');
    const decoded = jwt.verify(response.body.accessToken, process.env.JWT_SECRET);
    assert.equal(decoded.userId, userId);
    assert.equal(decoded.exp - decoded.iat, 15 * 60);
    assert.match(response.body.refreshToken, /^[0-9a-f-]{36}$/);
    assert.notEqual(response.body.refreshToken, oldToken);
  }

  await t.test('a successful refresh performs one lookup and one write statement', async subtest => {
    const { user, token } = await fixture(subtest);
    queries.length = 0;
    const before = Date.now();
    const response = await refresh(token.token);
    const after = Date.now();
    const commands = statements();
    subtest.diagnostic(JSON.stringify({ status: response.status, statements: commands }));
    assertLogin(response, user.id, token.token);
    const rotated = await prisma.refreshToken.findUnique({ where: { token: response.body.refreshToken } });
    assert.equal(rotated.userId, user.id);
    assert.equal(rotated.revoked, false);
    assert.ok(rotated.expiresAt.getTime() >= before + 7 * 24 * 60 * 60 * 1000);
    assert.ok(rotated.expiresAt.getTime() <= after + 7 * 24 * 60 * 60 * 1000);
    assert.deepEqual(commands, ['SELECT', 'UPDATE']);
  });

  await t.test('an already-rotated token returns the same HTTP 401 without writes', async subtest => {
    const { user, token } = await fixture(subtest);
    const first = await refresh(token.token);
    assertLogin(first, user.id, token.token);
    queries.length = 0;
    const reused = await refresh(token.token);
    assert.deepEqual(reused, { status: 401, body: { error: 'Invalid refresh token.' } });
    assert.deepEqual(statements(), ['SELECT']);
    subtest.diagnostic(JSON.stringify(reused));
  });

  await t.test('an expired token returns the same HTTP 403 and remains stored', async subtest => {
    const { token } = await fixture(subtest, new Date('2000-01-01'));
    queries.length = 0;
    const expired = await refresh(token.token);
    assert.deepEqual(expired, { status: 403, body: { error: 'Refresh token has expired.' } });
    assert.deepEqual(statements(), ['SELECT']);
    assert.deepEqual(await prisma.refreshToken.findUnique({ where: { token: token.token } }), token);
    subtest.diagnostic(JSON.stringify(expired));
  });

  await t.test('concurrent double-refresh keeps one winner and the same P2025 HTTP 500 loser', async subtest => {
    const { user, token } = await fixture(subtest);
    const errors = [];
    subtest.mock.method(console, 'error', error => errors.push(error));
    let lookups = 0;
    let release;
    const ready = new Promise(resolve => { release = resolve; });
    // Real SELECTs finish before either request can write, making the race deterministic.
    afterLookup = () => {
      if (++lookups === 2) release();
      return ready;
    };
    let responses;
    try {
      responses = await Promise.all([refresh(token.token), refresh(token.token)]);
    } finally {
      afterLookup = undefined;
      release();
    }
    assert.equal(lookups, 2);
    const winner = responses.find(response => response.status === 200);
    const loser = responses.find(response => response.status === 500);
    assert.ok(winner);
    assertLogin(winner, user.id, token.token);
    assert.deepEqual(loser, { status: 500, body: { error: 'Internal server error.' } });
    assert.equal(errors.length, 1);
    assert.equal(errors[0].code, 'P2025');
    assert.equal(await prisma.refreshToken.count({ where: { userId: user.id } }), 1);
    assert.equal(await prisma.refreshToken.findUnique({ where: { token: token.token } }), null);
    assert.ok(await prisma.refreshToken.findUnique({ where: { token: winner.body.refreshToken } }));
    subtest.diagnostic(JSON.stringify({ statuses: responses.map(response => response.status).sort(), loserErrorCode: errors[0].code }));
  });
});
