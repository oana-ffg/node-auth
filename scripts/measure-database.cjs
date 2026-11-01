// Run only against a disposable PostgreSQL database; see docs/RUNTIME-AUDIT.md.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Module = require('node:module');

assert.ok(process.env.AUDIT_DATABASE_URL, 'Set AUDIT_DATABASE_URL to a disposable audit database');
const url = new URL(process.env.AUDIT_DATABASE_URL);
assert.ok(['127.0.0.1', '[::1]'].includes(url.hostname), 'Audit database must be on loopback');
assert.equal(url.pathname, '/node_auth_waste_audit', 'Use a dedicated disposable database');
assert.equal(url.search, '', 'Do not redirect the audit to another schema');
process.env.DATABASE_URL = url.href;
process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.ENCRYPTION_KEY_V1 = crypto.randomBytes(32).toString('hex');
process.env.ENCRYPTION_VERSION_FOR_NEW_DATA = 'v1';
process.env.JWT_EXPIRES_IN = '15m';
process.env.JWT_REFRESH_EXPIRES_IN = '7d';

const generated = require('../src/generated/prisma');
const clients = [];
const queries = [];
class ObservedPrismaClient extends generated.PrismaClient {
  constructor() {
    super({ log: [{ level: 'query', emit: 'event' }] });
    this.$on('query', event => queries.push(event.query));
    clients.push(this);
  }
}

const load = Module._load;
Module._load = function(name, ...args) {
  if (name === '../generated/prisma') return { ...generated, PrismaClient: ObservedPrismaClient };
  return load.call(this, name, ...args);
};
let refreshTokenHandler;
try {
  ({ refreshTokenHandler } = require('../dist/controllers/authController'));
} finally {
  Module._load = load;
}

async function measure() {
  const prisma = clients[0];
  assert.equal(await prisma.refreshToken.count(), 0, 'Start with an empty audit database');
  const user = await prisma.user.create({
    data: { email: `${crypto.randomUUID()}@example.com`, password: 'unused-audit-fixture' },
  });
  try {
    const token = await prisma.refreshToken.create({
      data: { token: crypto.randomUUID(), userId: user.id, expiresAt: new Date('2100-01-01') },
    });
    queries.length = 0;
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
    };
    await refreshTokenHandler({ body: { refreshToken: token.token } }, res);
    assert.equal(res.statusCode, 200, JSON.stringify(res.body));
    const refreshSelects = queries.filter(sql => sql.startsWith('SELECT'));
    console.log(JSON.stringify({
      refreshRequests: 1,
      selectQueries: refreshSelects.length,
      userSelectQueries: refreshSelects.filter(sql => sql.includes('FROM "public"."User"')).length,
    }));
    if (process.argv.includes('--check')) {
      assert.equal(refreshSelects.length, 1, 'Refresh must load only the token');
      assert.equal(refreshSelects.filter(sql => sql.includes('FROM "public"."User"')).length, 0);
    }

    // Leave 100 expired rows among 100,000 rows, with the rest valid until 2100.
    await prisma.refreshToken.deleteMany({ where: { userId: user.id } });
    await prisma.$executeRaw`
      INSERT INTO "RefreshToken" ("id", "token", "userId", "expiresAt")
      SELECT 'audit-token-' || i, 'audit-token-' || i, ${user.id},
             CASE WHEN i <= 100 THEN TIMESTAMP '2000-01-01' ELSE TIMESTAMP '2100-01-01' END
      FROM generate_series(1, 100000) AS i
    `;
    await prisma.$executeRawUnsafe('ANALYZE "RefreshToken"');
    const [explain] = await prisma.$queryRawUnsafe(`
      EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
      DELETE FROM "RefreshToken" WHERE "expiresAt" < TIMESTAMP '2026-01-01'
    `);
    const plan = explain['QUERY PLAN'][0].Plan;
    console.log(JSON.stringify({ cleanupRows: 100000, expiredRows: 100, plan }));
    if (process.argv.includes('--check')) {
      const scans = [];
      function collect(node) {
        scans.push(node);
        for (const child of node.Plans || []) collect(child);
      }
      collect(plan);
      assert.ok(scans.some(node => node['Index Name'] === 'RefreshToken_expiresAt_idx'));
      assert.ok(scans.every(node => node['Node Type'] !== 'Seq Scan'));
      assert.equal(await prisma.refreshToken.count(), 99900);
    }
    const indexes = await prisma.$queryRawUnsafe(`
      SELECT tablename, indexname, indexdef FROM pg_indexes
      WHERE schemaname = 'public' AND tablename IN ('Passkey', 'Challenge')
      ORDER BY tablename, indexname
    `);
    console.log(JSON.stringify({ indexes }));
    if (process.argv.includes('--check')) {
      const names = indexes.map(index => index.indexname);
      assert.ok(names.includes('Passkey_credentialId_key'));
      assert.ok(names.includes('Challenge_challenge_key'));
      assert.ok(!names.includes('Passkey_credentialId_idx'));
      assert.ok(!names.includes('Challenge_challenge_idx'));
      for (const name of ['Passkey_credentialId_key', 'Challenge_challenge_key']) {
        assert.ok(indexes.find(index => index.indexname === name).indexdef.startsWith('CREATE UNIQUE INDEX'));
      }
    }
  } finally {
    // Only remove this run's synthetic user and its cascade-owned fixture tokens.
    await prisma.user.delete({ where: { id: user.id } });
  }
}

async function main() {
  try {
    await measure();
  } finally {
    await Promise.all(clients.map(client => client.$disconnect()));
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
