const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Module = require('node:module');
const express = require('express');
const jwt = require('jsonwebtoken');
process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.ENCRYPTION_KEY_V1 = crypto.randomBytes(32).toString('hex');
process.env.DATABASE_URL = 'postgresql://test:test@127.0.0.1:5432/test';
process.env.JWT_REFRESH_EXPIRES_IN = '2h';
process.env.RATE_LIMIT_MAX_REQUESTS = '2';
const savedTokens = [];
const prisma = {
    challenge: {
        findUnique: async () => ({ id: 'challenge', type: 'authentication', expiresAt: new Date(Date.now() + 60000) }),
        delete: async () => ({}),
    },
    passkey: {
        findUnique: async () => ({ id: 'passkey', credentialId: 'credential', publicKey: '', counter: 0n, transports: [], user: { id: 'test-user' } }),
        update: async () => ({}),
        findMany: async () => [],
    },
    refreshToken: { create: async data => savedTokens.push(data.data) },
};
const originalLoad = Module._load;
Module._load = function(name, ...args) {
    if (name === '../generated/prisma') return { PrismaClient: class { constructor() { return prisma; } }, DeviceType: {} };
    if (name === '@simplewebauthn/server') return { verifyAuthenticationResponse: async () => ({ verified: true, authenticationInfo: { newCounter: 1 } }) };
    return originalLoad.call(this, name, ...args);
};
let controller, router;
try {
    controller = require('../dist/controllers/passkeyController');
    router = require('../dist/routes/passkeyRoutes').default;
} finally { Module._load = originalLoad; }

test('passkey refresh token expiry uses the configured duration', async () => {
    const req = { body: { credential: {
        id: 'credential', rawId: 'credential', type: 'public-key',
        response: { clientDataJSON: Buffer.from(JSON.stringify({ challenge: 'synthetic-challenge' })).toString('base64url'), authenticatorData: 'data', signature: 'signature' },
        clientExtensionResults: {},
    } } };
    const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
    const before = Date.now();
    await controller.completePasskeyAuthentication(req, res);
    assert.equal(res.statusCode, 200, JSON.stringify(res.body));
    assert.equal(savedTokens.length, 1);
    const delay = savedTokens[0].expiresAt.getTime() - before;
    assert.ok(delay >= 2 * 60 * 60 * 1000 && delay < 2 * 60 * 60 * 1000 + 1000);
});

test('passkey management requests count once against the application-wide limiter', async (t) => {
    const app = express();
    app.use(require('../dist/middleware/rateLimitMiddleware').generalRateLimit);
    app.use('/passkeys', router);
    const server = await new Promise(resolve => {
        const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
    });
    t.after(() => new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close(error => error ? reject(error) : resolve());
    }));
    const url = `http://127.0.0.1:${server.address().port}/passkeys/list`;
    const token = jwt.sign({ userId: 'test-user' }, process.env.JWT_SECRET);
    const options = { headers: { Authorization: `Bearer ${token}` } };
    assert.equal((await fetch(url, options)).status, 200);
    assert.equal((await fetch(url, options)).status, 200);
    assert.equal((await fetch(url, options)).status, 429);
});
