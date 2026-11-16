// Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import WebSocket, { WebSocketServer } from 'ws';
import { createAuth, hashPassword, verifyPassword, validateUsername, validatePassword } from '../src/auth.js';

const silent = { info() { }, warn() { }, error() { } };
const PASSWORD = 'correct horse battery';
const passwordHash = await hashPassword(PASSWORD);

function memoryStore() {
    const accounts = new Map();
    const sessions = new Map();
    return {
        accounts,
        sessions,
        async getAccountByUsername(username) {
            return [...accounts.values()].find((a) => a.username.toLowerCase() === username.toLowerCase()) || null;
        },
        async createAuthSession(tokenHash, userId, expiresAt) {
            sessions.set(tokenHash, { user_id: userId, expires_at: expiresAt });
        },
        async getAuthSession(tokenHash) {
            const session = sessions.get(tokenHash);
            const account = session && accounts.get(session.user_id);
            if (!account) return null;
            return { user_id: account.user_id, username: account.username, disabled: account.disabled, expires_at: session.expires_at };
        },
        async deleteAuthSession(tokenHash) { sessions.delete(tokenHash); },
        async purgeExpiredAuthSessions(now) {
            for (const [hash, s] of sessions) if (s.expires_at <= now) sessions.delete(hash);
        },
    };
}

async function startApp(config = {}) {
    const store = memoryStore();
    store.accounts.set('id-alice', { user_id: 'id-alice', username: 'Alice', password_hash: passwordHash, disabled: 0 });
    store.accounts.set('id-bob', { user_id: 'id-bob', username: 'Bobby', password_hash: passwordHash, disabled: 1 });

    const auth = createAuth({ store, logger: silent, env: {}, config: { sessionCacheMs: 0, ...config } });
    const server = http.createServer((req, res) => {
        auth.middleware(req, res, () => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('app'); });
    });
    const connections = [];
    const wss = new WebSocketServer({ server, verifyClient: auth.verifyWebSocket });
    wss.on('connection', (ws, request) => {
        connections.push(request.stmpAccount);
        ws.close();
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return {
        auth, store, connections,
        port: server.address().port,
        close: () => { wss.close(); server.closeAllConnections(); return new Promise((resolve) => server.close(resolve)); },
    };
}

function request(port, { method = 'GET', path = '/', headers = {}, json } = {}) {
    return new Promise((resolve, reject) => {
        const body = json === undefined ? undefined : JSON.stringify(json);
        const req = http.request({
            host: '127.0.0.1', port, method, path,
            headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
        }, (res) => {
            let text = '';
            res.on('data', (c) => (text += c));
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text, json: () => JSON.parse(text) }));
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

const login = (port, username = 'Alice', password = PASSWORD, headers = {}) =>
    request(port, { method: 'POST', path: '/auth/login', json: { username, password }, headers });

const cookieFrom = (response) => response.headers['set-cookie'][0].split(';')[0];

function connectWs(port, headers = {}) {
    return new Promise((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}/`, { headers });
        ws.on('open', () => resolve({ opened: true }));
        ws.on('unexpected-response', (req, res) => { resolve({ opened: false, status: res.statusCode }); req.destroy(); });
        ws.on('error', () => { });
    });
}

//MARK: units
test('passwords: hash and verify', async () => {
    assert.equal(await verifyPassword(PASSWORD, passwordHash), true);
    assert.equal(await verifyPassword('wrong password!', passwordHash), false);
    assert.equal(await verifyPassword(PASSWORD, 'not-a-hash'), false);
    assert.notEqual(await hashPassword(PASSWORD), passwordHash, 'each hash gets its own salt');
});

test('username and password rules', () => {
    assert.equal(validateUsername('Alice_01'), null);
    assert.ok(validateUsername('ab'));
    assert.ok(validateUsername('has space'));
    assert.ok(validateUsername('123456'));
    assert.ok(validateUsername('waytoolongusername'));
    assert.equal(validatePassword(PASSWORD), null);
    assert.ok(validatePassword('short'));
});

test('client IP: X-Forwarded-For only believed from a trusted proxy', () => {
    const { getClientIP } = createAuth({ store: memoryStore(), logger: silent, env: {} });
    const req = (remoteAddress, xff) => ({ socket: { remoteAddress }, headers: xff ? { 'x-forwarded-for': xff } : {} });
    assert.equal(getClientIP(req('203.0.113.9', '1.2.3.4')), '203.0.113.9', 'forged header from a direct client is ignored');
    assert.equal(getClientIP(req('127.0.0.1', '198.51.100.7')), '198.51.100.7');
    assert.equal(getClientIP(req('::ffff:127.0.0.1', '6.6.6.6, 198.51.100.7')), '198.51.100.7', 'right-most untrusted entry wins');
    assert.equal(getClientIP(req('127.0.0.1')), '127.0.0.1');
});

//MARK: HTTP
test('anonymous requests are sent to the login page or refused', async () => {
    const app = await startApp();
    try {
        const page = await request(app.port, { path: '/', headers: { Accept: 'text/html' } });
        assert.equal(page.status, 302);
        assert.equal(page.headers.location, '/login.html');

        assert.equal((await request(app.port, { path: '/script.js', headers: { Accept: '*/*' } })).status, 401);
        assert.equal((await request(app.port, { path: '/characters/secret.png' })).status, 401);
        assert.equal((await request(app.port, { path: '/auth/me' })).status, 401);

        const loginPage = await request(app.port, { path: '/login.html' });
        assert.equal(loginPage.status, 200, 'the login page itself must stay reachable');
    } finally { await app.close(); }
});

test('login: wrong password and unknown user look the same', async () => {
    const app = await startApp();
    try {
        const wrong = await login(app.port, 'Alice', 'wrong password!');
        const unknown = await login(app.port, 'Nobody', PASSWORD);
        const disabled = await login(app.port, 'Bobby', PASSWORD);
        for (const r of [wrong, unknown, disabled]) {
            assert.equal(r.status, 401);
            assert.equal(r.text, wrong.text);
            assert.equal(r.headers['set-cookie'], undefined);
        }
    } finally { await app.close(); }
});

test('login: request validation', async () => {
    const app = await startApp();
    try {
        const noType = await request(app.port, { method: 'POST', path: '/auth/login', headers: { 'Content-Type': 'text/plain' } });
        assert.equal(noType.status, 415);
        assert.equal((await login(app.port, 'Alice', '')).status, 400);
        const foreign = await login(app.port, 'Alice', PASSWORD, { Origin: 'https://evil.example' });
        assert.equal(foreign.status, 403, 'cross-site login attempt');
        const sameSite = await login(app.port, 'Alice', PASSWORD, { Origin: `http://127.0.0.1:${app.port}` });
        assert.equal(sameSite.status, 200);
    } finally { await app.close(); }
});

test('login, session cookie, logout', async () => {
    const app = await startApp();
    try {
        const ok = await login(app.port);
        assert.equal(ok.status, 200);
        assert.deepEqual(ok.json(), { ok: true, username: 'Alice', userId: 'id-alice' });
        const setCookie = ok.headers['set-cookie'][0];
        assert.match(setCookie, /HttpOnly/);
        assert.match(setCookie, /SameSite=Lax/);
        assert.doesNotMatch(setCookie, /Secure/, 'plain HTTP: no Secure flag');
        assert.equal(app.store.sessions.has(cookieFrom(ok).split('=')[1]), false, 'only a hash of the token is stored');

        const cookie = cookieFrom(ok);
        assert.equal((await request(app.port, { path: '/', headers: { Cookie: cookie, Accept: 'text/html' } })).text, 'app');
        assert.equal((await request(app.port, { path: '/auth/me', headers: { Cookie: cookie } })).json().username, 'Alice');

        const out = await request(app.port, { method: 'POST', path: '/auth/logout', headers: { Cookie: cookie } });
        assert.equal(out.status, 200);
        assert.match(out.headers['set-cookie'][0], /Max-Age=0/);
        assert.equal(app.store.sessions.size, 0);
        assert.equal((await request(app.port, { path: '/auth/me', headers: { Cookie: cookie } })).status, 401, 'old cookie is dead');
    } finally { await app.close(); }
});

test('cookie is Secure behind an HTTPS reverse proxy', async () => {
    const app = await startApp();
    try {
        const r = await login(app.port, 'Alice', PASSWORD, { 'X-Forwarded-Proto': 'https' });
        assert.match(r.headers['set-cookie'][0], /; Secure/);
    } finally { await app.close(); }
});

test('expired and disabled sessions are refused', async () => {
    const app = await startApp();
    try {
        const cookie = cookieFrom(await login(app.port));
        const session = [...app.store.sessions.values()][0];

        session.expires_at = Date.now() - 1;
        assert.equal((await request(app.port, { path: '/auth/me', headers: { Cookie: cookie } })).status, 401);

        session.expires_at = Date.now() + 60000;
        assert.equal((await request(app.port, { path: '/auth/me', headers: { Cookie: cookie } })).status, 200);
        app.store.accounts.get('id-alice').disabled = 1;
        assert.equal((await request(app.port, { path: '/auth/me', headers: { Cookie: cookie } })).status, 401);
    } finally { await app.close(); }
});

test('brute force: locked after 5 failures, even with the right password', async () => {
    const app = await startApp();
    try {
        for (let i = 0; i < 5; i++) assert.equal((await login(app.port, 'Alice', 'wrong password!')).status, 401);
        const locked = await login(app.port, 'Alice', PASSWORD);
        assert.equal(locked.status, 429);
        assert.ok(Number(locked.headers['retry-after']) > 0);
        // another account from the same IP is not locked by the per-account counter
        assert.equal((await login(app.port, 'Bobby', PASSWORD)).status, 401);
    } finally { await app.close(); }
});

test('login can be switched off with requireLogin: false', async () => {
    const app = await startApp({ requireLogin: false });
    try {
        assert.equal((await request(app.port, { path: '/', headers: { Accept: 'text/html' } })).text, 'app');
        assert.equal((await connectWs(app.port)).opened, true);
    } finally { await app.close(); }
});

//MARK: WebSocket
test('WebSocket: needs a valid session and the right Origin', async () => {
    const app = await startApp();
    try {
        assert.equal((await connectWs(app.port)).status, 401, 'no cookie');
        assert.equal((await connectWs(app.port, { Cookie: 'stmp_session=forged' })).status, 401, 'forged cookie');

        const cookie = cookieFrom(await login(app.port));
        assert.equal((await connectWs(app.port, { Cookie: cookie, Origin: 'https://evil.example' })).status, 403, 'cross-site WebSocket');

        const good = await connectWs(app.port, { Cookie: cookie, Origin: `http://127.0.0.1:${app.port}` });
        assert.equal(good.opened, true);
        await new Promise((resolve) => setTimeout(resolve, 50));
        assert.deepEqual(app.connections, [{ user_id: 'id-alice', username: 'Alice' }], 'the connection handler sees the account');
    } finally { await app.close(); }
});
