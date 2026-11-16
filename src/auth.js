// Authentication for the Guest server (login/password, cookie sessions, WebSocket gate).
//
// This module only depends on Node built-ins so it can be tested in isolation.
// The persistence layer is injected (see src/auth-store.js for the SQLite one).
//
// Store interface:
//   getAccountByUsername(username) -> { user_id, username, password_hash, disabled } | null
//   createAuthSession(tokenHash, userId, expiresAtMs, ip, userAgent)
//   getAuthSession(tokenHash) -> { user_id, username, disabled, expires_at } | null
//   deleteAuthSession(tokenHash)
//   purgeExpiredAuthSessions(nowMs)

import crypto from 'crypto';
import { promisify } from 'util';

const scrypt = promisify(crypto.scrypt);

//MARK: Passwords
const SCRYPT_PARAMS = { N: 32768, r: 8, p: 1, keylen: 64 };
export const MIN_PASSWORD_LENGTH = 10;
export const MAX_PASSWORD_LENGTH = 256;

// Same rules as validateUserName() in public/script.js, so an account name is always a valid display name.
export function validateUsername(name) {
    if (typeof name !== 'string' || !/^[A-Za-z0-9_-]{3,12}$/.test(name)) {
        return 'Username must be 3-12 characters: A-Z, a-z, 0-9, _ or -.';
    }
    if ((name.match(/[A-Za-z]/g) || []).length < 3) {
        return 'Username must contain at least 3 letters (A-Z, a-z).';
    }
    return null;
}

export function validatePassword(password) {
    if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
        return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
    }
    if (password.length > MAX_PASSWORD_LENGTH) {
        return `Password must be at most ${MAX_PASSWORD_LENGTH} characters.`;
    }
    return null;
}

const normalizePassword = (password) => password.normalize('NFKC');

export async function hashPassword(password) {
    const { N, r, p, keylen } = SCRYPT_PARAMS;
    const salt = crypto.randomBytes(16);
    const hash = await scrypt(normalizePassword(password), salt, keylen, { N, r, p, maxmem: 256 * N * r });
    return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export async function verifyPassword(password, stored) {
    try {
        const [alg, N, r, p, saltB64, hashB64] = String(stored).split('$');
        if (alg !== 'scrypt') return false;
        const salt = Buffer.from(saltB64, 'base64');
        const expected = Buffer.from(hashB64, 'base64');
        const params = { N: Number(N), r: Number(r), p: Number(p) };
        const actual = await scrypt(normalizePassword(password), salt, expected.length, {
            ...params,
            maxmem: 256 * params.N * params.r,
        });
        return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    } catch {
        return false;
    }
}

// Verifying against this when the account does not exist keeps response time the same,
// so the login form cannot be used to find out which usernames exist.
let dummyHashPromise = null;
const getDummyHash = () => (dummyHashPromise ??= hashPassword(crypto.randomBytes(16).toString('hex')));

//MARK: Helpers
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

const normalizeIp = (ip) => String(ip || '').replace(/^::ffff:/i, '');

function parseCookies(header) {
    const out = {};
    for (const part of String(header || '').split(';')) {
        const i = part.indexOf('=');
        if (i < 0) continue;
        const key = part.slice(0, i).trim();
        if (key && !(key in out)) out[key] = part.slice(i + 1).trim();
    }
    return out;
}

function buildCookie(name, value, { maxAgeSec, secure }) {
    let cookie = `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}`;
    if (secure) cookie += '; Secure';
    return cookie;
}

function sendJson(res, status, body) {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(payload),
        'Cache-Control': 'no-store',
    });
    res.end(payload);
}

function readJson(req, limitBytes) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on('data', (chunk) => {
            size += chunk.length;
            if (size > limitBytes) {
                reject(Object.assign(new Error('Body too large'), { status: 413 }));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
                reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
            }
        });
        req.on('error', reject);
    });
}

// Sliding-window counter of failures per key.
class FailureLimiter {
    constructor(windowMs) {
        this.windowMs = windowMs;
        this.map = new Map();
    }
    _recent(key, now) {
        const recent = (this.map.get(key) || []).filter((t) => now - t < this.windowMs);
        if (recent.length) this.map.set(key, recent);
        else this.map.delete(key);
        return recent;
    }
    fail(key, now = Date.now()) {
        const recent = this._recent(key, now);
        recent.push(now);
        this.map.set(key, recent);
        if (this.map.size > 10000) this.sweep(now);
    }
    // 0 when allowed, otherwise the number of ms to wait.
    retryAfterMs(key, max, now = Date.now()) {
        const recent = this._recent(key, now);
        if (recent.length < max) return 0;
        return recent[recent.length - max] + this.windowMs - now;
    }
    clear(key) {
        this.map.delete(key);
    }
    sweep(now = Date.now()) {
        for (const key of [...this.map.keys()]) this._recent(key, now);
    }
}

//MARK: Config
function readBool(value, fallback) {
    if (value === undefined || value === '') return fallback;
    return !['0', 'false', 'off', 'no'].includes(String(value).toLowerCase());
}

function readList(value, fallback) {
    if (!value) return fallback;
    return String(value).split(',').map((s) => s.trim()).filter(Boolean);
}

export function readAuthConfig(env = process.env, overrides = {}) {
    const days = Number(env.STMP_SESSION_DAYS);
    const secure = String(env.STMP_COOKIE_SECURE || 'auto').toLowerCase();
    return {
        // Set STMP_REQUIRE_LOGIN=false to run the Guest server without any login (old behaviour).
        requireLogin: readBool(env.STMP_REQUIRE_LOGIN, true),
        sessionDays: days > 0 ? days : 14,
        cookieName: 'stmp_session',
        // 'auto' = Secure cookie when the request came in over HTTPS (directly or via a trusted proxy).
        cookieSecure: secure === 'auto' ? 'auto' : readBool(secure, 'auto'),
        // Reverse proxies whose X-Forwarded-* headers are believed. Default: proxy on the same machine.
        trustedProxies: readList(env.STMP_TRUSTED_PROXIES, ['127.0.0.1', '::1']).map(normalizeIp),
        // Extra Origins allowed to open a WebSocket / POST to /auth (host or full origin).
        allowedOrigins: readList(env.STMP_ALLOWED_ORIGINS, []).map((s) => s.toLowerCase()),
        windowMs: 15 * 60 * 1000,
        maxFailsPerIp: 20,
        maxFailsPerAccount: 5,
        sessionCacheMs: 30 * 1000,
        ...overrides,
    };
}

// Pages the browser must be able to load before logging in. Exact match only; everything else is gated.
const PUBLIC_PATHS = new Set([
    '/login.html',
    '/favicon.ico',
    '/favicon-16x16.png',
    '/favicon-32x32.png',
    '/apple-touch-icon.png',
    '/android-chrome-192x192.png',
    '/android-chrome-512x512.png',
    '/site.webmanifest',
]);

//MARK: createAuth
export function createAuth({ store, logger = console, env = process.env, config = {} }) {
    const cfg = readAuthConfig(env, config);
    const trusted = new Set(cfg.trustedProxies);
    const ipLimiter = new FailureLimiter(cfg.windowMs);
    const accountLimiter = new FailureLimiter(cfg.windowMs);
    const sessionCache = new Map(); // tokenHash -> { account, until }

    const isTrustedProxy = (req) => trusted.has(normalizeIp(req.socket?.remoteAddress));

    // The real client IP. X-Forwarded-For is only believed when the connection comes from a trusted proxy,
    // and the right-most entry that is not itself a trusted proxy wins (the left-most can be forged by the client).
    function getClientIP(req) {
        const remote = normalizeIp(req.socket?.remoteAddress) || 'unknown';
        if (!trusted.has(remote)) return remote.slice(0, 64);
        const forwarded = String(req.headers?.['x-forwarded-for'] || '')
            .split(',').map((s) => normalizeIp(s.trim())).filter(Boolean);
        for (let i = forwarded.length - 1; i >= 0; i--) {
            if (!trusted.has(forwarded[i])) return forwarded[i].slice(0, 64);
        }
        return remote.slice(0, 64);
    }

    function isHttps(req) {
        if (cfg.cookieSecure === true) return true;
        if (cfg.cookieSecure === false) return false;
        if (req.socket?.encrypted) return true;
        if (isTrustedProxy(req)) {
            return String(req.headers?.['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase() === 'https';
        }
        return false;
    }

    // Blocks cross-site WebSocket / POST attempts. Requests with no Origin (curl, bots) are not browsers, so they pass this check.
    function originAllowed(req) {
        const origin = req.headers?.origin;
        if (!origin) return true;
        let originHost;
        try {
            originHost = new URL(origin).host.toLowerCase();
        } catch {
            return false;
        }
        const hosts = [String(req.headers.host || '').toLowerCase()];
        if (isTrustedProxy(req) && req.headers['x-forwarded-host']) {
            hosts.push(String(req.headers['x-forwarded-host']).split(',')[0].trim().toLowerCase());
        }
        if (hosts.includes(originHost)) return true;
        if (cfg.allowedOrigins.includes(originHost) || cfg.allowedOrigins.includes(origin.toLowerCase())) return true;
        logger.warn(`Rejected Origin "${String(origin).slice(0, 100)}" (Host: "${hosts[0]}"). If this is your reverse proxy, make it pass the original Host header, or set STMP_ALLOWED_ORIGINS.`);
        return false;
    }

    async function getSession(req) {
        const token = parseCookies(req.headers?.cookie)[cfg.cookieName];
        if (!token || token.length > 128) return null;
        const tokenHash = hashToken(token);
        const now = Date.now();

        const cached = sessionCache.get(tokenHash);
        if (cached && cached.until > now) return cached.account;

        const row = await store.getAuthSession(tokenHash);
        if (!row || row.disabled || Number(row.expires_at) <= now) {
            sessionCache.delete(tokenHash);
            return null;
        }
        const account = { user_id: row.user_id, username: row.username };
        if (sessionCache.size > 1000) sessionCache.clear();
        // Revoking a session from the CLI takes effect within sessionCacheMs.
        sessionCache.set(tokenHash, { account, until: Math.min(now + cfg.sessionCacheMs, Number(row.expires_at)) });
        return account;
    }

    //MARK: handlers
    async function handleLogin(req, res) {
        const ip = getClientIP(req);
        if (!originAllowed(req)) return sendJson(res, 403, { ok: false, error: 'Forbidden origin.' });
        if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) {
            return sendJson(res, 415, { ok: false, error: 'Expected application/json.' });
        }

        let body;
        try {
            body = await readJson(req, 4096);
        } catch (err) {
            return sendJson(res, err.status || 400, { ok: false, error: 'Bad request.' });
        }
        const username = typeof body?.username === 'string' ? body.username.trim() : '';
        const password = typeof body?.password === 'string' ? body.password : '';
        if (!username || !password) {
            return sendJson(res, 400, { ok: false, error: 'Username and password are required.' });
        }

        const now = Date.now();
        const accountKey = `${ip}|${username.toLowerCase().slice(0, 64)}`;
        const wait = Math.max(
            ipLimiter.retryAfterMs(ip, cfg.maxFailsPerIp, now),
            accountLimiter.retryAfterMs(accountKey, cfg.maxFailsPerAccount, now),
        );
        if (wait > 0) {
            res.setHeader('Retry-After', Math.ceil(wait / 1000));
            return sendJson(res, 429, { ok: false, error: 'Too many failed attempts. Try again later.' });
        }

        const plausible = !validateUsername(username) && password.length <= MAX_PASSWORD_LENGTH;
        const account = plausible ? await store.getAccountByUsername(username) : null;
        const usable = Boolean(account) && !account.disabled;
        const passwordOk = await verifyPassword(password, usable ? account.password_hash : await getDummyHash());

        if (!usable || !passwordOk) {
            ipLimiter.fail(ip, now);
            accountLimiter.fail(accountKey, now);
            logger.warn(`Failed login for ${JSON.stringify(username.slice(0, 32))} from ${ip}`);
            return sendJson(res, 401, { ok: false, error: 'Invalid username or password.' });
        }

        accountLimiter.clear(accountKey);
        const token = crypto.randomBytes(32).toString('base64url');
        const maxAgeSec = Math.round(cfg.sessionDays * 86400);
        await store.createAuthSession(hashToken(token), account.user_id, now + maxAgeSec * 1000, ip, String(req.headers['user-agent'] || '').slice(0, 200));
        res.setHeader('Set-Cookie', buildCookie(cfg.cookieName, token, { maxAgeSec, secure: isHttps(req) }));
        logger.info(`Login: ${account.username} from ${ip}`);
        return sendJson(res, 200, { ok: true, username: account.username, userId: account.user_id });
    }

    async function handleLogout(req, res) {
        if (!originAllowed(req)) return sendJson(res, 403, { ok: false, error: 'Forbidden origin.' });
        const token = parseCookies(req.headers.cookie)[cfg.cookieName];
        if (token && token.length <= 128) {
            const tokenHash = hashToken(token);
            sessionCache.delete(tokenHash);
            await store.deleteAuthSession(tokenHash);
        }
        res.setHeader('Set-Cookie', buildCookie(cfg.cookieName, '', { maxAgeSec: 0, secure: isHttps(req) }));
        return sendJson(res, 200, { ok: true });
    }

    async function handleMe(req, res) {
        const account = await getSession(req);
        if (!account) return sendJson(res, 401, { ok: false });
        return sendJson(res, 200, { ok: true, username: account.username, userId: account.user_id });
    }

    //MARK: middleware
    // Plug into express with app.use(auth.middleware), before express.static.
    async function middleware(req, res, next) {
        try {
            if (!cfg.requireLogin) return next();

            const pathname = new URL(req.url, 'http://localhost').pathname;

            if (pathname.startsWith('/auth/')) {
                if (pathname === '/auth/login' && req.method === 'POST') return await handleLogin(req, res);
                if (pathname === '/auth/logout' && req.method === 'POST') return await handleLogout(req, res);
                if (pathname === '/auth/me' && req.method === 'GET') return await handleMe(req, res);
                return sendJson(res, 404, { ok: false, error: 'Not found.' });
            }

            if (PUBLIC_PATHS.has(pathname)) return next();

            const account = await getSession(req);
            if (account) {
                req.stmpAccount = account;
                return next();
            }

            const wantsPage = (req.method === 'GET' || req.method === 'HEAD') && String(req.headers.accept || '').includes('text/html');
            if (wantsPage) {
                res.writeHead(302, { Location: '/login.html', 'Cache-Control': 'no-store' });
                return res.end();
            }
            return sendJson(res, 401, { ok: false, error: 'Login required.' });
        } catch (err) {
            logger.error('Auth middleware error:', err);
            if (!res.headersSent) sendJson(res, 500, { ok: false, error: 'Server error.' });
            else res.end();
        }
    }

    // Use as the `verifyClient` option of the Guest WebSocket server (the two-argument async form).
    // On success, request.stmpAccount holds the logged-in account for handleConnections().
    async function verifyWebSocket(info, cb) {
        try {
            if (!cfg.requireLogin) return cb(true);
            const req = info.req;
            if (!originAllowed(req)) return cb(false, 403, 'Forbidden');
            const account = await getSession(req);
            if (!account) return cb(false, 401, 'Unauthorized');
            req.stmpAccount = account;
            return cb(true);
        } catch (err) {
            logger.error('WebSocket auth error:', err);
            return cb(false, 500, 'Server error');
        }
    }

    function startMaintenance() {
        const purge = () => store.purgeExpiredAuthSessions(Date.now()).catch((err) => logger.warn('Could not purge expired sessions:', err?.message));
        purge();
        const timer = setInterval(() => {
            purge();
            ipLimiter.sweep();
            accountLimiter.sweep();
        }, 60 * 60 * 1000);
        timer.unref();
    }

    return { config: cfg, middleware, verifyWebSocket, getClientIP, startMaintenance };
}

export default createAuth;
