// SQLite storage for logins (accounts) and login sessions.
//
// It opens its own connection to stmp.db instead of going through db.js, because db.js pulls in server.js:
// that would make the user-management script (manage-users.js) start the whole server.
// SQLite is in WAL mode, so two connections can safely share the file.

import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { fileURLToPath } from 'url';

const DB_FILE = fileURLToPath(new URL('../stmp.db', import.meta.url));

let dbPromise = null;

function getDb() {
    dbPromise ??= open({ filename: DB_FILE, driver: sqlite3.Database }).then(async (db) => {
        await db.exec(`
            PRAGMA busy_timeout = 5000;
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS accounts (
                user_id TEXT UNIQUE PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                disabled BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT UNIQUE PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at INTEGER NOT NULL,
                ip TEXT,
                user_agent TEXT
            );
        `);
        return db;
    });
    return dbPromise;
}

export async function closeAuthStore() {
    if (!dbPromise) return;
    const db = await dbPromise;
    dbPromise = null;
    await db.close();
}

//MARK: Accounts
export async function getAccountByUsername(username) {
    const db = await getDb();
    return (await db.get('SELECT user_id, username, password_hash, disabled FROM accounts WHERE username = ?', [username])) || null;
}

export async function getAccountByUserId(userId) {
    const db = await getDb();
    return (await db.get('SELECT user_id, username, disabled FROM accounts WHERE user_id = ?', [userId])) || null;
}

export async function listAccounts() {
    const db = await getDb();
    return db.all('SELECT user_id, username, disabled, created_at FROM accounts ORDER BY username');
}

export async function countAccounts() {
    const db = await getDb();
    const row = await db.get('SELECT COUNT(*) AS count FROM accounts WHERE disabled = 0');
    return row?.count ?? 0;
}

export async function createAccount(userId, username, passwordHash) {
    const db = await getDb();
    await db.run('INSERT INTO accounts (user_id, username, password_hash) VALUES (?, ?, ?)', [userId, username, passwordHash]);
}

// Changing the password logs the account out everywhere.
export async function setAccountPassword(username, passwordHash) {
    const db = await getDb();
    const account = await getAccountByUsername(username);
    if (!account) return false;
    await db.run('UPDATE accounts SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP WHERE user_id = ?', [passwordHash, account.user_id]);
    await deleteAuthSessionsForUser(account.user_id);
    return true;
}

export async function setAccountDisabled(username, disabled) {
    const db = await getDb();
    const account = await getAccountByUsername(username);
    if (!account) return false;
    await db.run('UPDATE accounts SET disabled = ? WHERE user_id = ?', [disabled ? 1 : 0, account.user_id]);
    if (disabled) await deleteAuthSessionsForUser(account.user_id);
    return true;
}

export async function deleteAccount(username) {
    const db = await getDb();
    const account = await getAccountByUsername(username);
    if (!account) return false;
    await deleteAuthSessionsForUser(account.user_id);
    await db.run('DELETE FROM accounts WHERE user_id = ?', [account.user_id]);
    return true;
}

//MARK: Sessions
export async function createAuthSession(tokenHash, userId, expiresAtMs, ip, userAgent) {
    const db = await getDb();
    await db.run('INSERT INTO auth_sessions (token_hash, user_id, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?)', [tokenHash, userId, expiresAtMs, ip, userAgent]);
}

export async function getAuthSession(tokenHash) {
    const db = await getDb();
    return (await db.get(
        `SELECT s.user_id, s.expires_at, a.username, a.disabled
         FROM auth_sessions s JOIN accounts a ON a.user_id = s.user_id
         WHERE s.token_hash = ?`,
        [tokenHash],
    )) || null;
}

export async function deleteAuthSession(tokenHash) {
    const db = await getDb();
    await db.run('DELETE FROM auth_sessions WHERE token_hash = ?', [tokenHash]);
}

export async function deleteAuthSessionsForUser(userId) {
    const db = await getDb();
    await db.run('DELETE FROM auth_sessions WHERE user_id = ?', [userId]);
}

export async function purgeExpiredAuthSessions(nowMs) {
    const db = await getDb();
    await db.run('DELETE FROM auth_sessions WHERE expires_at <= ?', [nowMs]);
}

export default {
    getAccountByUsername,
    getAccountByUserId,
    listAccounts,
    countAccounts,
    createAccount,
    setAccountPassword,
    setAccountDisabled,
    deleteAccount,
    createAuthSession,
    getAuthSession,
    deleteAuthSession,
    deleteAuthSessionsForUser,
    purgeExpiredAuthSessions,
    closeAuthStore,
};
