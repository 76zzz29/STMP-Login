// Manage the logins used by the Guest server.
//
//   node manage-users.js add <username> [--uuid <existing-user-id>]
//   node manage-users.js passwd <username>
//   node manage-users.js list
//   node manage-users.js disable <username>
//   node manage-users.js enable <username>
//   node manage-users.js remove <username> [--yes]
//
// Run it from the STMP folder. The server does not need to be stopped.

import crypto from 'crypto';
import readline from 'readline';
import store from './src/auth-store.js';
import { hashPassword, validateUsername, validatePassword, MIN_PASSWORD_LENGTH } from './src/auth.js';

const USAGE = `Usage:
  node manage-users.js add <username> [--uuid <existing-user-id>]
  node manage-users.js passwd <username>
  node manage-users.js list
  node manage-users.js disable <username>
  node manage-users.js enable <username>
  node manage-users.js remove <username> [--yes]

Usernames: 3-12 characters (A-Z, a-z, 0-9, _ or -), at least 3 letters.
Passwords: at least ${MIN_PASSWORD_LENGTH} characters.
--uuid links the login to an existing STMP user (keeps their chat history and role).`;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

class UserError extends Error { }

// Reads a password without echoing it. When stdin is piped, reads the first line.
function readPassword(prompt) {
    return new Promise((resolve) => {
        if (!process.stdin.isTTY) {
            const rl = readline.createInterface({ input: process.stdin });
            let answered = false;
            rl.once('line', (line) => { answered = true; rl.close(); resolve(line); });
            rl.once('close', () => { if (!answered) resolve(''); });
            return;
        }
        process.stdout.write(prompt);
        process.stdin.setRawMode(true);
        process.stdin.setEncoding('utf8');
        process.stdin.resume();
        let value = '';
        const finish = () => {
            process.stdin.setRawMode(false);
            process.stdin.pause();
            process.stdin.off('data', onData);
            process.stdout.write('\n');
        };
        const onData = (chunk) => {
            for (const ch of chunk) {
                if (ch === '\r' || ch === '\n') { finish(); return resolve(value); }
                if (ch === '\u0003') { finish(); process.exit(130); }
                if (ch === '\u007f' || ch === '\b') { value = value.slice(0, -1); continue; }
                if (ch >= ' ') value += ch;
            }
        };
        process.stdin.on('data', onData);
    });
}

async function askNewPassword() {
    const password = await readPassword('Password: ');
    const problem = validatePassword(password);
    if (problem) throw new UserError(problem);
    if (process.stdin.isTTY) {
        const again = await readPassword('Repeat password: ');
        if (again !== password) throw new UserError('The two passwords do not match.');
    }
    return password;
}

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => rl.question(question, (answer) => { rl.close(); resolve(answer.trim()); }));
}

async function requireAccount(username) {
    const account = username ? await store.getAccountByUsername(username) : null;
    if (!account) throw new UserError(`No account named "${username ?? ''}".`);
    return account;
}

const commands = {
    async add(username, options) {
        const nameProblem = validateUsername(username);
        if (nameProblem) throw new UserError(nameProblem);
        if (await store.getAccountByUsername(username)) throw new UserError(`The account "${username}" already exists.`);

        let userId = crypto.randomUUID();
        if (options.uuid !== undefined) {
            if (!UUID_PATTERN.test(options.uuid)) throw new UserError('--uuid must look like xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.');
            if (await store.getAccountByUserId(options.uuid)) throw new UserError('That user id already has a login.');
            userId = options.uuid.toLowerCase();
        }

        const password = await askNewPassword();
        await store.createAccount(userId, username, await hashPassword(password));
        console.log(`Account "${username}" created.`);
    },

    async passwd(username) {
        const account = await requireAccount(username);
        const password = await askNewPassword();
        await store.setAccountPassword(account.username, await hashPassword(password));
        console.log(`Password changed for "${account.username}". They are logged out everywhere (within about 30 seconds on a running server).`);
    },

    async list() {
        const accounts = await store.listAccounts();
        if (accounts.length === 0) {
            console.log('No accounts yet. Create one with: node manage-users.js add <username>');
            return;
        }
        for (const a of accounts) {
            console.log(`${a.username.padEnd(14)} ${a.disabled ? 'disabled' : 'active  '}  ${a.user_id}  created ${a.created_at}`);
        }
    },

    async disable(username) {
        const account = await requireAccount(username);
        await store.setAccountDisabled(account.username, true);
        console.log(`"${account.username}" disabled and logged out (within about 30 seconds on a running server). Connections already open stay open until the user disconnects.`);
    },

    async enable(username) {
        const account = await requireAccount(username);
        await store.setAccountDisabled(account.username, false);
        console.log(`"${account.username}" enabled.`);
    },

    async remove(username, options) {
        const account = await requireAccount(username);
        if (!options.yes) {
            const answer = await ask(`Type "${account.username}" to delete this login (chat history is kept): `);
            if (answer.toLowerCase() !== account.username.toLowerCase()) throw new UserError('Cancelled.');
        }
        await store.deleteAccount(account.username);
        console.log(`Account "${account.username}" removed.`);
    },
};

function parseArgs(argv) {
    const [command, ...rest] = argv;
    const positional = [];
    const options = {};
    for (let i = 0; i < rest.length; i++) {
        if (rest[i] === '--uuid') options.uuid = rest[++i];
        else if (rest[i] === '--yes') options.yes = true;
        else positional.push(rest[i]);
    }
    return { command, username: positional[0], options };
}

async function main() {
    const { command, username, options } = parseArgs(process.argv.slice(2));
    if (!command || !Object.hasOwn(commands, command)) {
        console.log(USAGE);
        return command ? 1 : 0;
    }
    try {
        await commands[command](username, options);
        return 0;
    } catch (err) {
        console.error(err instanceof UserError ? `Error: ${err.message}` : err);
        return 1;
    }
}

const code = await main();
await store.closeAuthStore();
process.exit(code);
