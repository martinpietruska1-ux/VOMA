const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const ASSETS_DIR = path.join(ROOT, 'assets');
const DATA_DIR = path.join(ROOT, 'data');
let DB_PATH;
let PORT;

function loadEnv() {
    const envPath = path.join(ROOT, '.env');
    if (!fs.existsSync(envPath)) return;
    for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
        const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
        if (match && process.env[match[1]] === undefined) {
            process.env[match[1]] = match[2].replace(/^(["'])(.*)\1$/, '$2');
        }
    }
}
loadEnv();

DB_PATH = process.env.BHP_DATABASE_PATH || path.join(DATA_DIR, 'accounts.sqlite');
PORT = Number(process.env.PORT || 3000);

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
`);

const mimeTypes = {
    '.css': 'text/css; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.ttf': 'font/ttf',
    '.woff2': 'font/woff2',
};

function escapeHtml(value = '') {
    return String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[char]);
}

function send(res, status, body, type = 'text/html; charset=utf-8') {
    res.writeHead(status, {
        'Content-Type': type,
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'same-origin',
        'Content-Security-Policy': "default-src 'self'; img-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    });
    res.end(body);
}

function renderPage(file, { error = '', notice = '', values = {} } = {}) {
    let html = fs.readFileSync(path.join(PUBLIC_DIR, file), 'utf8');
    html = html.replaceAll('{{ERROR}}', escapeHtml(error));
    html = html.replaceAll('{{NOTICE}}', escapeHtml(notice));
    html = html.replaceAll('{{USERNAME}}', escapeHtml(values.username || ''));
    html = html.replaceAll('{{EMAIL}}', escapeHtml(values.email || ''));
    html = html.replaceAll('{{REGISTRATION_STATUS}}', process.env.BHP_REGISTRATION_CODE
        ? '<p class="text-sm text-[#52605a]">Kod organizatora jest skonfigurowany.</p>'
        : '<p class="text-sm text-[#9a3412]">Administrator musi najpierw ustawić kod organizatora w pliku .env.</p>');
    return html;
}

function readForm(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk;
            if (body.length > 16_384) {
                reject(new Error('Formularz jest zbyt duży.'));
                req.destroy();
            }
        });
        req.on('end', () => resolve(new URLSearchParams(body)));
        req.on('error', reject);
    });
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = crypto.scryptSync(password, salt, 64);
    return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
    const [saltHex, hashHex] = String(stored).split(':');
    if (!saltHex || !hashHex) return false;
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function serveStatic(pathname, res) {
    let baseDir;
    let relativePath;
    if (pathname.startsWith('/assets/')) {
        baseDir = ASSETS_DIR;
        relativePath = pathname.slice('/assets/'.length);
    } else {
        baseDir = PUBLIC_DIR;
        relativePath = pathname.replace(/^\//, '');
    }
    const target = path.resolve(baseDir, relativePath);
    if (!target.startsWith(`${path.resolve(baseDir)}${path.sep}`)) {
        return send(res, 403, 'Forbidden', 'text/plain; charset=utf-8');
    }
    if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
        return send(res, 404, 'Nie znaleziono pliku.', 'text/plain; charset=utf-8');
    }
    send(res, 200, fs.readFileSync(target), mimeTypes[path.extname(target)] || 'application/octet-stream');
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const route = url.pathname;

    if (req.method === 'GET') {
        if (route === '/' || route === '/student.html') {
            return send(res, 200, renderPage('student.html', {
                error: url.searchParams.get('error') || '',
                notice: url.searchParams.get('notice') || '',
            }));
        }
        if (route === '/register.html') {
            return send(res, 200, renderPage('register.html', {
                error: url.searchParams.get('error') || '',
                notice: url.searchParams.get('notice') || '',
            }));
        }
        return serveStatic(route, res);
    }

    if (req.method !== 'POST') {
        res.setHeader('Allow', 'GET, POST');
        return send(res, 405, 'Niedozwolona metoda.', 'text/plain; charset=utf-8');
    }

    let form;
    try {
        form = await readForm(req);
    } catch {
        return send(res, 413, renderPage('register.html', { error: 'Formularz jest zbyt duży.' }));
    }

    if (route === '/register') {
        const username = (form.get('username') || '').trim();
        const email = (form.get('email') || '').trim().toLowerCase();
        const password = form.get('password') || '';
        const confirmation = form.get('password_confirmation') || '';
        const code = form.get('registration_code') || '';
        const values = { username, email };
        let error = '';

        if (!process.env.BHP_REGISTRATION_CODE) error = 'Rejestracja jest chwilowo niedostępna. Administrator musi ustawić kod organizatora.';
        else if (code !== process.env.BHP_REGISTRATION_CODE) error = 'Kod organizatora jest nieprawidłowy.';
        else if (!/^[\p{L}\p{N}_.-]{3,32}$/u.test(username)) error = 'Login musi mieć 3–32 znaki (litery, cyfry, kropka, myślnik lub podkreślenie).';
        else if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) error = 'Podaj poprawny adres e-mail.';
        else if (password.length < 10 || password.length > 128) error = 'Hasło musi mieć od 10 do 128 znaków.';
        else if (password !== confirmation) error = 'Hasła nie są takie same.';

        if (error) return send(res, 400, renderPage('register.html', { error, values }));
        try {
            db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)')
                .run(username, email, hashPassword(password));
            return send(res, 201, renderPage('student.html', {
                notice: 'Konto utworzono. Możesz teraz sprawdzić dane logowania poniżej.',
            }));
        } catch (err) {
            if (String(err.message).includes('UNIQUE')) {
                return send(res, 409, renderPage('register.html', {
                    error: 'Ten login lub adres e-mail jest już zajęty.', values,
                }));
            }
            console.error(err);
            return send(res, 500, renderPage('register.html', { error: 'Nie udało się utworzyć konta.' }));
        }
    }

    if (route === '/login') {
        const authCode = Array.from({ length: 6 }, (_, i) => form.get(`auth_digit_${i + 1}`) || '').join('');
        if (!/^\d{6}$/.test(authCode) || authCode !== process.env.BHP_REGISTRATION_CODE) {
            return send(res, 401, renderPage('student.html', { error: 'Kod autoryzacyjny jest nieprawidłowy.' }));
        }
        const identifier = (form.get('identifier') || '').trim();
        const password = form.get('password') || '';
        const user = db.prepare('SELECT username, password_hash FROM users WHERE username = ? OR email = ?')
            .get(identifier, identifier);
        if (!user || !verifyPassword(password, user.password_hash)) {
            return send(res, 401, renderPage('student.html', { error: 'Nieprawidłowy login, e-mail lub hasło.' }));
        }
        return send(res, 200, renderPage('student.html', {
            notice: `Dane logowania dla ${user.username} są poprawne. Sesja nie została utworzona.`,
        }));
    }

    return send(res, 404, 'Nie znaleziono endpointu.', 'text/plain; charset=utf-8');
});

server.listen(PORT, () => {
    console.log(`Serwer działa: http://localhost:${PORT}`);
});









