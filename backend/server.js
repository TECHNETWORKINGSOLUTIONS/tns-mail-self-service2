import express from 'express';
import cors from 'cors';
import axios from 'axios';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import dns from 'dns/promises';
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Rate limit login/signup
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { ok: false, error: 'Too many attempts, slow down' }
});
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);

const {
  MAILCOW_URL,
  MAILCOW_API_KEY,
  JWT_SECRET,
  DB_FILE
} = process.env;

if (!MAILCOW_URL || !MAILCOW_API_KEY || !JWT_SECRET || !DB_FILE) {
  console.error('Missing required environment variables');
  process.exit(1);
}

const api = axios.create({
  baseURL: `${MAILCOW_URL}/api/v1`,
  headers: { 'X-API-Key': MAILCOW_API_KEY }
});

// --- DB setup ---
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    suspended INTEGER NOT NULL DEFAULT 0,
    verify_token TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    address TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// --- Helpers ---
function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, error: 'Missing token' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ ok: false, error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  const row = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.user.id);
  if (!row || row.is_admin !== 1) {
    return res.status(403).json({ ok: false, error: 'Admin only' });
  }
  next();
}

function randomToken(len = 32) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out = '';
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

// --- Auth routes ---
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email and password required' });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const stmt = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)');
    const info = stmt.run(email, hash);
    const user = { id: info.lastInsertRowid, email };
    const token = createToken(user);
    res.json({ ok: true, token, user });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(400).json({ ok: false, error: 'Email already in use' });
    }
    res.status(500).json({ ok: false, error: 'Internal error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email and password required' });
  }

  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!row) return res.status(400).json({ ok: false, error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, row.password_hash);
  if (!match) return res.status(400).json({ ok: false, error: 'Invalid credentials' });

  const user = { id: row.id, email: row.email };
  const token = createToken(user);
  res.json({ ok: true, token, user });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT id, email, is_admin FROM users WHERE id = ?').get(req.user.id);
  res.json({ ok: true, user: row });
});

// --- Domain routes ---
app.get('/api/domains', authMiddleware, (req, res) => {
  const rows = db.prepare(
    'SELECT id, domain, verified, suspended, verify_token, created_at FROM domains WHERE user_id = ?'
  ).all(req.user.id);
  res.json({ ok: true, domains: rows });
});

app.post('/api/domains', authMiddleware, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) {
    return res.status(400).json({ ok: false, error: 'Domain is required' });
  }

  const verifyToken = randomToken(24);

  try {
    await api.post('/add/domain', { domain, active: true });

    const dkim = await api.post('/add/dkim', {
      domain,
      selector: 'dkim',
      length: 2048
    });

    db.prepare(
      'INSERT INTO domains (user_id, domain, verify_token) VALUES (?, ?, ?)'
    ).run(req.user.id, domain, verifyToken);

    res.json({
      ok: true,
      message: 'Domain provisioned. Add DNS records and verify.',
      dkim: dkim.data,
      verify: {
        type: 'TXT',
        name: `_tns-verify.${domain}`,
        value: verifyToken
      }
    });
  } catch (err) {
    res.status(400).json({
      ok: false,
      error: err.response?.data || err.message
    });
  }
});

// Manual verification
app.post('/api/domains/verify', authMiddleware, (req, res) => {
  const { domain, token } = req.body || {};
  if (!domain || !token) {
    return res.status(400).json({ ok: false, error: 'Domain and token required' });
  }

  const row = db.prepare(
    'SELECT * FROM domains WHERE user_id = ? AND domain = ?'
  ).get(req.user.id, domain);

  if (!row) {
    return res.status(404).json({ ok: false, error: 'Domain not found' });
  }

  if (row.verify_token !== token) {
    return res.status(400).json({ ok: false, error: 'Invalid verification token' });
  }

  db.prepare(
    'UPDATE domains SET verified = 1 WHERE id = ?'
  ).run(row.id);

  res.json({ ok: true, message: 'Domain marked as verified' });
});

// Automatic DNS verification
app.get('/api/domains/check-dns', authMiddleware, async (req, res) => {
  const { domain } = req.query;

  if (!domain)
    return res.status(400).json({ ok: false, error: 'Domain required' });

  const row = db.prepare(
    'SELECT * FROM domains WHERE domain = ? AND user_id = ?'
  ).get(domain, req.user.id);

  if (!row) return res.status(404).json({ ok: false, error: 'Domain not found' });

  try {
    const records = await dns.resolveTxt(`_tns-verify.${domain}`);
    const flat = records.flat().join('');

    if (flat.trim() === row.verify_token.trim()) {
      db.prepare('UPDATE domains SET verified = 1 WHERE id = ?').run(row.id);
      return res.json({ ok: true, message: 'Domain automatically verified' });
    }

    res.json({ ok: false, message: 'Token mismatch', found: flat });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'DNS lookup failed' });
  }
});

// --- Mailbox routes ---
app.get('/api/mailboxes', authMiddleware, (req, res) => {
  const rows = db.prepare(
    'SELECT id, domain, address, created_at FROM mailboxes WHERE user_id = ?'
  ).all(req.user.id);
  res.json({ ok: true, mailboxes: rows });
});

app.post('/api/mailboxes', authMiddleware, async (req, res) => {
  const { domain, local_part, password, quota } = req.body || {};
  if (!domain || !local_part || !password) {
    return res.status(400).json({ ok: false, error: 'Domain, local_part, and password required' });
  }

  const fullAddress = `${local_part}@${domain}`;
  const mbQuota = Number.isFinite(Number(quota)) ? Number(quota) : 1024;

  try {
    await api.post('/add/mailbox', {
      active: 1,
      domain: domain,
      local_part: local_part,
      password: password,
      password2: password,
      quota: mbQuota,
      force_pw_update: false
    });

    db.prepare(
      'INSERT INTO mailboxes (user_id, domain, address) VALUES (?, ?, ?)'
    ).run(req.user.id, domain, fullAddress);

    res.json({
      ok: true,
      message: 'Mailbox created',
      mailbox: fullAddress
    });
  } catch (err) {
    res.status(400).json({
      ok: false,
      error: err.response?.data || err.message
    });
  }
});

// Delete mailbox
app.delete('/api/mailboxes/:id', authMiddleware, async (req, res) => {
  const mb = db.prepare(
    'SELECT * FROM mailboxes WHERE id = ? AND user_id = ?'
  ).get(req.params.id, req.user.id);

  if (!mb) return res.status(404).json({ ok: false, error: 'Mailbox not found' });

  try {
    await api.post('/delete/mailbox', { mailbox: [mb.address] });

    db.prepare('DELETE FROM mailboxes WHERE id = ?').run(req.params.id);

    res.json({ ok: true, message: 'Mailbox deleted' });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.response?.data || err.message });
  }
});

// Reset mailbox password
app.post('/api/mailboxes/reset', authMiddleware, async (req, res) => {
  const { address, new_password } = req.body;

  if (!address || !new_password)
    return res.status(400).json({ ok: false, error: 'Missing fields' });

  const mb = db.prepare(
    'SELECT * FROM mailboxes WHERE address = ? AND user_id = ?'
  ).get(address, req.user.id);

  if (!mb) return res.status(404).json({ ok: false, error: 'Mailbox not found' });

  try {
    await api.post('/edit/mailbox', {
      mailbox: address,
      attr: {
        password: new_password,
        password2: new_password
      }
    });

    res.json({ ok: true, message: 'Password reset' });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.response?.data || err.message });
  }
});

// --- Admin routes ---
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const rows = db.prepare('SELECT id, email, is_admin, created_at FROM users').all();
  res.json({ ok: true, users: rows });
});

app.get('/api/admin/domains', authMiddleware, adminMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM domains').all();
  res.json({ ok: true, domains: rows });
});

app.post('/api/admin/domains/suspend', authMiddleware, adminMiddleware, async (req, res) => {
  const { domain } = req.body;

  if (!domain)
    return res.status(400).json({ ok: false, error: 'Domain required' });

  db.prepare('UPDATE domains SET suspended = 1 WHERE domain = ?').run(domain);

  try {
    await api.post('/edit/domain', {
      domain,
      attr: { active: false }
    });
  } catch {}

  res.json({ ok: true, message: 'Domain suspended' });
});

app.post('/api/admin/users/promote', authMiddleware, adminMiddleware, (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ ok: false, error: 'Email required' });

  db.prepare('UPDATE users SET is_admin = 1 WHERE email = ?').run(email);

  res.json({ ok: true, message: 'User promoted' });
});

// --- Start server ---
app.listen(3000, () => console.log('Backend running on port 3000'));
