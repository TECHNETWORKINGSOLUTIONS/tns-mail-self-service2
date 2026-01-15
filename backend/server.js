import express from 'express';
import cors from 'cors';
import axios from 'axios';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

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

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
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
    console.error(err);
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
  res.json({ ok: true, user: req.user });
});

// --- Domain routes ---
app.get('/api/domains', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT id, domain, created_at FROM domains WHERE user_id = ?')
    .all(req.user.id);
  res.json({ ok: true, domains: rows });
});

app.post('/api/domains', authMiddleware, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) {
    return res.status(400).json({ ok: false, error: 'Domain is required' });
  }

  try {
    // Provision in Mailcow
    await api.post('/add/domain', { domain, active: true });
    const dkim = await api.post('/add/dkim', { domain, selector: 'dkim', length: 2048 });

    // Store in DB
    db.prepare('INSERT INTO domains (user_id, domain) VALUES (?, ?)')
      .run(req.user.id, domain);

    res.json({
      ok: true,
      message: 'Domain provisioned. Add DNS records.',
      dkim: dkim.data
    });
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(400).json({
      ok: false,
      error: err.response?.data || err.message
    });
  }
});

// (Optional) keep your original /api/provision for internal use if you want
// or remove it to force auth-only usage.

app.listen(3000, () => console.log('Backend running on port 3000'));
