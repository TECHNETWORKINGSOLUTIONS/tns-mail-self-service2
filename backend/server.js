import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import sqlite3 from 'better-sqlite3';
import Stripe from 'stripe';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3(process.env.DB_FILE);
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Ensure tables exist
db.prepare(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT,
  is_admin INTEGER DEFAULT 0,
  plan TEXT DEFAULT 'free'
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT,
  user_id INTEGER,
  verified INTEGER DEFAULT 0,
  suspended INTEGER DEFAULT 0,
  verify_token TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT,
  local_part TEXT,
  password TEXT,
  quota INTEGER DEFAULT 1024,
  user_id INTEGER
)`).run();

// JWT helpers
function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email, plan: user.plan }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });

  const token = auth.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// --- User APIs ---

app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  try {
    const stmt = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)');
    const info = stmt.run(email, hashed);
    const user = db.prepare('SELECT id,email,plan FROM users WHERE id=?').get(info.lastInsertRowid);
    res.json({ token: generateToken(user), user });
  } catch (err) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!user) return res.status(400).json({ error: 'Invalid email or password' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid email or password' });

  res.json({ token: generateToken(user), user: { id: user.id, email: user.email, plan: user.plan } });
});

app.get('/api/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT id,email,plan,is_admin FROM users WHERE id=?').get(req.user.id);
  res.json({ user });
});

// --- SaaS: Plan enforcement ---
function checkPlanLimit(userId, type) {
  const user = db.prepare('SELECT plan FROM users WHERE id=?').get(userId);
  const limits = { free: { domains: 2, mailboxes: 5 }, pro: { domains: 10, mailboxes: 50 } };
  const userLimits = limits[user.plan] || limits.free;

  if (type === 'domain') {
    const count = db.prepare('SELECT COUNT(*) AS cnt FROM domains WHERE user_id=?').get(userId).cnt;
    return count < userLimits.domains;
  }
  if (type === 'mailbox') {
    const count = db.prepare('SELECT COUNT(*) AS cnt FROM mailboxes WHERE user_id=?').get(userId).cnt;
    return count < userLimits.mailboxes;
  }
  return false;
}

// --- Domain APIs ---
app.get('/api/domains', authenticate, (req, res) => {
  const domains = db.prepare('SELECT * FROM domains WHERE user_id=?').all(req.user.id);
  res.json({ domains });
});

app.post('/api/domains', authenticate, (req, res) => {
  if (!checkPlanLimit(req.user.id, 'domain')) return res.status(403).json({ error: 'Domain limit reached' });

  const { domain } = req.body;
  const verify_token = Math.random().toString(36).substring(2,10);
  db.prepare('INSERT INTO domains (domain,user_id,verify_token) VALUES (?,?,?)').run(domain, req.user.id, verify_token);
  res.json({ message: 'Domain added', verify_token });
});

// --- Mailbox APIs ---
app.get('/api/mailboxes', authenticate, (req, res) => {
  const mailboxes = db.prepare('SELECT * FROM mailboxes WHERE user_id=?').all(req.user.id);
  res.json({ mailboxes });
});

app.post('/api/mailboxes', authenticate, async (req, res) => {
  if (!checkPlanLimit(req.user.id, 'mailbox')) return res.status(403).json({ error: 'Mailbox limit reached' });

  const { domain, local_part, password, quota } = req.body;
  db.prepare('INSERT INTO mailboxes (domain,local_part,password,quota,user_id) VALUES (?,?,?,?,?)')
    .run(domain, local_part, password, quota || 1024, req.user.id);
  res.json({ message: 'Mailbox created' });
});

// --- Stripe integration: create checkout session ---
app.post('/api/checkout', authenticate, async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{ price: 'price_your_stripe_price_id', quantity: 1 }],
    mode: 'subscription',
    success_url: 'https://mail.tnsicn.org?success=true',
    cancel_url: 'https://mail.tnsicn.org?canceled=true',
    customer_email: req.user.email
  });
  res.json({ url: session.url });
});

// --- Start server ---
app.listen(3000, () => console.log('Backend running on port 3000'));
