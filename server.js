const express = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3333;
const DB   = path.join(__dirname, 'data', 'users.json');

// ── Secret key (auto-generated once, persisted) ──────────────────────────
const SECRET_FILE = path.join(__dirname, 'data', '.secret');
let JWT_SECRET;
if (fs.existsSync(SECRET_FILE)) {
  JWT_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
} else {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  fs.mkdirSync(path.dirname(SECRET_FILE), { recursive: true });
  fs.writeFileSync(SECRET_FILE, JWT_SECRET);
}

// ── Simple JSON database ──────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB)) return { users: [] };
  try { return JSON.parse(fs.readFileSync(DB, 'utf8')); } catch { return { users: [] }; }
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DB), { recursive: true });
  fs.writeFileSync(DB, JSON.stringify(db, null, 2));
}
function nextId(arr) { return arr.length ? Math.max(...arr.map(x => x.id)) + 1 : 1; }

// ── Middleware ────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ───────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── Validation ────────────────────────────────────────────────────────────
function isValidEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }
function isValidUsername(u) { return /^[a-zA-Z0-9_]{3,20}$/.test(u); }

// ── API Routes ────────────────────────────────────────────────────────────

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password)
    return res.status(400).json({ error: 'Email, username and password are required' });
  if (!isValidEmail(email))
    return res.status(400).json({ error: 'Invalid email address' });
  if (!isValidUsername(username))
    return res.status(400).json({ error: 'Username must be 3–20 chars, letters/numbers/underscore only' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const db = loadDB();
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: 'Email already in use' });
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({ error: 'Username already taken' });

  const hash = await bcrypt.hash(password, 12);
  const user = {
    id: nextId(db.users),
    email: email.toLowerCase().trim(),
    username: username.trim(),
    passwordHash: hash,
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  saveDB(db);

  const token = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.status(201).json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

  const db = loadDB();
  const user = db.users.find(u => u.email === email.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

// GET /api/me
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.userId, username: req.user.username, email: req.user.email } });
});

// DELETE /api/account  (delete own account)
app.delete('/api/account', requireAuth, (req, res) => {
  const db = loadDB();
  db.users = db.users.filter(u => u.id !== req.user.userId);
  saveDB(db);
  res.json({ ok: true });
});

// ── SPA fallback ──────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🎵 Pulsewave server running on http://localhost:${PORT}`);
  console.log(`   API: http://localhost:${PORT}/api`);
});
