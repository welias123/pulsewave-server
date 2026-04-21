require('dotenv').config();
const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
const nodemailer = require('nodemailer');

// ── E-Mail Transporter ────────────────────────────────────────────────────────
let mailer = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  mailer = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });
  mailer.verify().then(() => console.log('📧 E-Mail bereit')).catch(() => console.log('⚠️  E-Mail-Fehler — Zugangsdaten prüfen'));
} else {
  console.log('⚠️  E-Mail deaktiviert (EMAIL_USER + EMAIL_PASS fehlen in .env)');
}

// ── Pending Verifications (in-memory, 10 min TTL) ─────────────────────────────
// key: email → { code, expiresAt, username, passwordHash }
const pendingVerifications = new Map();

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6-digit
}

async function sendVerificationEmail(email, username, code) {
  if (!mailer) {
    // Dev fallback: log the code to console
    console.log(`\n📧 [DEV] Verifizierungscode für ${email}: ${code}\n`);
    return;
  }
  await mailer.sendMail({
    from: `"Pulsewave" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Dein Pulsewave Verifizierungscode',
    html: `
      <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;background:#080808;color:#fff;padding:40px;border-radius:16px">
        <div style="text-align:center;margin-bottom:32px">
          <span style="font-size:40px">🎵</span>
          <h1 style="color:#FFD600;margin:12px 0 4px;font-size:24px">Pulsewave</h1>
          <p style="color:#555;font-size:13px;margin:0">Deine Musik, dein Weg.</p>
        </div>
        <h2 style="font-size:18px;margin-bottom:8px">Hallo ${username} 👋</h2>
        <p style="color:#999;font-size:14px;margin-bottom:28px">
          Gib diesen Code in der App ein, um deine E-Mail-Adresse zu bestätigen:
        </p>
        <div style="background:#1a1a00;border:2px solid #FFD600;border-radius:12px;text-align:center;padding:24px;margin-bottom:28px">
          <span style="font-size:42px;font-weight:900;letter-spacing:10px;color:#FFD600">${code}</span>
        </div>
        <p style="color:#555;font-size:12px;text-align:center">
          Der Code ist <strong style="color:#888">10 Minuten</strong> gültig.<br/>
          Falls du kein Konto erstellt hast, ignoriere diese E-Mail.
        </p>
      </div>`
  });
}

const app  = express();
const PORT = process.env.PORT || 3333;

// ── Config ─────────────────────────────────────────────────────────────────
const CLIENT_URL  = process.env.CLIENT_URL  || 'https://welias123.github.io/pulsewave-website';
const PRICE_USDC  = parseFloat(process.env.PRICE_USDC || '2');   // monthly price in USDC

// ── Crypto payment system (USDC on Polygon) ────────────────────────────────
// Each user gets a unique wallet address derived from the master HD wallet.
// Polygon network: fast, gas < $0.001, USDC is always worth $1.
const POLYGON_RPC    = 'https://polygon-rpc.com';
const USDC_CONTRACT  = '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174'; // USDC on Polygon
const USDC_DECIMALS  = 6;
const BILLING_DAYS   = 31; // premium lasts this many days per payment

let _hdWallet = null;
function getHDWallet() {
  if (_hdWallet) return _hdWallet;
  const phrase = process.env.CRYPTO_MNEMONIC;
  if (!phrase) { console.warn('⚠️  CRYPTO_MNEMONIC not set — crypto payments disabled'); return null; }
  const { ethers } = require('ethers');
  _hdWallet = ethers.HDNodeWallet.fromMnemonic(ethers.Mnemonic.fromPhrase(phrase));
  return _hdWallet;
}

// Derive a unique address for a user (by their numeric ID)
function getUserCryptoAddress(userId) {
  const hd = getHDWallet();
  if (!hd) return null;
  const { ethers } = require('ethers');
  const child = hd.derivePath(`m/44'/60'/0'/0/${userId}`);
  return child.address;
}

// Check USDC balance of an address on Polygon via public RPC
async function getUSDCBalance(address) {
  const https = require('https');
  // ERC-20 balanceOf call: selector 0x70a08231 + padded address
  const { ethers } = require('ethers');
  const data = '0x70a08231' + address.slice(2).toLowerCase().padStart(64, '0');
  const body = JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'eth_call',
    params: [{ to: USDC_CONTRACT, data }, 'latest']
  });
  return new Promise((resolve, reject) => {
    const url = new URL(POLYGON_RPC);
    const req = https.request({
      hostname: url.hostname, path: url.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const result = JSON.parse(d).result;
          if (!result || result === '0x') { resolve(0); return; }
          resolve(Number(BigInt(result)) / 10 ** USDC_DECIMALS);
        } catch { resolve(0); }
      });
    });
    req.on('error', () => resolve(0));
    req.write(body); req.end();
  });
}

// Sweep (forward) USDC from a user's derived address to the master wallet
// (optional — keeps earnings in one place; runs after payment detected)
async function sweepUSDC(userId) {
  try {
    const { ethers } = require('ethers');
    const hd       = getHDWallet();
    if (!hd) return;
    const child    = hd.derivePath(`m/44'/60'/0'/0/${userId}`);
    const provider = new ethers.JsonRpcProvider(POLYGON_RPC);
    const signer   = child.connect(provider);
    const balance  = await getUSDCBalance(child.address);
    if (balance < 0.01) return;
    // Transfer USDC to master wallet
    const usdc   = new ethers.Contract(USDC_CONTRACT,
      ['function transfer(address to, uint256 amount) returns (bool)'], signer);
    const amount = ethers.parseUnits(balance.toFixed(6), USDC_DECIMALS);
    const tx     = await usdc.transfer(hd.address, amount);
    await tx.wait();
    console.log(`💸 Swept ${balance} USDC from user ${userId} to master wallet`);
  } catch(e) {
    console.warn(`[sweep] User ${userId}: ${e.message}`);
  }
}

// Background payment checker — runs every 3 minutes
async function checkCryptoPayments() {
  try {
    const db    = loadDB();
    const users = db.users;
    for (const user of users) {
      const addr    = getUserCryptoAddress(user.id);
      if (!addr) break;
      const balance = await getUSDCBalance(addr);
      if (balance >= PRICE_USDC) {
        // Payment detected!
        const expiresAt = new Date(Date.now() + BILLING_DAYS * 24 * 3600 * 1000).toISOString();
        await updateUser(user.id, { is_premium: true, premium_expires_at: expiresAt });
        console.log(`✅ [Crypto] ${user.username} paid ${balance} USDC → Premium until ${expiresAt}`);
        // Sweep funds to master wallet (background)
        sweepUSDC(user.id).catch(() => {});
      }
    }
    // Also expire overdue premiums
    for (const user of users) {
      if (user.is_premium && user.premium_expires_at) {
        if (new Date(user.premium_expires_at) < new Date()) {
          await updateUser(user.id, { is_premium: false });
          console.log(`❌ [Crypto] Premium expired for ${user.username}`);
        }
      }
    }
  } catch(e) { console.warn('[checkCryptoPayments]', e.message); }
}

// ── Find user by PayPal subscription ID (legacy stub) ──────────────────────
async function findByPaypalSubscr(subscrId) { return null; }

// ── Admin password (auto-generated once, stored in data/.adminpw) ──────────
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || (() => {
  const f = path.join(__dirname, 'data', '.adminpw');
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim();
  const pw = 'PW-' + crypto.randomBytes(6).toString('hex').toUpperCase();
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, pw);
  return pw;
})();

// ── Activation Codes ────────────────────────────────────────────────────────
const CODES_FILE = path.join(__dirname, 'data', 'codes.json');
function loadCodes() {
  try { return JSON.parse(fs.readFileSync(CODES_FILE, 'utf8')); } catch { return []; }
}
function saveCodes(codes) {
  fs.mkdirSync(path.dirname(CODES_FILE), { recursive: true });
  fs.writeFileSync(CODES_FILE, JSON.stringify(codes, null, 2));
}
function makeActivationCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous I,O,0,1
  const grp   = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `PULSE-${grp()}-${grp()}-${grp()}`;
}
function requireAdmin(req, res, next) {
  const pw = req.headers['x-admin-password'] || req.body?.adminPassword;
  if (!pw || pw !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Falsches Admin-Passwort' });
  next();
}

// ── JWT Secret ────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  const f = path.join(__dirname, 'data', '.secret');
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim();
  const s = crypto.randomBytes(48).toString('hex');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, s);
  return s;
})();

// ── Database ──────────────────────────────────────────────────────────────
let pool = null;
if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id                   SERIAL PRIMARY KEY,
      email                TEXT UNIQUE NOT NULL,
      username             TEXT UNIQUE NOT NULL,
      password_hash        TEXT NOT NULL,
      is_premium           BOOLEAN DEFAULT FALSE,
      stripe_customer_id   TEXT,
      stripe_subscription_id TEXT,
      created_at           TIMESTAMPTZ DEFAULT NOW()
    )
  `).then(() => console.log('✅ PostgreSQL ready')).catch(console.error);
}

const DB_FILE = path.join(__dirname, 'data', 'users.json');
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { users: [] };
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return { users: [] }; }
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function nextId(arr) { return arr.length ? Math.max(...arr.map(x => x.id)) + 1 : 1; }

// ── DB helpers ────────────────────────────────────────────────────────────
async function findByEmail(email) {
  if (pool) { const r = await pool.query('SELECT * FROM users WHERE lower(email)=$1',[email.toLowerCase()]); return r.rows[0]||null; }
  return loadDB().users.find(u=>u.email.toLowerCase()===email.toLowerCase())||null;
}
async function findByUsername(username) {
  if (pool) { const r = await pool.query('SELECT * FROM users WHERE lower(username)=$1',[username.toLowerCase()]); return r.rows[0]||null; }
  return loadDB().users.find(u=>u.username.toLowerCase()===username.toLowerCase())||null;
}
async function findById(id) {
  if (pool) { const r = await pool.query('SELECT * FROM users WHERE id=$1',[id]); return r.rows[0]||null; }
  return loadDB().users.find(u=>u.id===id)||null;
}
async function findByStripeCustomer(customerId) { return null; } // legacy stub
async function insertUser(email, username, hash) {
  if (pool) {
    const r = await pool.query(
      'INSERT INTO users(email,username,password_hash) VALUES($1,$2,$3) RETURNING *',
      [email.toLowerCase().trim(), username.trim(), hash]
    );
    return r.rows[0];
  }
  const db = loadDB();
  const user = { id:nextId(db.users), email:email.toLowerCase().trim(), username:username.trim(), passwordHash:hash, password_hash:hash, is_premium:false, createdAt:new Date().toISOString() };
  db.users.push(user); saveDB(db); return user;
}
async function updateUser(id, fields) {
  if (pool) {
    const sets = Object.entries(fields).map(([k,_],i)=>`${k}=$${i+2}`).join(',');
    await pool.query(`UPDATE users SET ${sets} WHERE id=$1`,[id,...Object.values(fields)]);
    return;
  }
  const db = loadDB();
  const idx = db.users.findIndex(u=>u.id===id);
  if (idx>=0) { Object.assign(db.users[idx], fields); saveDB(db); }
}
async function deleteById(id) {
  if (pool) { await pool.query('DELETE FROM users WHERE id=$1',[id]); return; }
  const db = loadDB(); db.users = db.users.filter(u=>u.id!==id); saveDB(db);
}

// ── Middleware ────────────────────────────────────────────────────────────
app.use(cors({ origin:'*', credentials:true }));
app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));

// ── Auth middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error:'No token' });
  try { req.user = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error:'Invalid token' }); }
}

function isValidEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }
function isValidUsername(u) { return /^[a-zA-Z0-9_]{3,20}$/.test(u); }

function makeToken(user) {
  return jwt.sign(
    { userId:user.id, username:user.username, email:user.email, is_premium:user.is_premium||false },
    JWT_SECRET, { expiresIn:'30d' }
  );
}

// ── POST /api/register — Step 1: send verification code ──────────────────────
app.post('/api/register', async (req,res) => {
  const { email, username, password } = req.body;
  if (!email||!username||!password) return res.status(400).json({ error:'E-Mail, Benutzername und Passwort erforderlich' });
  if (!isValidEmail(email))          return res.status(400).json({ error:'Ungültige E-Mail-Adresse' });
  if (!isValidUsername(username))    return res.status(400).json({ error:'Benutzername: 3–20 Zeichen, nur Buchstaben/Zahlen/_' });
  if (password.length < 6)           return res.status(400).json({ error:'Passwort muss mindestens 6 Zeichen haben' });
  try {
    if (await findByEmail(email))       return res.status(409).json({ error:'E-Mail bereits registriert' });
    if (await findByUsername(username)) return res.status(409).json({ error:'Benutzername bereits vergeben' });

    const hash = await bcrypt.hash(password, 12);
    const code = generateCode();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    // Store pending registration
    pendingVerifications.set(email.toLowerCase(), { code, expiresAt, username, passwordHash: hash });

    // Send code via e-mail
    await sendVerificationEmail(email, username, code);

    res.status(200).json({ needsVerification: true, message: 'Verifizierungscode wurde an deine E-Mail gesendet.' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server-Fehler: ' + e.message }); }
});

// ── POST /api/verify-email — Step 2: confirm code + create account ────────────
app.post('/api/verify-email', async (req,res) => {
  const { email, code } = req.body;
  if (!email||!code) return res.status(400).json({ error:'E-Mail und Code erforderlich' });

  const pending = pendingVerifications.get(email.toLowerCase());
  if (!pending) return res.status(400).json({ error:'Kein ausstehender Code für diese E-Mail. Bitte erneut registrieren.' });
  if (Date.now() > pending.expiresAt) {
    pendingVerifications.delete(email.toLowerCase());
    return res.status(400).json({ error:'Code abgelaufen. Bitte erneut registrieren.' });
  }
  if (String(code).trim() !== String(pending.code)) {
    return res.status(400).json({ error:'Falscher Code. Bitte nochmals prüfen.' });
  }

  try {
    // Double-check no duplicate appeared while waiting
    if (await findByEmail(email))          return res.status(409).json({ error:'E-Mail bereits registriert' });
    if (await findByUsername(pending.username)) return res.status(409).json({ error:'Benutzername bereits vergeben' });

    const user = await insertUser(email, pending.username, pending.passwordHash);
    pendingVerifications.delete(email.toLowerCase());

    const token = makeToken(user);
    res.status(201).json({ token, user:{ id:user.id, username:user.username, email:user.email, is_premium:false } });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server-Fehler' }); }
});

// ── POST /api/resend-code ─────────────────────────────────────────────────────
app.post('/api/resend-code', async (req,res) => {
  const { email } = req.body;
  const pending = pendingVerifications.get(email?.toLowerCase());
  if (!pending) return res.status(400).json({ error:'Keine ausstehende Registrierung für diese E-Mail' });

  const code = generateCode();
  pending.code      = code;
  pending.expiresAt = Date.now() + 10 * 60 * 1000;
  try {
    await sendVerificationEmail(email, pending.username, code);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error:'E-Mail konnte nicht gesendet werden' }); }
});

// ── POST /api/login ────────────────────────────────────────────────────────
app.post('/api/login', async (req,res) => {
  const { email, password } = req.body;
  if (!email||!password) return res.status(400).json({ error:'E-Mail und Passwort erforderlich' });
  try {
    const user = await findByEmail(email);
    if (!user) return res.status(401).json({ error:'E-Mail oder Passwort falsch' });
    const ok = await bcrypt.compare(password, user.password_hash||user.passwordHash);
    if (!ok)   return res.status(401).json({ error:'E-Mail oder Passwort falsch' });
    const token = makeToken(user);
    res.json({ token, user:{ id:user.id, username:user.username, email:user.email, is_premium:user.is_premium||false } });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server-Fehler' }); }
});

// ── GET /api/me ────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, async (req,res) => {
  try {
    // Refresh premium status from DB on every /me call
    const user = await findById(req.user.userId);
    const isPremium = user?.is_premium || false;
    res.json({ user:{ id:req.user.userId, username:req.user.username, email:req.user.email, is_premium:isPremium } });
  } catch { res.json({ user:{ id:req.user.userId, username:req.user.username, email:req.user.email, is_premium:false } }); }
});

// ── GET /api/crypto-address — get user's unique payment address ───────────
app.get('/api/crypto-address', requireAuth, async (req, res) => {
  const address = getUserCryptoAddress(req.user.userId);
  if (!address) return res.status(503).json({ error: 'Crypto-Zahlungen nicht konfiguriert' });
  const user = await findById(req.user.userId);
  res.json({
    address,
    network: 'Polygon',
    token: 'USDC',
    amount: PRICE_USDC,
    is_premium: user?.is_premium || false,
    premium_expires_at: user?.premium_expires_at || null,
    instructions: `Schick exakt ${PRICE_USDC} USDC (Polygon-Netzwerk) an diese Adresse. Premium wird innerhalb von 3 Minuten aktiviert.`
  });
});

// ── GET /api/check-payment — manually trigger a payment check for this user
app.get('/api/check-payment', requireAuth, async (req, res) => {
  const address = getUserCryptoAddress(req.user.userId);
  if (!address) return res.status(503).json({ error: 'Crypto nicht konfiguriert' });
  const balance = await getUSDCBalance(address);
  if (balance >= PRICE_USDC) {
    const expiresAt = new Date(Date.now() + BILLING_DAYS * 24 * 3600 * 1000).toISOString();
    await updateUser(req.user.userId, { is_premium: true, premium_expires_at: expiresAt });
    sweepUSDC(req.user.userId).catch(() => {});
    return res.json({ ok: true, paid: true, balance, is_premium: true, premium_expires_at: expiresAt, message: '🎉 Zahlung erkannt! Premium ist jetzt aktiv.' });
  }
  res.json({ ok: true, paid: false, balance, needed: PRICE_USDC, message: `${balance.toFixed(2)} / ${PRICE_USDC} USDC erhalten — warte auf Zahlung…` });
});

// ── POST /api/redeem-code-app — Electron app code redemption (no JWT needed) ──
// The app uses local auth, so we just verify the code and mark it used.
// Premium status is then stored locally in the Electron app.
app.post('/api/redeem-code-app', async (req, res) => {
  const { code, username } = req.body;
  if (!code) return res.status(400).json({ error: 'Code fehlt' });

  const normalized = code.trim().toUpperCase().replace(/\s/g, '');
  const codes = loadCodes();
  const idx = codes.findIndex(c => c.code === normalized && !c.usedBy);

  if (idx === -1) {
    const already = codes.find(c => c.code === normalized);
    if (already) return res.status(409).json({ error: 'Dieser Code wurde bereits eingelöst' });
    return res.status(404).json({ error: 'Ungültiger Code — bitte prüfen' });
  }

  codes[idx].usedBy   = username || 'electron-app';
  codes[idx].usedAt   = new Date().toISOString();
  codes[idx].username = username || 'app-user';
  saveCodes(codes);

  console.log(`⭐ Electron user "${username}" activated Premium with code ${normalized}`);
  res.json({ ok: true, message: '🎉 Premium aktiviert!' });
});

// ── GET /api/payment-info — public: what does premium cost + how to pay ──────
app.get('/api/payment-info', (req, res) => {
  res.json({
    price: PRICE_USDC,
    currency: 'USDC',
    network: 'Polygon',
    cryptoEnabled: !!getHDWallet()
  });
});

// ── POST /api/redeem-code — user redeems an activation code ──────────────
app.post('/api/redeem-code', requireAuth, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code fehlt' });

  const normalized = code.trim().toUpperCase().replace(/\s/g, '');
  const codes = loadCodes();
  const idx = codes.findIndex(c => c.code === normalized && !c.usedBy);

  if (idx === -1) {
    const already = codes.find(c => c.code === normalized && c.usedBy);
    if (already) return res.status(409).json({ error: 'Dieser Code wurde bereits eingelöst' });
    return res.status(404).json({ error: 'Ungültiger Code — bitte prüfen' });
  }

  // Mark code as used
  codes[idx].usedBy   = req.user.userId;
  codes[idx].usedAt   = new Date().toISOString();
  codes[idx].username = req.user.username;
  saveCodes(codes);

  // Activate premium
  await updateUser(req.user.userId, { is_premium: true });
  console.log(`⭐ User ${req.user.username} (${req.user.userId}) activated Premium with code ${normalized}`);
  res.json({ ok: true, message: '🎉 Premium aktiviert! Genieße Pulsewave ohne Werbung.' });
});

// ── GET /api/subscription — current premium status ────────────────────────
app.get('/api/subscription', requireAuth, async (req, res) => {
  try {
    const user = await findById(req.user.userId);
    res.json({ is_premium: user?.is_premium || false });
  } catch { res.json({ is_premium: false }); }
});

// ── POST /api/cancel-subscription — user cancels premium ──────────────────
app.post('/api/cancel-subscription', requireAuth, async (req, res) => {
  try {
    await updateUser(req.user.userId, { is_premium: false });
    res.json({ ok: true, message: 'Premium wurde deaktiviert' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN ENDPOINTS (require x-admin-password header)
// ═══════════════════════════════════════════════════════════════════════════

// ── POST /api/admin/generate-code — generate one or more codes ─────────────
app.post('/api/admin/generate-code', requireAdmin, (req, res) => {
  const count = Math.min(parseInt(req.body.count) || 1, 50);
  const codes = loadCodes();
  const newCodes = [];
  for (let i = 0; i < count; i++) {
    const code = makeActivationCode();
    const entry = { code, createdAt: new Date().toISOString(), usedBy: null, note: req.body.note || '' };
    codes.push(entry);
    newCodes.push(entry);
  }
  saveCodes(codes);
  console.log(`🔑 Admin generated ${count} code(s)`);
  res.json({ ok: true, codes: newCodes });
});

// ── GET /api/admin/codes — list all codes ─────────────────────────────────
app.get('/api/admin/codes', requireAdmin, (req, res) => {
  res.json({ codes: loadCodes() });
});

// ── DELETE /api/admin/codes/:code — delete / revoke a code ────────────────
app.delete('/api/admin/codes/:code', requireAdmin, (req, res) => {
  const target = req.params.code.toUpperCase();
  let codes = loadCodes();
  codes = codes.filter(c => c.code !== target);
  saveCodes(codes);
  res.json({ ok: true });
});

// ── GET /api/admin/users — list all users (admin) ─────────────────────────
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    if (pool) {
      const r = await pool.query('SELECT id, username, email, is_premium, created_at FROM users ORDER BY id DESC');
      return res.json({ users: r.rows });
    }
    const db = loadDB();
    res.json({ users: db.users.map(u => ({ id:u.id, username:u.username, email:u.email, is_premium:u.is_premium||false, created_at:u.createdAt||u.created_at })) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/admin/set-premium — manually set premium for a user ──────────
app.post('/api/admin/set-premium', requireAdmin, async (req, res) => {
  const { username, isPremium } = req.body;
  const user = await findByUsername(username);
  if (!user) return res.status(404).json({ error: 'Benutzer nicht gefunden' });
  await updateUser(user.id, { is_premium: !!isPremium });
  res.json({ ok: true, username, is_premium: !!isPremium });
});

// ── DELETE /api/account ────────────────────────────────────────────────────
app.delete('/api/account', requireAuth, async (req,res) => {
  await deleteById(req.user.userId);
  res.json({ ok:true });
});

// ── GET /api/status — returns current tunnel URL ───────────────────────────
app.get('/api/status', (req,res) => {
  const urlFile = require('path').join(__dirname,'tunnel-url.json');
  let tunnelUrl = null;
  try { tunnelUrl = JSON.parse(require('fs').readFileSync(urlFile,'utf8')).url; } catch(e) {}
  res.json({ ok: true, tunnelUrl, version: '1.1.0' });
});

// ── GET /api/search — YouTube search via yt-dlp (with cache) ─────────────
const searchCache = new Map(); // simple in-memory cache, TTL 10 min
const CACHE_TTL = 10 * 60 * 1000;

app.get('/api/search', async (req,res) => {
  const q = req.query.q;
  if (!q) return res.status(400).json({ error:'Query fehlt' });

  // Serve from cache if fresh
  const cacheKey = q.toLowerCase().trim();
  const cached = searchCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL) {
    return res.json({ results: cached.results, cached: true });
  }

  const ytdlp = require('path').join(__dirname,'..','pulsewave','bin','yt-dlp.exe');
  const bins = [
    ytdlp,
    require('path').join(__dirname,'bin','yt-dlp.exe'),
    'yt-dlp'
  ];
  const { exec } = require('child_process');
  const bin = bins.find(b => { try { return require('fs').existsSync(b); } catch { return false; } }) || 'yt-dlp';
  const safe = q.replace(/"/g,'').replace(/[`$]/g,'');
  const cmd = `"${bin}" "ytsearch8:${safe}" -j --flat-playlist --no-warnings`;

  exec(cmd, { maxBuffer: 10*1024*1024, timeout: 60000 }, (err, out) => {
    if (err) return res.status(500).json({ error: err.message, results: [] });
    try {
      const results = out.trim().split('\n').filter(Boolean).map(l => {
        const d = JSON.parse(l);
        const dur = d.duration || 0;
        const m = Math.floor(dur/60);
        const s = String(Math.floor(dur%60)).padStart(2,'0');
        return {
          videoId: d.id,
          title: d.title || 'Unknown',
          artist: d.uploader || d.channel || 'Unknown',
          thumbnail: d.thumbnail || `https://img.youtube.com/vi/${d.id}/hqdefault.jpg`,
          duration: `${m}:${s}`,
          durationSec: dur
        };
      });
      // Store in cache
      searchCache.set(cacheKey, { results, ts: Date.now() });
      res.json({ results });
    } catch(e) { res.status(500).json({ error: e.message, results: [] }); }
  });
});

// ── Admin panel ───────────────────────────────────────────────────────────
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ── SPA fallback ───────────────────────────────────────────────────────────
app.get('*', (req,res) => {
  const f = require('path').join(__dirname,'public','index.html');
  if (require('fs').existsSync(f)) res.sendFile(f);
  else res.status(404).json({ error:'Not found' });
});

app.listen(PORT, () => {
  console.log(`\n🎵 Pulsewave server on http://localhost:${PORT}`);
  console.log(`   Mode: ${pool?'PostgreSQL':'JSON file'} · Crypto: USDC on Polygon`);
  console.log(`\n🔑 Admin-Passwort: ${ADMIN_PASSWORD}\n   Admin-Panel: http://localhost:${PORT}/admin\n`);

  // Start crypto payment checker — runs every 3 minutes
  if (getHDWallet()) {
    console.log(`💰 Crypto payments: USDC on Polygon · Master wallet: ${getHDWallet().address}`);
    setInterval(checkCryptoPayments, 3 * 60 * 1000);
    setTimeout(checkCryptoPayments, 5000); // first check 5s after boot
  }

  // Pre-warm search cache for all radio station queries so they respond instantly
  const PREWARM = [
    'lofi hip hop chill beats',
    'top chart hits music 2024',
    'hip hop rap songs',
    'pop music hits',
    'electronic dance music',
    'rock music classic hits',
    'workout motivation gym music',
    'kpop songs hits'
  ];
  const { exec } = require('child_process');
  const path = require('path');
  const fs = require('fs');
  const bins = [
    path.join(__dirname,'..','pulsewave','bin','yt-dlp.exe'),
    path.join(__dirname,'bin','yt-dlp.exe'),
    'yt-dlp'
  ];
  const bin = bins.find(b => { try { return fs.existsSync(b); } catch { return false; } }) || 'yt-dlp';

  let idx = 0;
  const warmNext = () => {
    if (idx >= PREWARM.length) { console.log('✅ Cache pre-warm complete'); return; }
    const q = PREWARM[idx++];
    const key = q.toLowerCase().trim();
    if (searchCache.has(key)) { warmNext(); return; }
    const safe = q.replace(/"/g,'').replace(/[`$]/g,'');
    exec(`"${bin}" "ytsearch8:${safe}" -j --flat-playlist --no-warnings`,
      { maxBuffer: 10*1024*1024, timeout: 60000 },
      (err, out) => {
        if (!err) {
          try {
            const results = out.trim().split('\n').filter(Boolean).map(l => {
              const d = JSON.parse(l);
              const dur = d.duration || 0;
              return { videoId:d.id, title:d.title||'Unknown', artist:d.uploader||d.channel||'Unknown',
                thumbnail:d.thumbnail||`https://img.youtube.com/vi/${d.id}/hqdefault.jpg`,
                duration:`${Math.floor(dur/60)}:${String(Math.floor(dur%60)).padStart(2,'0')}`, durationSec:dur };
            });
            searchCache.set(key, { results, ts: Date.now() });
            console.log(`  ♻️  cached: ${q} (${results.length} tracks)`);
          } catch(e) {}
        }
        warmNext(); // run sequentially to avoid overloading yt-dlp
      }
    );
  };
  setTimeout(warmNext, 3000); // start 3s after server is ready
});
