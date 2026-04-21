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

// ── Stripe (optional — set STRIPE_SECRET_KEY env var to enable) ───────────
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  console.log('💳 Stripe enabled');
} else {
  console.log('⚠️  Stripe disabled (set STRIPE_SECRET_KEY to enable payments)');
}
const STRIPE_PRICE_ID      = process.env.STRIPE_PRICE_ID      || '';
const STRIPE_WEBHOOK_SECRET= process.env.STRIPE_WEBHOOK_SECRET || '';
const CLIENT_URL           = process.env.CLIENT_URL || 'https://welias123.github.io/pulsewave-website';

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
async function findByStripeCustomer(customerId) {
  if (pool) { const r = await pool.query('SELECT * FROM users WHERE stripe_customer_id=$1',[customerId]); return r.rows[0]||null; }
  return loadDB().users.find(u=>u.stripe_customer_id===customerId)||null;
}
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

// Raw body for Stripe webhooks (must be before express.json())
app.use('/api/webhook', express.raw({ type:'application/json' }));
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

// ── POST /api/create-checkout ─────────────────────────────────────────────
app.post('/api/create-checkout', requireAuth, async (req,res) => {
  if (!stripe) return res.status(503).json({ error:'Zahlungen noch nicht eingerichtet. Stripe-Key fehlt.' });
  if (!STRIPE_PRICE_ID) return res.status(503).json({ error:'Kein Stripe-Preis konfiguriert.' });
  try {
    let user = await findById(req.user.userId);
    // Create Stripe customer if not exists
    let customerId = user?.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: req.user.email,
        metadata: { userId: String(req.user.userId), username: req.user.username }
      });
      customerId = customer.id;
      await updateUser(req.user.userId, { stripe_customer_id: customerId });
    }
    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      success_url: `${CLIENT_URL}?premium=success`,
      cancel_url:  `${CLIENT_URL}?premium=cancel`,
      metadata: { userId: String(req.user.userId) }
    });
    res.json({ url: session.url });
  } catch(e) { console.error(e); res.status(500).json({ error:'Checkout fehlgeschlagen: '+e.message }); }
});

// ── GET /api/subscription ──────────────────────────────────────────────────
app.get('/api/subscription', requireAuth, async (req,res) => {
  try {
    const user = await findById(req.user.userId);
    res.json({ is_premium: user?.is_premium||false, stripe_customer_id: user?.stripe_customer_id||null });
  } catch { res.json({ is_premium:false }); }
});

// ── POST /api/cancel-subscription ─────────────────────────────────────────
app.post('/api/cancel-subscription', requireAuth, async (req,res) => {
  if (!stripe) return res.status(503).json({ error:'Stripe nicht konfiguriert' });
  try {
    const user = await findById(req.user.userId);
    if (!user?.stripe_subscription_id) return res.status(400).json({ error:'Kein aktives Abo' });
    await stripe.subscriptions.cancel(user.stripe_subscription_id);
    await updateUser(req.user.userId, { is_premium:false, stripe_subscription_id:null });
    res.json({ ok:true, message:'Abo erfolgreich gekündigt' });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── POST /api/webhook (Stripe) ─────────────────────────────────────────────
app.post('/api/webhook', async (req,res) => {
  if (!stripe) return res.status(200).json({ received:true });
  let event;
  try {
    event = STRIPE_WEBHOOK_SECRET
      ? stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET)
      : JSON.parse(req.body.toString());
  } catch(e) { return res.status(400).send(`Webhook Error: ${e.message}`); }

  try {
    switch(event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const userId = parseInt(session.metadata?.userId);
        if (userId) {
          await updateUser(userId, {
            is_premium: true,
            stripe_subscription_id: session.subscription
          });
          console.log(`✅ User ${userId} upgraded to Premium`);
        }
        break;
      }
      case 'customer.subscription.deleted':
      case 'customer.subscription.paused': {
        const sub = event.data.object;
        const user = await findByStripeCustomer(sub.customer);
        if (user) {
          await updateUser(user.id, { is_premium:false, stripe_subscription_id:null });
          console.log(`❌ User ${user.id} Premium cancelled`);
        }
        break;
      }
      case 'invoice.payment_failed': {
        console.log('⚠️  Payment failed for:', event.data.object.customer);
        break;
      }
    }
  } catch(e) { console.error('Webhook handler error:', e); }

  res.json({ received:true });
});

// ── DELETE /api/account ────────────────────────────────────────────────────
app.delete('/api/account', requireAuth, async (req,res) => {
  await deleteById(req.user.userId);
  res.json({ ok:true });
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

// ── SPA fallback ───────────────────────────────────────────────────────────
app.get('*', (req,res) => {
  const f = require('path').join(__dirname,'public','index.html');
  if (require('fs').existsSync(f)) res.sendFile(f);
  else res.status(404).json({ error:'Not found' });
});

app.listen(PORT, () => {
  console.log(`\n🎵 Pulsewave server on http://localhost:${PORT}`);
  console.log(`   Mode: ${pool?'PostgreSQL':'JSON file'} · Stripe: ${stripe?'enabled':'disabled'}`);

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
