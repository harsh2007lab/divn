const express    = require('express');
const mongoose   = require('mongoose');
const path       = require('path');
const session    = require('express-session');
const MongoStore = require('connect-mongo');
const crypto     = require('crypto');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 6000;
const MONGODB_URI = process.env.MONGODB_URI;

// Trust Render/Heroku reverse proxy so secure cookies work over HTTPS
app.set('trust proxy', 1);

if (!MONGODB_URI) {
  console.error('❌  MONGODB_URI not set in .env'); process.exit(1);
}

const SESSION_SECRET = process.env.SESSION_SECRET || '16bd798d9d4f58bb3c4809e0b7cd8601dc3bf92f9d30ac558a66b0b41b8a7ced';

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'div.sid',
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    collectionName: 'sessions',
    ttl: 24 * 60 * 60,
    autoRemove: 'interval',
    autoRemoveInterval: 10
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// ─── Auth guard ───────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated && req.session.userId) return next();
  res.status(401).json({ success: false, error: 'Login required' });
}

// ─── Password helpers ─────────────────────────────────────────────────────────
function hashPass(pass) {
  return crypto.createHash('sha256').update(pass + 'div_salt_2026').digest('hex');
}

// ─── Email validation ─────────────────────────────────────────────────────────
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ─── MongoDB Schemas ──────────────────────────────────────────────────────────

// Users — email + password based registration
const UserModel = mongoose.model('User', new mongoose.Schema({
  email:     { type: String, required: true, unique: true, index: true, lowercase: true, trim: true },
  username:  { type: String, required: true, unique: true, index: true, trim: true },
  password:  { type: String, required: true },  // sha256 hashed
  createdAt: { type: Date, default: Date.now }
}));

// Data — scoped by userId (each user's data is isolated)
const DataModel = mongoose.model('Store', new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, required: true, index: true, ref: 'User' },
  key:       { type: String, required: true, index: true },
  value:     { type: mongoose.Schema.Types.Mixed, required: true },
  updatedAt: { type: Date, default: Date.now }
}));
// Compound unique index: one key per user
DataModel.schema.index({ userId: 1, key: 1 }, { unique: true });

// ─── Backup Schema (keeps last 5 versions per userId+key) ────────────────────
const BackupModel = mongoose.model('Backup', new mongoose.Schema({
  userId:  { type: mongoose.Schema.Types.ObjectId, required: true, index: true, ref: 'User' },
  key:     { type: String, required: true, index: true },
  value:   { type: mongoose.Schema.Types.Mixed, required: true },
  savedAt: { type: Date, default: Date.now }
}));

async function saveBackup(userId, key, value) {
  try {
    await BackupModel.create({ userId, key, value });
    // Keep only last 5 backups per userId+key
    const all = await BackupModel.find({ userId, key }).sort({ savedAt: -1 }).select('_id');
    if (all.length > 5) {
      const toDelete = all.slice(5).map(d => d._id);
      await BackupModel.deleteMany({ _id: { $in: toDelete } });
    }
  } catch (e) {
    console.warn('⚠️  Backup save failed (non-critical):', e.message);
  }
}

// Bills & Rpay — also scoped by userId
const BillModel = mongoose.model('Bill', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true, ref: 'User' }
}, { strict: false }));

const RpayModel = mongoose.model('Rpay', new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, required: true, index: true, ref: 'User' },
  id:           { type: String, required: true, index: true },
  customerName: { type: String, required: true },
  customerPhone:{ type: String, default: '' },
  creditAmount: { type: Number, required: true, default: 0 },
  creditDate:   { type: String, required: true },
  notes:        { type: String, default: '' },
  payments:     [new mongoose.Schema({
    id: String, date: String,
    amount: Number,
    mode: { type: String, default: 'Cash' },
    notes: String
  }, { _id: false })],
  status:    { type: String, enum: ['pending','partially_paid','settled'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
}));
// Unique rpay id per user
RpayModel.schema.index({ userId: 1, id: 1 }, { unique: true });

// ─── MongoDB Connect ──────────────────────────────────────────────────────────
let dbOk = false;
mongoose.connect(MONGODB_URI)
  .then(async () => {
    dbOk = true;
    console.log('✅  MongoDB connected');
  })
  .catch(e => {
    dbOk = false;
    console.error('❌  MongoDB error:', e.message);
  });
mongoose.connection.on('disconnected', () => { dbOk = false; });
mongoose.connection.on('connected',    () => { dbOk = true;  });

// ─── Helper: upsert per user ──────────────────────────────────────────────────
async function upsert(userId, key, value) {
  await DataModel.findOneAndUpdate(
    { userId, key },
    { value, updatedAt: new Date() },
    { upsert: true }
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES  (no requireAuth — these ARE the auth endpoints)
// ══════════════════════════════════════════════════════════════════════════════

// ─── REGISTER ─────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, username, password } = req.body || {};

  if (!email || !username || !password)
    return res.status(400).json({ success: false, error: 'Email, username aur password sab chahiye' });

  if (!isValidEmail(email))
    return res.status(400).json({ success: false, error: 'Valid email address enter karo' });

  if (username.trim().length < 3)
    return res.status(400).json({ success: false, error: 'Username kam se kam 3 characters ka hona chahiye' });

  if (password.length < 6)
    return res.status(400).json({ success: false, error: 'Password kam se kam 6 characters ka hona chahiye' });

  if (!dbOk)
    return res.status(503).json({ success: false, error: 'Database connected nahi hai, baad mein try karo' });

  try {
    // Check if email or username already taken
    const existing = await UserModel.findOne({
      $or: [{ email: email.toLowerCase().trim() }, { username: username.trim() }]
    });
    if (existing) {
      if (existing.email === email.toLowerCase().trim())
        return res.status(409).json({ success: false, error: 'Ye email already registered hai' });
      return res.status(409).json({ success: false, error: 'Ye username already liya hua hai' });
    }

    const user = await UserModel.create({
      email:    email.toLowerCase().trim(),
      username: username.trim(),
      password: hashPass(password)
    });

    // Regenerate session (prevents fixation), then set data and save
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ success: false, error: 'Session error' });
      req.session.authenticated = true;
      req.session.userId        = user._id.toString();
      req.session.username      = user.username;
      req.session.email         = user.email;
      req.session.save((err2) => {
        if (err2) return res.status(500).json({ success: false, error: 'Session save failed' });
        return res.json({ success: true, username: user.username, email: user.email });
      });
    });
  } catch (e) {
    if (e.code === 11000) {
      const field = Object.keys(e.keyPattern || {})[0] || 'field';
      return res.status(409).json({ success: false, error: `Ye ${field} already registered hai` });
    }
    res.status(500).json({ success: false, error: 'Server error: ' + e.message });
  }
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ success: false, error: 'Email aur password dono chahiye' });

  if (!dbOk)
    return res.status(503).json({ success: false, error: 'Database connected nahi hai' });

  try {
    // Login by email
    const user = await UserModel.findOne({ email: email.toLowerCase().trim() });
    if (!user || user.password !== hashPass(password)) {
      return res.status(401).json({ success: false, error: 'Email ya password galat hai' });
    }

    req.session.authenticated = true;
    req.session.userId        = user._id.toString();
    req.session.username      = user.username;
    req.session.email         = user.email;

    // Regenerate session (prevents fixation), then set data and save
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ success: false, error: 'Session error' });
      req.session.authenticated = true;
      req.session.userId        = user._id.toString();
      req.session.username      = user.username;
      req.session.email         = user.email;
      req.session.save((err2) => {
        if (err2) return res.status(500).json({ success: false, error: 'Session save failed' });
        return res.json({ success: true, username: user.username, email: user.email });
      });
    });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Server error: ' + e.message });
  }
});

// ─── LOGOUT ───────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.warn('⚠️  Session destroy error:', err.message);
    res.clearCookie('div.sid');
    res.json({ success: true });
  });
});

// ─── AUTH STATUS ──────────────────────────────────────────────────────────────
app.get('/api/auth-status', (req, res) => {
  res.json({
    authenticated: !!(req.session && req.session.authenticated),
    username: (req.session && req.session.username) || null,
    email:    (req.session && req.session.email)    || null
  });
});

// ─── Status (public) ─────────────────────────────────────────────────────────
app.get('/api/status', (req, res) => {
  res.json({ status: 'ok', mongodb: dbOk ? 'connected' : 'disconnected' });
});

// ══════════════════════════════════════════════════════════════════════════════
//  DATA ROUTES  (all protected — data scoped by req.session.userId)
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/all-data', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    if (!dbOk) return res.status(503).json({ success: false, error: 'MongoDB not connected' });
    const result = {};
    const docs = await DataModel.find({ userId });
    docs.forEach(d => { result[d.key] = d.value; });

    // Also pull from scoped Bill/Rpay models if not already in DataModel
    if (!result['bills'] || (Array.isArray(result['bills']) && !result['bills'].length)) {
      const items = await BillModel.find({ userId }).lean();
      if (items.length) result['bills'] = items;
    }
    if (!result['rpay'] || (Array.isArray(result['rpay']) && !result['rpay'].length)) {
      const items = await RpayModel.find({ userId }).lean();
      if (items.length) result['rpay'] = items;
    }

    res.json({ success: true, data: result });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/data/:key', requireAuth, async (req, res) => {
  const { key } = req.params;
  const userId  = req.session.userId;
  try {
    if (!dbOk) return res.status(503).json({ success: false, error: 'MongoDB not connected' });
    const doc = await DataModel.findOne({ userId, key });
    if (doc && doc.value != null) return res.json({ success: true, data: doc.value });

    if (key === 'bills') return res.json({ success: true, data: await BillModel.find({ userId }).lean() });
    if (key === 'rpay')  return res.json({ success: true, data: await RpayModel.find({ userId }).lean() });

    res.json({ success: true, data: null });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/data/:key', requireAuth, async (req, res) => {
  const { key } = req.params;
  const { data } = req.body;
  const userId   = req.session.userId;

  // Guard: data field must be present in body (null is valid, undefined is not)
  if (!('data' in (req.body || {}))) {
    return res.status(400).json({ success: false, error: 'Request body mein "data" field zaroori hai' });
  }

  try {
    if (!dbOk) return res.status(503).json({ success: false, error: 'MongoDB not connected' });

    // Backup current value before overwriting
    const existing = await DataModel.findOne({ userId, key });
    if (existing && existing.value != null) await saveBackup(userId, key, existing.value);

    await upsert(userId, key, data);

    // Mirror to typed collections (scoped)
    if (key === 'bills') {
      await BillModel.deleteMany({ userId });
      if (Array.isArray(data) && data.length)
        await BillModel.insertMany(data.map(d => ({ ...d, userId })));
      else if (data && typeof data === 'object' && !Array.isArray(data))
        await BillModel.create({ ...data, userId });
    }
    if (key === 'rpay') {
      await RpayModel.deleteMany({ userId });
      if (Array.isArray(data) && data.length)
        await RpayModel.insertMany(data.map(d => ({ ...d, userId })));
      else if (data && typeof data === 'object' && !Array.isArray(data))
        await RpayModel.create({ ...data, userId });
    }

    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// Delete single bill (scoped)
app.delete('/api/bills/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const userId  = req.session.userId;
  try {
    if (!dbOk) return res.status(503).json({ success: false, error: 'MongoDB not connected' });
    const doc   = await DataModel.findOne({ userId, key: 'bills' });
    const bills = ((doc && Array.isArray(doc.value)) ? doc.value : []).filter(b => b.id !== id);
    await upsert(userId, 'bills', bills);
    await BillModel.deleteOne({ userId, id });
    res.json({ success: true, message: 'Bill deleted' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// List backups for a key (scoped)
app.get('/api/backups/:key', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    if (!dbOk) return res.status(503).json({ success: false, error: 'MongoDB not connected' });
    const backups = await BackupModel.find({ userId, key: req.params.key })
      .sort({ savedAt: -1 })
      .select('_id savedAt')
      .lean();
    res.json({ success: true, backups });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// Restore a specific backup by id (scoped)
app.post('/api/backups/:id/restore', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    if (!dbOk) return res.status(503).json({ success: false, error: 'MongoDB not connected' });
    const backup = await BackupModel.findOne({ _id: req.params.id, userId });
    if (!backup) return res.status(404).json({ success: false, error: 'Backup not found' });
    const existing = await DataModel.findOne({ userId, key: backup.key });
    if (existing && existing.value != null) await saveBackup(userId, backup.key, existing.value);
    await upsert(userId, backup.key, backup.value);
    res.json({ success: true, message: `Restored backup for key: ${backup.key}` });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// Bulk sync (scoped)
app.post('/api/sync', requireAuth, async (req, res) => {
  const { allData } = req.body;
  const userId      = req.session.userId;
  if (!allData || typeof allData !== 'object')
    return res.status(400).json({ success: false, error: 'Invalid payload' });
  try {
    if (!dbOk) return res.status(503).json({ success: false, error: 'MongoDB not connected' });
    for (const key of Object.keys(allData)) {
      const val = allData[key];
      const existing = await DataModel.findOne({ userId, key });
      if (existing && existing.value != null) await saveBackup(userId, key, existing.value);
      await upsert(userId, key, val);

      if (key === 'bills' && Array.isArray(val)) {
        await BillModel.deleteMany({ userId });
        if (val.length) await BillModel.insertMany(val.map(d => ({ ...d, userId })));
      }
      if (key === 'rpay' && Array.isArray(val)) {
        await RpayModel.deleteMany({ userId });
        if (val.length) await RpayModel.insertMany(val.map(d => ({ ...d, userId })));
      }
    }
    res.json({ success: true, message: 'Synced!' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  PWA STATIC FILES  (public — no auth needed)
// ══════════════════════════════════════════════════════════════════════════════
app.get('/manifest.json', (req, res) => {
  res.setHeader('Content-Type', 'application/manifest+json');
  res.sendFile(path.join(__dirname, 'manifest.json'));
});
app.get('/sw.js', (req, res) => {
  // No-cache so browser always gets latest SW
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.sendFile(path.join(__dirname, 'sw.js'));
});
// PNG icons — generated via canvas on first request, then cached in-memory
const { createCanvas } = (() => { try { return require('canvas'); } catch { return {}; } })();
const iconCache = {};
app.get('/icon-:size.png', (req, res) => {
  const size = parseInt(req.params.size, 10);
  if (![192, 512].includes(size)) return res.status(404).end();
  if (iconCache[size]) { res.setHeader('Content-Type','image/png'); return res.send(iconCache[size]); }
  if (!createCanvas) {
    // canvas not installed — return a 1x1 transparent PNG fallback
    const tiny = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==','base64');
    res.setHeader('Content-Type','image/png'); return res.send(tiny);
  }
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');
  const r = size * 0.188;
  ctx.beginPath();
  ctx.moveTo(r, 0); ctx.lineTo(size-r, 0);
  ctx.quadraticCurveTo(size, 0, size, r);
  ctx.lineTo(size, size-r); ctx.quadraticCurveTo(size, size, size-r, size);
  ctx.lineTo(r, size); ctx.quadraticCurveTo(0, size, 0, size-r);
  ctx.lineTo(0, r); ctx.quadraticCurveTo(0, 0, r, 0);
  ctx.closePath();
  ctx.fillStyle = '#16233B'; ctx.fill();
  ctx.font = `${size * 0.52}px serif`;
  ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.fillText('🏪', size / 2, size / 2 + size * 0.03);
  iconCache[size] = canvas.toBuffer('image/png');
  res.setHeader('Content-Type','image/png'); res.send(iconCache[size]);
});

// ══════════════════════════════════════════════════════════════════════════════
//  PAGES
// ══════════════════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  if (req.session && req.session.authenticated && req.session.userId) {
    res.sendFile(path.join(__dirname, 'index.html'));
  } else {
    res.sendFile(path.join(__dirname, 'login.html'));
  }
});

app.get('/index.html', (req, res) => res.redirect('/'));
app.get('/login.html',  (req, res) => res.redirect('/'));
app.use((req, res) => res.redirect('/'));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀  Div Manager  →  http://localhost:${PORT}`);
  console.log(`📧  Registration: /api/register (email + password)`);
  console.log(`🍃  DB: MongoDB Atlas (div_db)\n`);
});
