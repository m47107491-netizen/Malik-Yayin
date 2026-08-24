require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const path = require('path');
const STATIC_ROOT = process.env.VERCEL ? path.join(__dirname) : __dirname;
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

// JWT Gizli Anahtar Fallback Güvenliği
const JWT_SECRET = process.env.JWT_SECRET || process.env.JWT_SECRET_KEY || process.env.SECRET_KEY || 'malik_yayin_default_fallback_secret_key_2026';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'maliksponsorluk@gmail.com').toLowerCase().trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'grok30101';

// ---------- DB ----------
// Vercel'de dosya sistemi salt-okunur; yazılabilir yol /tmp
const dbPath = process.env.VERCEL
  ? path.join('/tmp', 'malikyayin-db.json')
  : path.join(__dirname, 'db.json');
const adapter = new FileSync(dbPath);
const db = low(adapter);
db.defaults({ users: [], otps: [], orders: [] }).write();

// ---------- App ----------
const app = express();
app.set('trust proxy', 1); // Railway / reverse proxy
app.use(cors());
app.use(bodyParser.json());

// PayTR bildirim endpoint'i form-urlencoded gönderir
app.use('/api/payment/paytr/callback', bodyParser.urlencoded({ extended: false }));

const PORT = process.env.PORT || 3000;
const APP_URL = (process.env.APP_URL || 'https://malikyayin.com').replace(/\/$/, '');
const APK_DOWNLOAD_URL = `${APP_URL}/MalikYayin.apk`;

// Statik dosyalar: HTML sayfalar + APK
app.use(express.static(path.join(__dirname), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('.apk')) {
      res.setHeader('Content-Type', 'application/vnd.android.package-archive');
      res.setHeader('Content-Disposition', 'attachment; filename="MalikYayin.apk"');
    }
  },
}));

const otpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: { error: 'Çok fazla istek, lütfen biraz sonra tekrar deneyin.' },
});

// ---------- Mail ----------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: process.env.SMTP_SECURE !== 'false',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

function otpEmailHtml(name, code) {
  return `
  <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#1a1a1a">
    <h2 style="margin:0 0 16px">Merhaba ${name},</h2>
    <p>Hesabına giriş yapmak için aşağıdaki kodu kullan:</p>
    <div style="font-size:32px;font-weight:700;letter-spacing:6px;background:#f0f7ff;padding:16px 20px;border-radius:12px;text-align:center;margin:20px 0">${code}</div>
    <p>Bu kod <b>10 dakika</b> boyunca geçerlidir.</p>
    <p style="color:#888;font-size:12px;margin-top:32px">MalikYayın — TikTok LIVE Hediye Overlay</p>
  </div>`;
}

function licenseEmailHtml(key, days) {
  return `
  <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#1a1a1a">
    <h2 style="margin:0 0 12px">Ödemen alındı! 🎉</h2>
    <p>Lisans KEY'in hazır. Uygulamayı indir, KEY'i gir, yayına başla.</p>
    <p style="margin:20px 0 6px;font-size:13px;color:#666">Lisans KEY</p>
    <div style="font-size:22px;font-weight:700;letter-spacing:2px;background:#f0f7ff;padding:14px 18px;border-radius:10px;text-align:center">${key}</div>
    <p style="margin-top:16px"><b>${days} gün</b> süresi, KEY'i uygulamaya <b>ilk girdiğin anda</b> başlar. Hiç girmezsen satın alımdan sonra 24 saat içinde iade talep edebilirsin.</p>
    <p style="margin:28px 0 8px;font-size:13px;color:#666">Uygulama (APK)</p>
    <a href="${APK_DOWNLOAD_URL}" style="display:inline-block;background:linear-gradient(135deg,#22D3EE,#A78BFA);color:#061018;padding:14px 22px;border-radius:10px;font-weight:700;text-decoration:none">
      MalikYayın APK İndir
    </a>
    <p style="margin-top:18px;font-size:13px;color:#555">
      1) APK'yı indir ve kur<br>
      2) Uygulamayı aç, KEY'i yaz (süre bu anda başlar)<br>
      3) TikTok kullanıcı adını bağla ve overlay'i başlat
    </p>
    <p style="color:#888;font-size:12px;margin-top:32px">MalikYayın — TikTok LIVE Hediye Overlay</p>
  </div>`;
}

function genCode() {
  return String(crypto.randomInt(100000, 999999));
}

function genLicenseKey() {
  const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `MY-${seg()}-${seg()}-${seg()}`;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string' || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(String(password), salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
  } catch {
    return false;
  }
}

function publicUser(user) {
  return {
    email: user.email,
    name: user.name,
    license: user.license || null,
  };
}

function issueUserToken(user) {
  return jwt.sign(
    { uid: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

// ============================================================
// KAYIT — ad + e-posta + şifre (min 8)
// ============================================================
app.post('/api/auth/register', otpLimiter, (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const name = String(req.body?.name || '').trim();
  const password = String(req.body?.password || '');
  const password2 = String(req.body?.password2 || req.body?.passwordConfirm || '');

  if (!name || name.length < 2) {
    return res.status(400).json({ error: 'Adınız en az 2 karakter olmalı.' });
  }
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'Geçerli bir e-posta adresi girin.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Şifre en az 8 karakter olmalı.' });
  }
  if (password !== password2) {
    return res.status(400).json({ error: 'Şifreler eşleşmiyor.' });
  }
  if (db.get('users').find({ email }).value()) {
    return res.status(400).json({ error: 'Bu e-posta zaten kayıtlı. Giriş yap veya şifreni sıfırla.' });
  }

  const user = {
    id: crypto.randomUUID(),
    email,
    name,
    passwordHash: hashPassword(password),
    createdAt: Date.now(),
    license: null,
  };
  db.get('users').push(user).write();

  const token = issueUserToken(user);
  res.json({ ok: true, token, user: publicUser(user) });
});

// ============================================================
// GİRİŞ — e-posta + şifre
// ============================================================
app.post('/api/auth/login', otpLimiter, (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const password = String(req.body?.password || '');

  if (!email || !password) {
    return res.status(400).json({ error: 'E-posta ve şifre gerekli.' });
  }

  const user = db.get('users').find({ email }).value();
  if (!user || !user.passwordHash) {
    return res.status(401).json({ error: 'E-posta veya şifre hatalı.' });
  }
  if (!verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'E-posta veya şifre hatalı.' });
  }

  const token = issueUserToken(user);
  res.json({ ok: true, token, user: publicUser(user) });
});

// ============================================================
// ŞİFRE SIFIRLAMA — kod gönder
// ============================================================
app.post('/api/auth/send-code', otpLimiter, async (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const purpose = String(req.body?.purpose || 'reset'); // reset | legacy

  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'Geçerli bir e-posta adresi girin.' });
  }

  const user = db.get('users').find({ email }).value();
  if (!user) {
    return res.status(404).json({ error: 'Bu e-posta ile kayıtlı hesap bulunamadı.' });
  }

  const code = genCode();
  const expiresAt = Date.now() + 10 * 60 * 1000;

  db.get('otps').remove({ email }).write();
  db.get('otps').push({ email, code, expiresAt, attempts: 0, purpose: 'reset' }).write();

  const displayName = user.name || email.split('@')[0];

  try {
    await transporter.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to: email,
      subject: 'MalikYayın şifre sıfırlama kodu',
      html: otpEmailHtml(displayName, code),
    });
    res.json({ ok: true, message: 'Şifre sıfırlama kodu e-postana gönderildi.' });
  } catch (err) {
    console.error('Mail gönderim hatası:', err.message);
    res.status(500).json({ error: 'Kod gönderilemedi, SMTP ayarlarını kontrol edin.' });
  }
});

// ============================================================
// ŞİFRE SIFIRLAMA — kod + yeni şifre
// ============================================================
app.post('/api/auth/reset-password', otpLimiter, (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const code = String(req.body?.code || '');
  const password = String(req.body?.password || '');
  const password2 = String(req.body?.password2 || req.body?.passwordConfirm || '');

  if (!email || !code) {
    return res.status(400).json({ error: 'E-posta ve kod gerekli.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Yeni şifre en az 8 karakter olmalı.' });
  }
  if (password !== password2) {
    return res.status(400).json({ error: 'Şifreler eşleşmiyor.' });
  }

  const record = db.get('otps').find({ email }).value();
  if (!record) return res.status(400).json({ error: 'Önce bir kod iste.' });
  if (record.attempts >= 5)
    return res.status(429).json({ error: 'Çok fazla yanlış deneme. Yeni kod iste.' });
  if (Date.now() > record.expiresAt)
    return res.status(400).json({ error: 'Kodun süresi doldu, yeni kod iste.' });
  if (record.code !== String(code)) {
    db.get('otps').find({ email }).assign({ attempts: record.attempts + 1 }).write();
    return res.status(400).json({ error: 'Kod hatalı.' });
  }

  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

  db.get('otps').remove({ email }).write();
  db.get('users')
    .find({ email })
    .assign({ passwordHash: hashPassword(password) })
    .write();

  const updated = db.get('users').find({ email }).value();
  const token = issueUserToken(updated);
  res.json({
    ok: true,
    message: 'Şifren güncellendi.',
    token,
    user: publicUser(updated),
  });
});

// Eski OTP giriş (geriye uyumluluk) — kod doğrula, şifresiz hesaplara izin
app.post('/api/auth/verify-code', (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const code = String(req.body?.code || '');
  const name = String(req.body?.name || '').trim();
  const record = db.get('otps').find({ email }).value();

  if (!record) return res.status(400).json({ error: 'Önce bir kod iste.' });
  if (record.attempts >= 5)
    return res.status(429).json({ error: 'Çok fazla yanlış deneme. Yeni kod iste.' });
  if (Date.now() > record.expiresAt)
    return res.status(400).json({ error: 'Kodun süresi doldu, yeni kod iste.' });
  if (record.code !== String(code)) {
    db.get('otps').find({ email }).assign({ attempts: record.attempts + 1 }).write();
    return res.status(400).json({ error: 'Kod hatalı.' });
  }

  db.get('otps').remove({ email }).write();

  let user = db.get('users').find({ email }).value();
  if (!user) {
    user = {
      id: crypto.randomUUID(),
      email,
      name: name || email.split('@')[0],
      createdAt: Date.now(),
      license: null,
    };
    db.get('users').push(user).write();
  }

  const token = issueUserToken(user);
  res.json({
    ok: true,
    token,
    user: publicUser(user),
  });
});

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Giriş gerekli.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Oturum geçersiz, tekrar giriş yap.' });
  }
}

function adminAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Admin girişi gerekli.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') {
      return res.status(403).json({ error: 'Yetkisiz.' });
    }
    req.admin = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Admin oturumu geçersiz.' });
  }
}

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.get('users').find({ email: req.user.email }).value();
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
  res.json({ email: user.email, name: user.name, license: user.license });
});

// ============================================================
// KEY doğrulama (mobil uygulama için)
// ============================================================
app.post('/api/license/check', (req, res) => {
  const { key } = req.body || {};
  if (!key || typeof key !== 'string') {
    return res.status(400).json({ ok: false, error: 'KEY gerekli.' });
  }
  const normalized = key.trim().toUpperCase();
  const user = db
    .get('users')
    .find((u) => u.license && u.license.key && u.license.key.toUpperCase() === normalized)
    .value();

  if (!user || !user.license) {
    return res.json({ ok: false, active: false, error: 'Geçersiz KEY.' });
  }

  const lic = user.license;
  if (lic.active === false) {
    return res.json({ ok: true, active: false, error: 'KEY iptal edilmiş.', used: !!lic.activatedAt });
  }

  if (!lic.activatedAt) {
    const days = Number(lic.durationDays || process.env.LICENSE_DURATION_DAYS || 30);
    const activatedAt = Date.now();
    const expiresAt = activatedAt + days * 24 * 60 * 60 * 1000;
    db.get('users')
      .find({ email: user.email })
      .assign({
        license: {
          ...lic,
          activatedAt,
          expiresAt,
          active: true,
        },
      })
      .write();

    if (lic.key) {
      const order = db.get('orders').find({ key: lic.key }).value();
      if (order) {
        db.get('orders').find({ key: lic.key }).assign({ activatedAt, used: true }).write();
      }
    }
    return res.json({
      ok: true,
      active: true,
      firstActivation: true,
      activatedAt,
      expiresAt,
      durationDays: days,
      email: user.email,
      name: user.name,
    });
  }

  const stillValid = lic.expiresAt && lic.expiresAt > Date.now();
  if (!stillValid) {
    return res.json({
      ok: true,
      active: false,
      used: true,
      error: 'KEY süresi dolmuş.',
      expiresAt: lic.expiresAt,
      activatedAt: lic.activatedAt,
    });
  }

  res.json({
    ok: true,
    active: true,
    used: true,
    firstActivation: false,
    activatedAt: lic.activatedAt,
    expiresAt: lic.expiresAt,
    email: user.email,
    name: user.name,
  });
});

app.post('/api/license/refund-check', (req, res) => {
  const { key, email } = req.body || {};
  let user = null;
  if (key) {
    const normalized = String(key).trim().toUpperCase();
    user = db
      .get('users')
      .find((u) => u.license && u.license.key && u.license.key.toUpperCase() === normalized)
      .value();
  } else if (email) {
    user = db.get('users').find({ email: String(email).trim().toLowerCase() }).value();
  }
  if (!user || !user.license) {
    return res.json({ ok: false, refundable: false, error: 'KEY veya kullanıcı bulunamadı.' });
  }
  const lic = user.license;
  const used = !!lic.activatedAt;
  const purchasedAt = lic.purchasedAt || 0;
  const within24h = Date.now() - purchasedAt <= 24 * 60 * 60 * 1000;
  const refundable = !used && within24h && lic.active !== false;

  res.json({
    ok: true,
    refundable,
    used,
    within24h,
    purchasedAt,
    activatedAt: lic.activatedAt || null,
    expiresAt: lic.expiresAt || null,
    key: lic.key,
    email: user.email,
    reason: used
      ? 'KEY uygulamada aktifleştirilmiş, iade yapılamaz.'
      : !within24h
        ? '24 saat dolmuş, iade yapılamaz.'
        : 'KEY hiç kullanılmamış ve 24 saat içinde — iade uygun.',
  });
});


// ============================================================
// ADMIN — giriş + panel API
// ============================================================
app.post('/api/admin/login', (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const password = String(req.body?.password || '');
  if (!email || !password) {
    return res.status(400).json({ error: 'E-posta ve şifre gerekli.' });
  }
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'E-posta veya şifre hatalı.' });
  }
  const token = jwt.sign(
    { role: 'admin', email: ADMIN_EMAIL },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
  res.json({ ok: true, token, email: ADMIN_EMAIL });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  const users = db.get('users').value() || [];
  const orders = db.get('orders').value() || [];
  const now = Date.now();
  const activeLicenses = users.filter(
    (u) =>
      u.license &&
      u.license.active !== false &&
      u.license.key &&
      (!u.license.expiresAt || u.license.expiresAt > now)
  ).length;
  const unusedKeys = users.filter(
    (u) => u.license && u.license.key && !u.license.activatedAt && u.license.active !== false
  ).length;
  const expiredKeys = users.filter(
    (u) => u.license && u.license.expiresAt && u.license.expiresAt <= now
  ).length;
  const successOrders = orders.filter((o) => o.status === 'success').length;
  const pendingOrders = orders.filter((o) => o.status === 'pending').length;
  const failedOrders = orders.filter((o) => o.status === 'failed').length;
  const revenueTry = orders
    .filter((o) => o.status === 'success')
    .reduce((s, o) => s + Number(o.priceTry || (o.amount || 0) / 100), 0);
  const dayAgo = now - 24 * 60 * 60 * 1000;
  const newUsers24h = users.filter((u) => (u.createdAt || 0) >= dayAgo).length;
  const orders24h = orders.filter((o) => (o.createdAt || 0) >= dayAgo).length;
  const paytrReady = process.env.PAYTR_READY === '1' || process.env.PAYTR_READY === 'true';
  res.json({
    ok: true,
    users: users.length,
    activeLicenses,
    unusedKeys,
    expiredKeys,
    orders: orders.length,
    successOrders,
    pendingOrders,
    failedOrders,
    revenueTry,
    newUsers24h,
    orders24h,
    paytrReady,
    packages: { 7: 30, 30: 70, 60: 120, 365: 500 },
  });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const users = (db.get('users').value() || []).map((u) => ({
    id: u.id,
    email: u.email,
    name: u.name,
    createdAt: u.createdAt,
    license: u.license
      ? {
          key: u.license.key,
          purchasedAt: u.license.purchasedAt,
          activatedAt: u.license.activatedAt,
          expiresAt: u.license.expiresAt,
          durationDays: u.license.durationDays,
          active: u.license.active,
        }
      : null,
  }));
  users.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  res.json({ ok: true, users });
});

app.get('/api/admin/orders', adminAuth, (req, res) => {
  const orders = [...(db.get('orders').value() || [])];
  orders.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  res.json({ ok: true, orders });
});

app.post('/api/admin/license/revoke', adminAuth, (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'E-posta gerekli.' });
  const user = db.get('users').find({ email }).value();
  if (!user || !user.license) {
    return res.status(404).json({ error: 'Kullanıcı veya lisans bulunamadı.' });
  }
  db.get('users')
    .find({ email })
    .assign({
      license: { ...user.license, active: false },
    })
    .write();
  res.json({ ok: true, message: 'Lisans iptal edildi.' });
});

app.post('/api/admin/license/grant', adminAuth, (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const days = Number(req.body?.days || 30);
  if (!email) return res.status(400).json({ error: 'E-posta gerekli.' });
  let user = db.get('users').find({ email }).value();
  if (!user) {
    user = {
      id: crypto.randomUUID(),
      email,
      name: email.split('@')[0],
      createdAt: Date.now(),
      license: null,
    };
    db.get('users').push(user).write();
  }
  const key = genLicenseKey();
  const purchasedAt = Date.now();
  db.get('users')
    .find({ email })
    .assign({
      license: {
        key,
        purchasedAt,
        durationDays: days,
        activatedAt: null,
        expiresAt: null,
        active: true,
      },
    })
    .write();
  res.json({ ok: true, key, days, email });
});


app.post('/api/admin/license/extend', adminAuth, (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const extraDays = Number(req.body?.days || 30);
  if (!email) return res.status(400).json({ error: 'E-posta gerekli.' });
  if (!extraDays || extraDays < 1) return res.status(400).json({ error: 'Geçerli gün sayısı girin.' });
  const user = db.get('users').find({ email }).value();
  if (!user || !user.license || !user.license.key) {
    return res.status(404).json({ error: 'Kullanıcı veya lisans bulunamadı.' });
  }
  const lic = { ...user.license, active: true };
  const base = lic.expiresAt && lic.expiresAt > Date.now() ? lic.expiresAt : Date.now();
  if (!lic.activatedAt) {
    lic.durationDays = Number(lic.durationDays || 0) + extraDays;
  } else {
    lic.expiresAt = base + extraDays * 24 * 60 * 60 * 1000;
    lic.durationDays = Number(lic.durationDays || 0) + extraDays;
  }
  db.get('users').find({ email }).assign({ license: lic }).write();
  res.json({ ok: true, license: lic, message: extraDays + ' gün eklendi.' });
});

app.post('/api/admin/license/reactivate', adminAuth, (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'E-posta gerekli.' });
  const user = db.get('users').find({ email }).value();
  if (!user || !user.license || !user.license.key) {
    return res.status(404).json({ error: 'Kullanıcı veya lisans bulunamadı.' });
  }
  const lic = { ...user.license, active: true };
  db.get('users').find({ email }).assign({ license: lic }).write();
  res.json({ ok: true, message: 'Lisans yeniden aktif.', license: lic });
});

app.post('/api/admin/user/delete', adminAuth, (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'E-posta gerekli.' });
  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
  db.get('users').remove({ email }).write();
  res.json({ ok: true, message: 'Kullanıcı silindi.' });
});

app.post('/api/admin/user/rename', adminAuth, (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const name = String(req.body?.name || '').trim();
  if (!email || !name) return res.status(400).json({ error: 'E-posta ve ad gerekli.' });
  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
  db.get('users').find({ email }).assign({ name }).write();
  res.json({ ok: true, name });
});

// ============================================================
// 3) PAYTR — ödeme başlat
// ============================================================
app.post('/api/payment/paytr/init', auth, async (req, res) => {
  // PayTR onayı bitene kadar ödeme kapalı (env: PAYTR_READY=1 olunca açılır)
  const paytrReady = process.env.PAYTR_READY === '1' || process.env.PAYTR_READY === 'true';
  if (!paytrReady) {
    return res.status(503).json({ error: 'Ödeme yakında aktif olacak. PayTR onayı bekleniyor.' });
  }
  try {
    const user = db.get('users').find({ email: req.user.email }).value();
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

    const merchant_id = process.env.PAYTR_MERCHANT_ID;
    const merchant_key = process.env.PAYTR_MERCHANT_KEY;
    const merchant_salt = process.env.PAYTR_MERCHANT_SALT;

    const merchant_oid = 'MY' + Date.now() + crypto.randomBytes(2).toString('hex');
    const email = user.email;

    const allowed = {
      7: 30, 30: 70, 60: 120, 365: 500,
    };
    let days = Number(req.body?.days || process.env.LICENSE_DURATION_DAYS || 30);
    let priceTry = Number(req.body?.price || process.env.LICENSE_PRICE_TRY || 70);
    if (allowed[days] != null) priceTry = allowed[days];
    else { days = 30; priceTry = Number(process.env.LICENSE_PRICE_TRY || 70); }
    const payment_amount = Math.round(priceTry * 100);
    const user_ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0')
      .toString()
      .split(',')[0]
      .trim();
    const user_basket = Buffer.from(
      JSON.stringify([
        [
          `MalikYayın ${days} Günlük Lisans + APK`,
          String(priceTry.toFixed(2)),
          1,
        ],
      ])
    ).toString('base64');
    const no_installment = 1;
    const max_installment = 0;
    const currency = 'TL';
    const test_mode = process.env.PAYTR_TEST_MODE || '1';

    db.get('orders')
      .push({
        merchant_oid,
        email,
        amount: payment_amount,
        status: 'pending',
        days,
        priceTry,
        createdAt: Date.now(),
      })
      .write();

    const hashStr = `${merchant_id}${user_ip}${merchant_oid}${email}${payment_amount}${user_basket}${no_installment}${max_installment}${currency}${test_mode}`;
    const paytr_token = crypto
      .createHmac('sha256', merchant_key)
      .update(hashStr + merchant_salt)
      .digest('base64');

    const params = new URLSearchParams({
      merchant_id,
      user_ip,
      merchant_oid,
      email,
      payment_amount: String(payment_amount),
      paytr_token,
      user_basket,
      debug_on: '1',
      no_installment: String(no_installment),
      max_installment: String(max_installment),
      user_name: user.name || email,
      user_address: 'Belirtilmedi',
      user_phone: '05000000000',
      merchant_ok_url: process.env.PAYTR_OK_URL,
      merchant_fail_url: process.env.PAYTR_FAIL_URL,
      timeout_limit: '30',
      currency,
      test_mode: String(test_mode),
    });

    const { data } = await axios.post(
      'https://www.paytr.com/odeme/api/get-token',
      params.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    if (data.status === 'success') {
      res.json({
        ok: true,
        token: data.token,
        iframeUrl: `https://www.paytr.com/odeme/guvenli/${data.token}`,
      });
    } else {
      res.status(400).json({
        error: 'PayTR token alınamadı: ' + (data.reason || 'bilinmeyen hata'),
      });
    }
  } catch (err) {
    console.error('PayTR init hatası:', err.response?.data || err.message);
    res.status(500).json({ error: 'Ödeme başlatılamadı.' });
  }
});

// ============================================================
// 4) PAYTR — callback
// ============================================================
app.post('/api/payment/paytr/callback', (req, res) => {
  const { merchant_oid, status, total_amount, hash } = req.body;
  const merchant_key = process.env.PAYTR_MERCHANT_KEY;
  const merchant_salt = process.env.PAYTR_MERCHANT_SALT;

  const check = crypto
    .createHmac('sha256', merchant_key)
    .update(merchant_oid + merchant_salt + status + total_amount)
    .digest('base64');

  if (check !== hash) {
    console.error('PayTR callback: hash uyuşmuyor.');
    return res.status(400).send('PAYTR notification failed: bad hash');
  }

  const order = db.get('orders').find({ merchant_oid }).value();
  if (order && order.status === 'pending') {
    if (status === 'success') {
      const key = genLicenseKey();
      const days = Number(order.days || process.env.LICENSE_DURATION_DAYS || 30);
      const purchasedAt = Date.now();

      db.get('orders')
        .find({ merchant_oid })
        .assign({ status: 'success', key, purchasedAt, used: false })
        .write();
      db.get('users')
        .find({ email: order.email })
        .assign({
          license: {
            key,
            purchasedAt,
            durationDays: days,
            activatedAt: null,
            expiresAt: null,
            active: true,
          },
        })
        .write();

      transporter
        .sendMail({
          from: process.env.MAIL_FROM || process.env.SMTP_USER,
          to: order.email,
          subject: 'MalikYayın KEY + APK hazır 🎉',
          html: licenseEmailHtml(key, days),
        })
        .catch((e) => console.error('KEY/APK mail hatası:', e.message));
    } else {
      db.get('orders').find({ merchant_oid }).assign({ status: 'failed' }).write();
    }
  }

  res.send('OK');
});

// APK indirme
app.get('/download/apk', (req, res) => {
  const apkPath = path.join(__dirname, 'MalikYayin.apk');
  res.download(apkPath, 'MalikYayin.apk', (err) => {
    if (err) {
      console.error('APK indirme hatası:', err.message);
      if (!res.headersSent) res.status(404).send('APK bulunamadı.');
    }
  });
});

if (!process.env.VERCEL) {
  app.listen(PORT, () =>
    console.log(`MalikYayın backend http://localhost:${PORT} — APK: ${APK_DOWNLOAD_URL}`)
  );
}

module.exports = app;
