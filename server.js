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
db.defaults({
  users: [],
  otps: [],
  orders: [],
  captchas: [],
  appConfig: {
    forceUpdate: false,
    title: 'Zorunlu Güncelleme',
    message: 'Uygulama güncellendi ve bazı hatalar düzeltildi.',
    note: "MalikYayın'ı kullanmaya devam etmek için güncelleme zorunludur.",
    button: 'Şimdi Güncelle',
    url: 'https://malik-yayin-alpha.vercel.app/',
  },
}).write();


// ---------- Kalıcı bellek (Vercel /tmp silinir; warm instance + Gist opsiyonel) ----------
global.__myAppConfig = global.__myAppConfig || null;
global.__myDbCache = global.__myDbCache || null;

function readAppConfig() {
  if (global.__myAppConfig) return { ...global.__myAppConfig };
  try {
    const cfg = db.get('appConfig').value();
    if (cfg) {
      global.__myAppConfig = { ...cfg };
      return { ...cfg };
    }
  } catch (e) {}
  return {
    forceUpdate: false,
    title: 'Zorunlu Güncelleme',
    message: 'Uygulama güncellendi ve bazı hatalar düzeltildi.',
    note: "MalikYayın'ı kullanmaya devam etmek için güncelleme zorunludur.",
    button: 'Şimdi Güncelle',
    url: 'https://malik-yayin-alpha.vercel.app/',
  };
}

function writeAppConfig(next) {
  global.__myAppConfig = { ...next };
  try {
    db.set('appConfig', next).write();
  } catch (e) {
    console.error('appConfig disk yazılamadı:', e.message);
  }
  // Opsiyonel: GitHub Gist (GIST_ID + GITHUB_TOKEN) — gerçekten kalıcı
  persistGist().catch((e) => console.warn('Gist kayıt:', e.message));
}

async function persistGist() {
  const token = (process.env.GITHUB_TOKEN || '').trim();
  if (!token) return;
  const payload = {
    users: db.get('users').value() || [],
    orders: db.get('orders').value() || [],
    appConfig: readAppConfig(),
    otps: [],
    captchas: [],
  };
  const content = JSON.stringify(payload, null, 2);
  const gistId = (process.env.GIST_ID || '').trim();
  const repo = (process.env.GITHUB_REPO || '').trim(); // örn: m47107491-netizen/Malik-Yayin
  const path = (process.env.GITHUB_DB_PATH || 'malikyayin-db.json').trim();

  // 1) GitHub Gist
  if (gistId) {
    const r = await fetch('https://api.github.com/gists/' + gistId, {
      method: 'PATCH',
      headers: {
        Authorization: 'Bearer ' + token,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        files: { 'malikyayin-db.json': { content } },
      }),
    });
    if (!r.ok) {
      const txt = await r.text();
      throw new Error('Gist ' + r.status + ' ' + txt.slice(0, 120));
    }
    return;
  }

  // 2) Repo dosyası (senin yaptığın: malikyayin-db.json)
  if (repo) {
    const apiBase = 'https://api.github.com/repos/' + repo + '/contents/' + path;
    let sha = null;
    try {
      const get = await fetch(apiBase, {
        headers: {
          Authorization: 'Bearer ' + token,
          Accept: 'application/vnd.github+json',
        },
      });
      if (get.ok) {
        const cur = await get.json();
        sha = cur.sha || null;
      }
    } catch (e) {}
    const body = {
      message: 'chore: malikyayin db sync',
      content: Buffer.from(content, 'utf8').toString('base64'),
      branch: process.env.GITHUB_BRANCH || 'main',
    };
    if (sha) body.sha = sha;
    const r = await fetch(apiBase, {
      method: 'PUT',
      headers: {
        Authorization: 'Bearer ' + token,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const txt = await r.text();
      throw new Error('Repo DB ' + r.status + ' ' + txt.slice(0, 160));
    }
  }
}

async function loadGistOnBoot() {
  const token = (process.env.GITHUB_TOKEN || '').trim();
  if (!token) return;
  const gistId = (process.env.GIST_ID || '').trim();
  const repo = (process.env.GITHUB_REPO || '').trim();
  const path = (process.env.GITHUB_DB_PATH || 'malikyayin-db.json').trim();
  try {
    let raw = null;
    if (gistId) {
      const r = await fetch('https://api.github.com/gists/' + gistId, {
        headers: {
          Authorization: 'Bearer ' + token,
          Accept: 'application/vnd.github+json',
        },
      });
      if (!r.ok) return;
      const data = await r.json();
      const file = (data.files && data.files['malikyayin-db.json']) || null;
      if (file && file.content) raw = file.content;
    } else if (repo) {
      const apiBase = 'https://api.github.com/repos/' + repo + '/contents/' + path;
      const r = await fetch(apiBase + '?ref=' + encodeURIComponent(process.env.GITHUB_BRANCH || 'main'), {
        headers: {
          Authorization: 'Bearer ' + token,
          Accept: 'application/vnd.github+json',
        },
      });
      if (!r.ok) return;
      const data = await r.json();
      if (data.content) {
        raw = Buffer.from(data.content.replace(/\n/g, ''), 'base64').toString('utf8');
      }
    }
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (parsed.users) db.set('users', parsed.users).write();
    if (parsed.orders) db.set('orders', parsed.orders).write();
    if (parsed.appConfig) {
      global.__myAppConfig = parsed.appConfig;
      db.set('appConfig', parsed.appConfig).write();
    }
    console.log('Kalici DB yuklendi — users:', (parsed.users || []).length);
  } catch (e) {
    console.warn('Kalici DB yuklenemedi:', e.message);
  }
}
// ---------- Kalıcı bellek + ilk yükleme kilidi ----------
global.__myUsers = global.__myUsers || null;      // [{...}]
global.__myOrders = global.__myOrders || null;
global.__myDbReady = global.__myDbReady || null;  // Promise

function hydrateFromMemory() {
  if (Array.isArray(global.__myUsers)) {
    db.set('users', global.__myUsers).write();
  }
  if (Array.isArray(global.__myOrders)) {
    db.set('orders', global.__myOrders).write();
  }
}

function snapshotToMemory() {
  global.__myUsers = db.get('users').value() || [];
  global.__myOrders = db.get('orders').value() || [];
}

/** Her istekten önce: Gist/Repo'dan bir kez yükle, belleğe al */
async function ensureDb() {
  // Önce warm memory varsa diske yaz
  if (Array.isArray(global.__myUsers) && global.__myUsers.length) {
    hydrateFromMemory();
    return;
  }
  if (!global.__myDbReady) {
    global.__myDbReady = (async () => {
      await loadGistOnBoot();
      snapshotToMemory();
      console.log('ensureDb hazır — users:', (global.__myUsers || []).length);
    })().catch((e) => {
      console.warn('ensureDb hata:', e.message);
      global.__myDbReady = null;
      snapshotToMemory();
    });
  }
  await global.__myDbReady;
  hydrateFromMemory();
}

/** Kullanıcı/sipariş yazdıktan sonra çağır — disk + bellek + Gist */
async function saveDb() {
  snapshotToMemory();
  try {
    await persistGist();
  } catch (e) {
    console.warn('saveDb persist:', e.message || e);
  }
}

// Boot'da bir kez dene
loadGistOnBoot().then(() => snapshotToMemory()).catch(() => {});

// ---------- App ----------
const app = express();
app.set('trust proxy', 1); // Railway / reverse proxy
app.use(cors());
app.use(bodyParser.json());

// API isteklerinde DB'yi yükle (Vercel cold start)
app.use(async (req, res, next) => {
  if (req.path && req.path.startsWith('/api/')) {
    try { await ensureDb(); } catch (e) { console.warn('ensureDb mw:', e.message); }
  }
  next();
});

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
function buildTransporter(overridePort) {
  // Gmail varsayılan: smtp.gmail.com — env yoksa da dene (sadece USER/PASS varsa)
  let host = (process.env.SMTP_HOST || '').trim();
  const user = (process.env.SMTP_USER || '').trim();
  // App password'ta boşluk olabilir — kaldır
  const pass = String(process.env.SMTP_PASS || '').replace(/\s+/g, '').trim();
  if (!user || !pass) {
    console.error('SMTP eksik: SMTP_USER ve SMTP_PASS gerekli (Vercel Environment Variables).');
    return null;
  }
  if (!host) {
    // Gmail adresi ise otomatik
    if (/@gmail\.com$/i.test(user) || /@googlemail\.com$/i.test(user)) {
      host = 'smtp.gmail.com';
      console.log('SMTP_HOST boş — Gmail varsayılanı kullanılıyor: smtp.gmail.com');
    } else {
      console.error('SMTP_HOST eksik. Örn: smtp.gmail.com');
      return null;
    }
  }

  const port = Number(overridePort != null ? overridePort : (process.env.SMTP_PORT || 465));
  let secure = process.env.SMTP_SECURE;
  if (secure === undefined || secure === '') {
    secure = port === 465;
  } else {
    secure = secure !== 'false' && secure !== '0';
  }

  const opts = {
    host,
    port,
    secure: Boolean(secure),
    auth: { user, pass },
    connectionTimeout: 20000,
    greetingTimeout: 20000,
    socketTimeout: 25000,
  };
  if (port === 587 && !opts.secure) {
    opts.requireTLS = true;
  }
  return nodemailer.createTransport(opts);
}
let transporter = buildTransporter();

async function sendOtpMail(to, name, code, purpose) {
  const subjects = {
    register: 'MalikYayin dogrulama kodun: ' + code,
    reset: 'MalikYayin sifre sifirlama kodu: ' + code,
    login: 'MalikYayin giris kodun: ' + code,
  };
  const subject = subjects[purpose] || ('MalikYayin kod: ' + code);
  const html = otpEmailHtml(name || String(to).split('@')[0], code);
  const text = 'MalikYayin dogrulama kodun: ' + code + ' (10 dakika gecerli). Siteye yaz.';

  // From: ASCII only — Türkçe karakter Gmail'de bazen düşürür
  let from = (process.env.MAIL_FROM || process.env.SMTP_USER || 'MalikYayin <noreply@malikyayin.com>').trim();
  from = from.replace(/[^\x00-\x7F]/g, ''); // non-ASCII temizle
  if (!from.includes('@')) {
    const u = (process.env.SMTP_USER || '').trim();
    from = u ? ('MalikYayin <' + u + '>') : from;
  }

  console.log('[OTP] gonderiliyor', { to, purpose, code }); // Vercel Logs'ta görünür

  // ---- 1) Resend (tercih — Vercel'de en güvenilir) ----
  const resendKey = (process.env.RESEND_API_KEY || '').trim();
  if (resendKey) {
    try {
      const resendFrom = (process.env.RESEND_FROM || from || 'MalikYayin <onboarding@resend.dev>').trim();
      const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + resendKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: resendFrom,
          to: [to],
          subject,
          html,
          text,
        }),
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok) {
        console.log('Mail OK (Resend)', { to, id: data.id });
        return { ok: true, messageId: data.id, via: 'resend' };
      }
      console.error('Resend hata:', r.status, data);
      // SMTP'ye düş
    } catch (e) {
      console.error('Resend exception:', e.message || e);
    }
  }

  // ---- 2) SMTP (Gmail) ----
  if (!transporter) transporter = buildTransporter();
  if (!transporter) {
    const msg = 'E-posta gönderilemedi. RESEND_API_KEY veya SMTP_USER/SMTP_PASS ekle.';
    console.error(msg);
    if (process.env.OTP_DEBUG === '1') {
      console.log('[OTP_DEBUG]', to, code, purpose);
      return { ok: true, debug: true, code };
    }
    return { ok: false, error: msg };
  }

  const mailOpts = {
    from,
    to,
    subject,
    html,
    text,
    replyTo: (process.env.SMTP_USER || '').trim() || undefined,
    headers: { 'X-Mailer': 'MalikYayin', 'X-Priority': '1' },
  };

  try {
    const info = await transporter.sendMail(mailOpts);
    console.log('Mail OK (SMTP)', { to, messageId: info.messageId, response: info.response });
    return { ok: true, messageId: info.messageId, via: 'smtp' };
  } catch (err) {
    console.error('SMTP 465 hata:', err && (err.response || err.message));
    try {
      const alt = buildTransporter(587);
      if (alt) {
        const info2 = await alt.sendMail(mailOpts);
        transporter = alt;
        console.log('Mail OK (SMTP 587)', { to, messageId: info2.messageId });
        return { ok: true, messageId: info2.messageId, via: 'smtp587' };
      }
    } catch (err2) {
      console.error('SMTP 587 hata:', err2 && (err2.response || err2.message));
    }
    let detail = err && (err.response || err.message) ? String(err.response || err.message) : 'SMTP hatasi';
    if (/Invalid login|EAUTH|535/i.test(detail)) {
      detail = 'Gmail reddetti. App Password dogru mu?';
    }
    if (process.env.OTP_DEBUG === '1') {
      console.log('[OTP_DEBUG fallback]', to, code);
      return { ok: true, debug: true, code, error: detail };
    }
    return { ok: false, error: 'Kod gonderilemedi: ' + detail };
  }
}

// Teşhis — tarayıcıda aç: /api/health/mail
app.get('/api/health/mail', async (req, res) => {
  const host = !!(process.env.SMTP_HOST || '').trim();
  const user = !!(process.env.SMTP_USER || '').trim();
  const pass = !!(process.env.SMTP_PASS || '').trim();
  const out = {
    ok: false,
    env: {
      SMTP_HOST: host,
      SMTP_USER: user,
      SMTP_PASS: pass,
      SMTP_PORT: process.env.SMTP_PORT || '(default 465)',
      SMTP_SECURE: process.env.SMTP_SECURE || '(auto)',
      MAIL_FROM: !!(process.env.MAIL_FROM || '').trim(),
    },
  };
  if (!host || !user || !pass) {
    out.error = 'SMTP env eksik';
    return res.status(500).json(out);
  }
  try {
    if (!transporter) transporter = buildTransporter();
    await transporter.verify();
    out.ok = true;
    out.message = 'SMTP baglantisi basarili';
    res.json(out);
  } catch (err) {
    out.error = String(err && err.message ? err.message : err);
    res.status(500).json(out);
  }
});

// Gerçek test maili gönder (sadece SMTP_USER adresine)
app.post('/api/health/mail-test', async (req, res) => {
  const user = (process.env.SMTP_USER || '').trim();
  if (!user) return res.status(500).json({ ok: false, error: 'SMTP_USER yok' });
  const code = genCode();
  const mail = await sendOtpMail(user, 'Test', code, 'register');
  if (!mail.ok) {
    return res.status(500).json({ ok: false, error: mail.error, hint: 'Vercel Logs + Spam klasörünü kontrol et' });
  }
  res.json({
    ok: true,
    message: 'Test kodu ' + user + ' adresine gönderildi. Gelen kutusu + Spam bak.',
    messageId: mail.messageId || null,
    // Sadece test endpoint — kodu da göster (inbox gelmezse debug)
    debugCode: code,
  });
});



function otpEmailHtml(name, code) {
  return `
  <div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#1a1a1a;background:#ffffff">
    <p style="margin:0 0 4px;font-size:13px;color:#888">MalikYayın</p>
    <h2 style="margin:0 0 16px;color:#1a1a1a">Merhaba ${name},</h2>
    <p style="margin:0 0 12px;line-height:1.5">Kayıt / doğrulama kodun aşağıda. Bu kodu sitedeki alana yaz.</p>
    <div style="font-size:34px;font-weight:700;letter-spacing:8px;background:#fff5f0;border:1px solid #ffd4c4;padding:18px 20px;border-radius:12px;text-align:center;margin:20px 0;color:#c2410c">${code}</div>
    <p style="margin:0;line-height:1.5">Kod <b>10 dakika</b> geçerlidir. Sen istemediysen bu maili yok say.</p>
    <p style="color:#999;font-size:12px;margin-top:28px">MalikYayın — TikTok LIVE Overlay<br>Bu otomatik bir mesajdır.</p>
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
    <a href="${APK_DOWNLOAD_URL}" style="display:inline-block;background:linear-gradient(135deg,#FF6B4A,#FFB020);color:#1A0A06;padding:14px 22px;border-radius:10px;font-weight:700;text-decoration:none">
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

function createOtpToken(data) {
  // data: { purpose, email, code, exp, name?, passwordHash? }
  const body = Buffer.from(JSON.stringify(data)).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(body).digest('hex').slice(0, 32);
  return `${body}.${sig}`;
}

function readOtpToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const i = token.lastIndexOf('.');
  const body = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expect = crypto.createHmac('sha256', JWT_SECRET).update(body).digest('hex').slice(0, 32);
  if (sig !== expect) return null;
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!data || !data.exp || Date.now() > data.exp) return null;
    return data;
  } catch {
    return null;
  }
}


function genLicenseKey() {
  const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `MY-${seg()}-${seg()}-${seg()}`;
}

// ============================================================
// CAPTCHA — Google reCAPTCHA v2 (opsiyonel) + basit "robot değilim" token
// Env: RECAPTCHA_SECRET_KEY, RECAPTCHA_SITE_KEY (frontend config.js)
// ============================================================
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET_KEY || '';

function createCheckboxToken() {
  const expiresAt = Date.now() + 10 * 60 * 1000;
  const nonce = crypto.randomBytes(8).toString('hex');
  const payload = `cb.${expiresAt}.${nonce}`;
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex').slice(0, 24);
  return Buffer.from(`${payload}.${sig}`).toString('base64url');
}

function verifyCheckboxToken(token) {
  if (!token) return false;
  try {
    const raw = Buffer.from(String(token), 'base64url').toString('utf8');
    const parts = raw.split('.');
    if (parts.length !== 4 || parts[0] !== 'cb') return false;
    const [, expStr, nonce, sig] = parts;
    const payload = `cb.${expStr}.${nonce}`;
    const expect = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex').slice(0, 24);
    if (sig !== expect) return false;
    if (Date.now() > Number(expStr)) return false;
    return true;
  } catch {
    return false;
  }
}

async function verifyRecaptcha(responseToken, remoteip) {
  if (!RECAPTCHA_SECRET) return { ok: false, skip: true };
  if (!responseToken) return { ok: false, error: 'Robot doğrulamasını tamamla.' };
  try {
    const params = new URLSearchParams();
    params.set('secret', RECAPTCHA_SECRET);
    params.set('response', String(responseToken));
    if (remoteip) params.set('remoteip', remoteip);
    const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const data = await r.json();
    if (data.success) return { ok: true };
    return { ok: false, error: 'Robot doğrulaması başarısız, tekrar dene.' };
  } catch (e) {
    console.error('reCAPTCHA error:', e.message);
    return { ok: false, error: 'Robot doğrulaması kontrol edilemedi.' };
  }
}

// Honeypot + hız koruması (botlar gizli alanı doldurur / anında submit eder)
function checkHoneypot(body) {
  const traps = [
    body?.website,
    body?.url,
    body?.company,
    body?.fax,
    body?.hp_field,
    body?.honeypot,
  ];
  for (const v of traps) {
    if (v !== undefined && v !== null && String(v).trim() !== '') {
      return { ok: false, error: 'İstek reddedildi.' };
    }
  }
  // Sadece GERÇEK (geçmişte) formStartedAt varsa hız kontrolü yap
  const started = Number(body?.formStartedAt || body?._t || 0);
  if (started > 1000000000000) {
    const elapsed = Date.now() - started;
    // Saat farkı toleransı: -30sn .. +2saat
    if (elapsed >= -30000 && elapsed < 800) {
      return { ok: false, error: 'Çok hızlı gönderim, 1 sn bekle.' };
    }
    if (elapsed > 2 * 60 * 60 * 1000) {
      return { ok: false, error: 'Oturum zaman aşımı, sayfayı yenile.' };
    }
  }
  return { ok: true };
}

async function consumeCaptcha(body, req) {
  // 1) Google reCAPTCHA
  if (RECAPTCHA_SECRET) {
    const token = body?.recaptchaToken || body?.captchaAnswer || '';
    const v = await verifyRecaptcha(token, req?.ip);
    if (v.ok) return { ok: true };
    if (!v.skip) return { ok: false, error: v.error || 'Robot doğrulaması gerekli.' };
  }
  // 2) Yerel "Ben robot değilim" checkbox token
  const cb = body?.captchaId || body?.checkboxToken || '';
  const checked = body?.captchaAnswer === '1' || body?.captchaAnswer === 'true' || body?.notRobot === true;
  if (!checked) return { ok: false, error: '“Ben robot değilim” kutusunu işaretle.' };
  if (!verifyCheckboxToken(cb)) {
    return { ok: false, error: 'Doğrulama süresi doldu, kutuyu yeniden işaretle.' };
  }
  return { ok: true };
}

app.get('/api/captcha', (req, res) => {
  res.json({
    ok: true,
    mode: RECAPTCHA_SECRET ? 'recaptcha' : 'checkbox',
    id: createCheckboxToken(),
    question: 'Ben robot değilim',
  });
});

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
// CAPTCHA
// ============================================================
// ============================================================
// KAYIT — adım 1: bilgileri al, e-postaya kod gönder
// ============================================================
app.post('/api/auth/register', otpLimiter, async (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const name = String(req.body?.name || '').trim();
  const password = String(req.body?.password || '');
  const password2 = String(req.body?.password2 || req.body?.passwordConfirm || '');
  const hp = checkHoneypot(req.body);
  if (!hp.ok) return res.status(400).json({ error: hp.error });

  const cap = await consumeCaptcha(req.body, req);
  if (!cap.ok) return res.status(400).json({ error: cap.error });

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

  const code = genCode();
  const expiresAt = Date.now() + 10 * 60 * 1000;
  const passwordHash = hashPassword(password);
  const otpToken = createOtpToken({
    purpose: 'register',
    email,
    name,
    passwordHash,
    code,
    exp: expiresAt,
  });

  // Yerel/db yedek (tek instance)
  try {
    db.get('otps').remove({ email }).write();
    db.get('otps').push({ email, code, expiresAt, attempts: 0, purpose: 'register', name, passwordHash }).write();
  } catch (e) {}

  const mail = await sendOtpMail(email, name, code, 'register');
  if (!mail.ok) {
    try { db.get('otps').remove({ email }).write(); } catch (e) {}
    return res.status(500).json({ error: mail.error || 'Kod gonderilemedi, SMTP ayarlarini kontrol edin.' });
  }
    const payload = {
    ok: true,
    needCode: true,
    otpToken,
    message: 'Dogrulama kodu e-postana gonderildi. Spam / Gereksiz klasorunu de kontrol et.',
    via: mail.via || null,
  };
  // Gecici: Vercel env OTP_RETURN_CODE=1 yaparsan kod JSON'da da gelir (sadece test icin)
  if (process.env.OTP_RETURN_CODE === '1' || process.env.OTP_DEBUG === '1' || mail.debug) {
    payload.devCode = code;
  }
  if (mail.debug && process.env.OTP_DEBUG === '1') payload.debugCode = code;
  res.json(payload);
});

// ============================================================
// KAYIT — adım 2: kodu doğrula, hesabı oluştur
// ============================================================
app.post('/api/auth/register-verify', otpLimiter, async (req, res) => {
  const hp = checkHoneypot(req.body);
  if (!hp.ok) return res.status(400).json({ error: hp.error });
  const email = String(req.body?.email || '').toLowerCase().trim();
  const code = String(req.body?.code || '');
  const otpToken = String(req.body?.otpToken || '');

  if (!email || !code) {
    return res.status(400).json({ error: 'E-posta ve kod gerekli.' });
  }

  let name = email.split('@')[0];
  let passwordHash = null;

  const tokenData = readOtpToken(otpToken);
  if (tokenData && tokenData.purpose === 'register' && tokenData.email === email) {
    if (String(tokenData.code) !== String(code)) {
      return res.status(400).json({ error: 'Kod hatalı.' });
    }
    name = tokenData.name || name;
    passwordHash = tokenData.passwordHash;
  } else {
    const record = db.get('otps').find({ email }).value();
    if (!record || record.purpose !== 'register') {
      return res.status(400).json({ error: 'Önce kayıt formunu doldurup kod iste.' });
    }
    if (record.attempts >= 5) {
      return res.status(429).json({ error: 'Çok fazla yanlış deneme. Kayıdı yeniden başlat.' });
    }
    if (Date.now() > record.expiresAt) {
      return res.status(400).json({ error: 'Kodun süresi doldu, kaydı yeniden başlat.' });
    }
    if (record.code !== String(code)) {
      db.get('otps').find({ email }).assign({ attempts: record.attempts + 1 }).write();
      return res.status(400).json({ error: 'Kod hatalı.' });
    }
    name = record.name || name;
    passwordHash = record.passwordHash;
  }

  if (!passwordHash) {
    return res.status(400).json({ error: 'Kayıt oturumu geçersiz, yeniden başlat.' });
  }

  if (db.get('users').find({ email }).value()) {
    try { db.get('otps').remove({ email }).write(); } catch (e) {}
    return res.status(400).json({ error: 'Bu e-posta zaten kayıtlı.' });
  }

  const user = {
    id: crypto.randomUUID(),
    email,
    name,
    passwordHash,
    createdAt: Date.now(),
    license: null,
  };
  try { db.get('otps').remove({ email }).write(); } catch (e) {}
  db.get('users').push(user).write();
  await saveDb();

  const token = issueUserToken(user);
  res.json({ ok: true, token, user: publicUser(user) });
});

// ============================================================
// GİRİŞ — e-posta + şifre
// ============================================================
app.post('/api/auth/login', otpLimiter, async (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const password = String(req.body?.password || '');
  const hp = checkHoneypot(req.body);
  if (!hp.ok) return res.status(400).json({ error: hp.error });

  const cap = await consumeCaptcha(req.body, req);
  if (!cap.ok) return res.status(400).json({ error: cap.error });

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
  const hp = checkHoneypot(req.body);
  if (!hp.ok) return res.status(400).json({ error: hp.error });

  const cap = await consumeCaptcha(req.body, req);
  if (!cap.ok) return res.status(400).json({ error: cap.error });

  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'Geçerli bir e-posta adresi girin.' });
  }

  const user = db.get('users').find({ email }).value();
  if (!user) {
    return res.status(404).json({ error: 'Bu e-posta ile kayıtlı hesap bulunamadı.' });
  }

  const code = genCode();
  const expiresAt = Date.now() + 10 * 60 * 1000;
  const otpToken = createOtpToken({ purpose: 'reset', email, code, exp: expiresAt });

  try {
    db.get('otps').remove({ email }).write();
    db.get('otps').push({ email, code, expiresAt, attempts: 0, purpose: 'reset' }).write();
  } catch (e) {}

  const displayName = user.name || email.split('@')[0];

  const mail = await sendOtpMail(email, displayName, code, 'reset');
  if (!mail.ok) {
    return res.status(500).json({ error: mail.error || 'Kod gonderilemedi, SMTP ayarlarini kontrol edin.' });
  }
  const payload = { ok: true, otpToken, message: 'Sifre sifirlama kodu e-postana gonderildi. Spam klasorune bak.', via: mail.via || null };
  if (process.env.OTP_RETURN_CODE === '1' || process.env.OTP_DEBUG === '1' || mail.debug) {
    payload.devCode = code;
  }
  if (mail.debug && process.env.OTP_DEBUG === '1') payload.debugCode = code;
  res.json(payload);
});

// ============================================================
// ŞİFRE SIFIRLAMA — kod + yeni şifre
// ============================================================
app.post('/api/auth/reset-password', otpLimiter, async (req, res) => {
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

  const otpToken = String(req.body?.otpToken || '');
  const tokenData = readOtpToken(otpToken);
  let codeOk = false;
  if (tokenData && tokenData.purpose === 'reset' && tokenData.email === email) {
    codeOk = String(tokenData.code) === String(code);
    if (!codeOk) return res.status(400).json({ error: 'Kod hatalı.' });
  } else {
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
    codeOk = true;
  }

  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

  try { db.get('otps').remove({ email }).write(); } catch (e) {}
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
    saveDb().catch(()=>{});
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

app.get('/api/auth/me', auth, async (req, res) => {
  await ensureDb();
  let user = db.get('users').find({ email: req.user.email }).value();
  if (!user) {
    // JWT var ama DB soğuk — stub (kalıcı DB yüklenene kadar)
    return res.json({
      email: req.user.email,
      name: (req.user.email || '').split('@')[0],
      license: null,
      _stub: true,
    });
  }
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

// ============================================================
// UYGULAMA ZORUNLU GÜNCELLEME (sürüm numarası yok)
// GET  /api/app/update          → herkese açık (APK kontrol eder)
// POST /api/admin/app/update    → admin aç/kapa + metin
// Env: FORCE_APP_UPDATE=1  → env ile de zorla açılabilir
// ============================================================
app.get('/api/app/update', (req, res) => {
  const cfg = readAppConfig();
  const envForce = process.env.FORCE_APP_UPDATE === '1' || process.env.FORCE_APP_UPDATE === 'true';
  const force = envForce || cfg.forceUpdate === true;
  res.json({
    force,
    title: cfg.title || 'Zorunlu Güncelleme',
    message: cfg.message || 'Uygulama güncellendi ve bazı hatalar düzeltildi.',
    note: cfg.note || "MalikYayın'ı kullanmaya devam etmek için güncelleme zorunludur.",
    button: cfg.button || 'Şimdi Güncelle',
    url: cfg.url || process.env.APP_URL || 'https://malik-yayin-alpha.vercel.app/',
  });
});

app.post('/api/admin/app/update', adminAuth, (req, res) => {
  const body = req.body || {};
  const prev = readAppConfig();
  const next = {
    forceUpdate: body.forceUpdate === true || body.forceUpdate === 'true' || body.force === true,
    title: String(body.title || prev.title || 'Zorunlu Güncelleme').slice(0, 80),
    message: String(body.message || prev.message || 'Uygulama güncellendi ve bazı hatalar düzeltildi.').slice(0, 400),
    note: String(body.note || prev.note || "MalikYayın'ı kullanmaya devam etmek için güncelleme zorunludur.").slice(0, 300),
    button: String(body.button || prev.button || 'Şimdi Güncelle').slice(0, 40),
    url: String(body.url || prev.url || process.env.APP_URL || 'https://malik-yayin-alpha.vercel.app/').slice(0, 300),
  };
  writeAppConfig(next);
  res.json({ ok: true, appConfig: next });
});

app.get('/api/admin/app/update', adminAuth, (req, res) => {
  res.json({ ok: true, appConfig: readAppConfig() });
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

app.post('/api/admin/license/revoke', adminAuth, async (req, res) => {
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
  await saveDb();
  res.json({ ok: true, message: 'Lisans iptal edildi.' });
});

app.post('/api/admin/license/grant', adminAuth, async (req, res) => {
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
  await saveDb();
  res.json({ ok: true, key, days, email });
});


app.post('/api/admin/license/extend', adminAuth, async (req, res) => {
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
  await saveDb();
  res.json({ ok: true, license: lic, message: extraDays + ' gün eklendi.' });
});

app.post('/api/admin/license/reactivate', adminAuth, async (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'E-posta gerekli.' });
  const user = db.get('users').find({ email }).value();
  if (!user || !user.license || !user.license.key) {
    return res.status(404).json({ error: 'Kullanıcı veya lisans bulunamadı.' });
  }
  const lic = { ...user.license, active: true };
  db.get('users').find({ email }).assign({ license: lic }).write();
  await saveDb();
  res.json({ ok: true, message: 'Lisans yeniden aktif.', license: lic });
});

app.post('/api/admin/user/delete', adminAuth, async (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'E-posta gerekli.' });
  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
  db.get('users').remove({ email }).write();
  await saveDb();
  res.json({ ok: true, message: 'Kullanıcı silindi.' });
});

app.post('/api/admin/user/rename', adminAuth, async (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const name = String(req.body?.name || '').trim();
  if (!email || !name) return res.status(400).json({ error: 'E-posta ve ad gerekli.' });
  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
  db.get('users').find({ email }).assign({ name }).write();
  await saveDb();
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
app.post('/api/payment/paytr/callback', async (req, res) => {
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
      await saveDb();
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
