require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

// ---------- DB (basit JSON dosya veritabanı; büyürse Postgres/Mongo'ya taşıyın) ----------
const adapter = new FileSync('db.json');
const db = low(adapter);
db.defaults({ users: [], otps: [], orders: [] }).write();

// ---------- App ----------
const app = express();
app.use(cors());
app.use(bodyParser.json());

// PayTR bildirim endpoint'i form-urlencoded gönderir
app.use('/api/payment/paytr/callback', bodyParser.urlencoded({ extended: false }));

const PORT = process.env.PORT || 3000;

// Kod isteklerinde kötüye kullanımı önlemek için sınırlama
const otpLimiter = rateLimit({ windowMs: 60 * 1000, max: 3, message: { error: 'Çok fazla istek, lütfen biraz sonra tekrar deneyin.' } });

// ---------- Mail gönderici ----------
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
    <div style="font-size:32px;font-weight:700;letter-spacing:6px;background:#f5f0fa;padding:16px 20px;border-radius:12px;text-align:center;margin:20px 0">${code}</div>
    <p>Bu kod <b>10 dakika</b> boyunca geçerlidir. Eğer bu girişi sen yapmadıysan, şifreni değiştirmeni öneririz.</p>
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

// ============================================================
// 1) E-POSTA İLE KAYIT / GİRİŞ — kod gönder
// ============================================================
app.post('/api/auth/send-code', otpLimiter, async (req, res) => {
  const { email, name } = req.body;
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'Geçerli bir e-posta adresi girin.' });
  }

  const code = genCode();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 dakika

  // Aynı e-posta için eski kodları temizle, yenisini kaydet
  db.get('otps').remove({ email }).write();
  db.get('otps').push({ email, code, expiresAt, attempts: 0 }).write();

  const displayName = name || (db.get('users').find({ email }).value()?.name) || email.split('@')[0];

  try {
    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: email,
      subject: 'MalikYayın giriş kodun',
      html: otpEmailHtml(displayName, code),
    });
    res.json({ ok: true, message: 'Doğrulama kodu e-postana gönderildi.' });
  } catch (err) {
    console.error('Mail gönderim hatası:', err.message);
    res.status(500).json({ error: 'Kod gönderilemedi, SMTP ayarlarını kontrol edin.' });
  }
});

// ============================================================
// 2) KODU DOĞRULA — hesap yoksa oluştur, JWT oturum döndür
// ============================================================
app.post('/api/auth/verify-code', (req, res) => {
  const { email, code, name } = req.body;
  const record = db.get('otps').find({ email }).value();

  if (!record) return res.status(400).json({ error: 'Önce bir kod iste.' });
  if (record.attempts >= 5) return res.status(429).json({ error: 'Çok fazla yanlış deneme. Yeni kod iste.' });
  if (Date.now() > record.expiresAt) return res.status(400).json({ error: 'Kodun süresi doldu, yeni kod iste.' });
  if (record.code !== String(code)) {
    db.get('otps').find({ email }).assign({ attempts: record.attempts + 1 }).write();
    return res.status(400).json({ error: 'Kod hatalı.' });
  }

  // Doğrulandı — kullanılan kodu temizle
  db.get('otps').remove({ email }).write();

  let user = db.get('users').find({ email }).value();
  if (!user) {
    user = { id: crypto.randomUUID(), email, name: name || email.split('@')[0], createdAt: Date.now(), license: null };
    db.get('users').push(user).write();
  }

  const token = jwt.sign({ uid: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ ok: true, token, user: { email: user.email, name: user.name, license: user.license } });
});

// ---------- Oturum kontrolü ----------
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Giriş gerekli.' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Oturum geçersiz, tekrar giriş yap.' });
  }
}

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.get('users').find({ email: req.user.email }).value();
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
  res.json({ email: user.email, name: user.name, license: user.license });
});

// ============================================================
// 3) PAYTR — ödeme başlat (iFrame API)
//    Dokümantasyon: https://dev.paytr.com/odeme-entegrasyonu/ideal-entegrasyon
// ============================================================
app.post('/api/payment/paytr/init', auth, async (req, res) => {
  try {
    const user = db.get('users').find({ email: req.user.email }).value();
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

    const merchant_id = process.env.PAYTR_MERCHANT_ID;
    const merchant_key = process.env.PAYTR_MERCHANT_KEY;
    const merchant_salt = process.env.PAYTR_MERCHANT_SALT;

    const merchant_oid = 'MY' + Date.now() + crypto.randomBytes(2).toString('hex');
    const email = user.email;
    const payment_amount = Math.round(Number(process.env.LICENSE_PRICE_TRY || 70) * 100); // kuruş cinsinden
    const user_ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0').toString().split(',')[0].trim();
    const user_basket = Buffer.from(JSON.stringify([[`MalikYayın ${process.env.LICENSE_DURATION_DAYS || 30} Günlük Lisans`, process.env.LICENSE_PRICE_TRY || '70.00', 1]])).toString('base64');
    const no_installment = 1;
    const max_installment = 0;
    const currency = 'TL';
    const test_mode = process.env.PAYTR_TEST_MODE || '1';

    // Sipariş kaydı (bekliyor)
    db.get('orders').push({
      merchant_oid, email, amount: payment_amount, status: 'pending', createdAt: Date.now(),
    }).write();

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

    const { data } = await axios.post('https://www.paytr.com/odeme/api/get-token', params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    if (data.status === 'success') {
      res.json({ ok: true, token: data.token, iframeUrl: `https://www.paytr.com/odeme/guvenli/${data.token}` });
    } else {
      res.status(400).json({ error: 'PayTR token alınamadı: ' + (data.reason || 'bilinmeyen hata') });
    }
  } catch (err) {
    console.error('PayTR init hatası:', err.response?.data || err.message);
    res.status(500).json({ error: 'Ödeme başlatılamadı.' });
  }
});

// ============================================================
// 4) PAYTR — bildirim (callback) — ödeme sonucu burada doğrulanır
//    Bu endpoint PayTR panelinde "Bildirim URL" olarak tanımlanmalı.
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
    console.error('PayTR callback: hash uyuşmuyor, sahte istek olabilir.');
    return res.status(400).send('PAYTR notification failed: bad hash');
  }

  const order = db.get('orders').find({ merchant_oid }).value();
  if (order && order.status === 'pending') {
    if (status === 'success') {
      const key = genLicenseKey();
      const expiresAt = Date.now() + Number(process.env.LICENSE_DURATION_DAYS || 30) * 24 * 60 * 60 * 1000;
      db.get('orders').find({ merchant_oid }).assign({ status: 'success' }).write();
      db.get('users').find({ email: order.email }).assign({ license: { key, expiresAt, active: true } }).write();

      // Kullanıcıya KEY'ini e-posta ile gönder
      transporter.sendMail({
        from: process.env.MAIL_FROM,
        to: order.email,
        subject: 'MalikYayın lisans KEY’in hazır 🎉',
        html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px">
          <h2>Ödemen alındı!</h2>
          <p>Lisans KEY'in:</p>
          <div style="font-size:22px;font-weight:700;letter-spacing:2px;background:#f5f0fa;padding:14px 18px;border-radius:10px;text-align:center">${key}</div>
          <p>${process.env.LICENSE_DURATION_DAYS || 30} gün boyunca geçerlidir. Uygulamayı aç ve bu KEY ile giriş yap.</p>
        </div>`,
      }).catch((e) => console.error('KEY mail hatası:', e.message));
    } else {
      db.get('orders').find({ merchant_oid }).assign({ status: 'failed' }).write();
    }
  }

  // PayTR bu endpoint'ten düz metin "OK" bekler, aksi halde tekrar tekrar dener
  res.send('OK');
});

app.listen(PORT, () => console.log(`MalikYayın backend http://localhost:${PORT} portunda çalışıyor`));
