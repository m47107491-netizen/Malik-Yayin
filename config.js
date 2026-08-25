// Aynı origin (Vercel veya Railway). Boş bırak = kendi domainin.
// Ayrı API kullanıyorsan: 'https://malik-yayin-production.up.railway.app'
window.MALIKYAYIN_API_BASE = '';

// PayTR mağaza onayı / canlı ödeme hazır olunca true yap.
// false iken paket al butonları "Yakında" gösterir, ödeme sayfası kilitlenir.
window.MALIKYAYIN_PAYTR_READY = false;

// Google reCAPTCHA v2 site key (boş bırakırsan yerel kutu kullanılır)
window.MALIKYAYIN_RECAPTCHA_SITE_KEY = window.MALIKYAYIN_RECAPTCHA_SITE_KEY || '';
