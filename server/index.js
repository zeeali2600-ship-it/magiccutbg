// Backend proxy for ClippingMagic (simplified: direct clipped PNG)
// Env: CLIPPINGMAGIC_ID, CLIPPINGMAGIC_SECRET, (optional) TRIALS_INIT
// Optional (recommended for per-user trials):
//   UPSTASH_REDIS_URL, UPSTASH_REDIS_TOKEN
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const cors = require('cors');

// NEW (minimal): cookies + optional Redis for per-user trials
const cookieParser = require('cookie-parser');
let Redis = null;
try {
  // load only if configured
  Redis = require('@upstash/redis').Redis;
} catch (_) { /* optional */ }
const { v4: uuidv4 } = (() => {
  try { return require('uuid'); } catch (_) { return { v4: () => Math.random().toString(36).slice(2) }; }
})();

const app = express();
app.use(cookieParser());

// CORS (same as before, but allow credentials if using cookies)
app.use(cors({ origin: true, credentials: true }));

// In-memory global fallback trials (resets on server restart)
// Will be used only if Redis not configured
let TRIALS_LEFT = Number.parseInt(process.env.TRIALS_INIT || '3', 10);
if (Number.isNaN(TRIALS_LEFT) || TRIALS_LEFT < 0) TRIALS_LEFT = 3;

// Optional Redis client
let redis = null;
if (process.env.UPSTASH_REDIS_URL && process.env.UPSTASH_REDIS_TOKEN && Redis) {
  redis = new Redis({
    url: process.env.UPSTASH_REDIS_URL,
    token: process.env.UPSTASH_REDIS_TOKEN,
  });
}
const DEFAULT_TRIALS = Number.parseInt(process.env.TRIALS_INIT || '3', 10) || 3;

// Cookie settings
const COOKIE_NAME = 'uid';
const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'Lax',
  secure: true, // GH Pages + Render both https
  maxAge: 365 * 24 * 60 * 60 * 1000
};

const upload = multer(); // memory

// Helper: ensure per-user identity and trials (if Redis enabled)
async function ensureUserAndTrials(req, res) {
  // If Redis not configured, return global fallback
  if (!redis) return { mode: 'global', trials: TRIALS_LEFT };

  // Per-user mode
  let uid = req.cookies[COOKIE_NAME];
  if (!uid) {
    uid = uuidv4();
    res.cookie(COOKIE_NAME, uid, COOKIE_OPTIONS);
  }
  const key = `trial:${uid}`;
  let trials = await redis.get(key);
  if (trials === null || trials === undefined) {
    await redis.set(key, DEFAULT_TRIALS, { ex: 7 * 24 * 60 * 60 }); // optional expiry
    trials = DEFAULT_TRIALS;
  }
  return { mode: 'per-user', uid, key, trials: Number(trials) };
}

// Health
app.get('/api/ping', (req, res) => res.json({ ok: true }));

// Report remaining trials
app.get('/api/trials', async (req, res) => {
  try {
    const info = await ensureUserAndTrials(req, res);
    res.set('Cache-Control', 'no-store');
    res.json({ trials: info.trials });
  } catch (e) {
    res.status(500).json({ error: 'Trials fetch failed' });
  }
});

// Simplified Auto Clip (format=result)
app.post('/api/remove', upload.single('image'), async (req, res) => {
  try {
    const info = await ensureUserAndTrials(req, res);

    // Enforce trials
    if (info.trials <= 0) {
      return res.status(402).json({ error: 'No trials left' });
    }

    if (!req.file) return res.status(400).json({ error: 'No image uploaded' });

    // Optional size guard (8 MB)
    const maxBytes = 8 * 1024 * 1024;
    if (req.file.size > maxBytes) {
      return res.status(413).json({ error: 'File too large (max 8 MB)' });
    }

    const form = new FormData();
    form.append('image', req.file.buffer, { filename: req.file.originalname });
    form.append('format', 'result');          // direct processed output
    form.append('background', 'transparent'); // transparent bg

    const auth = {
      username: process.env.CLIPPINGMAGIC_ID,
      password: process.env.CLIPPINGMAGIC_SECRET,
    };

    const resp = await axios.post('https://clippingmagic.com/api/v1/images', form, {
      auth,
      headers: form.getHeaders(),
      responseType: 'arraybuffer',
      timeout: 60000,
      validateStatus: s => true
    });

    // If API returned HTML (auth error) detect quickly
    const firstBytes = Buffer.from(resp.data).slice(0, 32).toString();
    if (resp.status !== 200 || firstBytes.includes('<!DOCTYPE') || firstBytes.includes('<html')) {
      return res.status(500).json({
        error: 'ClippingMagic API error',
        status: resp.status,
        hint: 'Check ID/SECRET or ensure account has credits.'
      });
    }

    // Decrement trials on success
    let left = info.trials;
    if (info.mode === 'per-user') {
      // Redis per-user atomic decrement
      left = await redis.decr(info.key);
      if (left < 0) {
        await redis.set(info.key, 0);
        left = 0;
      }
    } else {
      // Global fallback
      TRIALS_LEFT = Math.max(0, TRIALS_LEFT - 1);
      left = TRIALS_LEFT;
    }

    // Headers (added Access-Control-Expose-Headers for X-Trials-Left)
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'no-store');
    res.set('X-Trials-Left', String(left));
    res.set('Access-Control-Expose-Headers', 'X-Trials-Left');

    res.send(Buffer.from(resp.data));
  } catch (e) {
    console.error('Clip error:', e.response?.data || e.message);
    res.status(500).json({ error: 'Processing failed', details: e.response?.data || e.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Backend running on http://localhost:' + port));
