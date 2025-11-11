// Backend proxy for ClippingMagic (simplified: direct clipped PNG)
// Env: CLIPPINGMAGIC_ID, CLIPPINGMAGIC_SECRET, (optional) TRIALS_INIT
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const cors = require('cors');

const app = express();
app.use(cors({ origin: true }));

// In-memory trials (resets on server restart)
let TRIALS_LEFT = Number.parseInt(process.env.TRIALS_INIT || '3', 10);
if (Number.isNaN(TRIALS_LEFT) || TRIALS_LEFT < 0) TRIALS_LEFT = 3;

const upload = multer(); // memory

// Health
app.get('/api/ping', (req, res) => res.json({ ok: true }));

// Report remaining trials
app.get('/api/trials', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ trials: TRIALS_LEFT });
});

// Simplified Auto Clip (format=result)
app.post('/api/remove', upload.single('image'), async (req, res) => {
  try {
    // Enforce trials
    if (TRIALS_LEFT <= 0) {
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
    TRIALS_LEFT = Math.max(0, TRIALS_LEFT - 1);

    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'no-store');
    res.set('X-Trials-Left', String(TRIALS_LEFT));
    res.send(Buffer.from(resp.data));
  } catch (e) {
    console.error('Clip error:', e.response?.data || e.message);
    res.status(500).json({ error: 'Processing failed', details: e.response?.data || e.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Backend running on http://localhost:' + port));
