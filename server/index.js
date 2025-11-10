// Backend proxy for ClippingMagic (upload -> transparent PNG)
// Env vars chahiyen: CLIPPINGMAGIC_ID, CLIPPINGMAGIC_SECRET  (code me secret mat likhna)
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const cors = require('cors');

const app = express();
app.use(cors({ origin: true }));

const upload = multer(); // memory storage
const CLIP_UPLOAD = 'https://clippingmagic.com/api/v1/images';

// Health
app.get('/api/ping', (req, res) => res.json({ ok: true }));

// /api/remove: file lo -> ClippingMagic pe upload -> processed PNG download karke bhej do
app.post('/api/remove', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image uploaded' });

    // 1) Upload
    const form = new FormData();
    form.append('image', req.file.buffer, { filename: req.file.originalname });

    const auth = {
      username: process.env.CLIPPINGMAGIC_ID,
      password: process.env.CLIPPINGMAGIC_SECRET,
    };

    const up = await axios.post(CLIP_UPLOAD, form, {
      auth,
      headers: form.getHeaders(),
      timeout: 60000,
    });

    const imageId = up.data?.id || up.data?.image?.id;
    if (!imageId) throw new Error('Upload succeeded but no image id returned');

    // 2) Download transparent PNG (thoda retry)
    const dlUrl = `https://clippingmagic.com/api/v1/images/${imageId}/download`;
    const params = { format: 'png', background: 'transparent' };

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    let lastErr;
    for (let i = 0; i < 8; i++) {
      try {
        const dl = await axios.get(dlUrl, {
          auth,
          params,
          responseType: 'arraybuffer',
          timeout: 60000,
        });
        res.set('Content-Type', 'image/png');
        return res.send(Buffer.from(dl.data));
      } catch (e) {
        lastErr = e;
        await sleep(900);
      }
    }
    throw lastErr || new Error('Download failed after retries');
  } catch (e) {
    console.error('ClippingMagic error:', e.response?.data || e.message);
    res.status(500).json({ error: 'Processing failed', details: e.response?.data || e.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Backend running on http://localhost:' + port));
