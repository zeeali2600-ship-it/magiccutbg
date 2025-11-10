// Backend proxy for ClippingMagic (upload -> download transparent PNG)
// Env vars: CLIPPINGMAGIC_ID, CLIPPINGMAGIC_SECRET
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const cors = require('cors');

const app = express();
app.use(cors({ origin: true })); // prod me apni domain set kar den

const upload = multer(); // memory storage
const CLIP_UPLOAD = 'https://clippingmagic.com/api/v1/images';

app.get('/api/ping', (req, res) => res.json({ ok: true }));

// Single call: client se file lo -> ClippingMagic pe upload -> transparent PNG download karke client ko bhej do
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
    if (!imageId) throw new Error('Upload OK but no image id returned');

    // 2) Download transparent PNG (retry thoda sa, agar processing lag rahi ho)
    const dlUrl = `https://clippingmagic.com/api/v1/images/${imageId}/download`;
    const params = { format: 'png', background: 'transparent' };

    const wait = (ms) => new Promise((r) => setTimeout(r, ms));
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
        await wait(900); // thoda wait phir try
      }
    }
    throw lastErr || new Error('Download failed after retries');
  } catch (e) {
    console.error('ClippingMagic error:', e.response ? e.response.data : e.message);
    res.status(500).json({ error: 'Processing failed', details: e.response?.data || e.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Backend running on http://localhost:' + port));
