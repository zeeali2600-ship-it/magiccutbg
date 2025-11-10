// Backend proxy for ClippingMagic (simplified: direct clipped PNG)
// Env: CLIPPINGMAGIC_ID, CLIPPINGMAGIC_SECRET
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const cors = require('cors');

const app = express();
app.use(cors({ origin: true }));

const upload = multer(); // memory

app.get('/api/ping', (req, res) => res.json({ ok: true }));

// Simplified Auto Clip (format=result)
app.post('/api/remove', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image uploaded' });

    const form = new FormData();
    form.append('image', req.file.buffer, { filename: req.file.originalname });
    form.append('format', 'result');          // direct processed output
    form.append('background', 'transparent'); // transparent bg
    form.append('test', 'true');              // test mode (remove later)

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
    const firstBytes = resp.data.slice(0, 15).toString();
    if (resp.status !== 200 || firstBytes.includes('<!DOCTYPE') || firstBytes.includes('<html')) {
      return res.status(500).json({
        error: 'ClippingMagic API error',
        status: resp.status,
        hint: 'Check ID/SECRET or remove test=true when you have credits.'
      });
    }

    res.set('Content-Type', 'image/png');
    res.send(Buffer.from(resp.data));
  } catch (e) {
    console.error('Clip error:', e.response?.data || e.message);
    res.status(500).json({ error: 'Processing failed', details: e.response?.data || e.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Backend running on http://localhost:' + port));
