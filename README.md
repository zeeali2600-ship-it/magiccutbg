# MagicCutBG

1‑click background removal with a tiny Node backend + static frontend.

## Live
- Backend: https://magiccutbg-server.onrender.com
- Health: https://magiccutbg-server.onrender.com/api/ping → {"ok":true}
- Frontend: GitHub Pages (this repo)

## Quick Start (Local)
- Server
  - cd server
  - npm ci
  - Set env: CLIPPINGMAGIC_ID, CLIPPINGMAGIC_SECRET, optional TRIALS_INIT=3
  - node index.js  → http://localhost:3000
- Frontend
  - Open index.html (or serve statically)

## API
- GET /api/ping → { ok: true }
- GET /api/trials → { trials: number }
- POST /api/remove
  - body: form-data with field image (file)
  - returns: image/png (processed)
  - headers: X-Trials-Left: <remaining>
  - limits: max 8 MB

## Trials (Free Attempts)
- Server keeps trials in memory (reset on server restart).
- Change initial count: set env TRIALS_INIT (e.g. 10) → Restart service.
- Reset to fresh: Render → magiccutbg-server → Restart OR Manual Deploy → Deploy latest commit.

## Reviewer Test (MS Dev etc.)
1) Open /api/ping → {"ok":true}
2) Frontend: try 3 images → all should work.
3) 4th try → “Trials finished” (HTTP 402) expected.

## Notes
- Service Worker never caches /api/* (always hits live backend).
- Frontend reads trials from server and uses header X-Trials-Left (exposed via Access-Control-Expose-Headers).
- If backend sleeps, frontend warms up with /api/ping on load.
