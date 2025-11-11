const CACHE_NAME = 'magiccutbg-v3';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './privacy.html',
  './design.png'
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);

  // Only handle GET requests
  if (req.method !== 'GET') return;

  // Bypass cache for API requests
  if (url.pathname.includes('/api/')) {
    event.respondWith(fetch(req));
    return;
  }

  // For navigations, go network-first, fallback to cached shell
  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).catch(() => caches.match('./index.html')));
    return;
  }

  // Static assets: cache-first
  event.respondWith(
    caches.match(req).then(res => res || fetch(req))
  );
});
