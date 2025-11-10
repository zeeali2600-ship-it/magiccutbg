const CACHE_NAME = 'magiccutbg-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/design.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  // For navigation requests, try network first then fallback to cache
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => caches.match('/index.html'))
    );
    return;
  }
  // For other requests, respond with cache-first
  event.respondWith(
    caches.match(event.request).then(res => res || fetch(event.request).catch(()=> caches.match('/index.html')))
  );
});
