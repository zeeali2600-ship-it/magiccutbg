const CACHE_NAME = 'magiccutbg-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/privacy.html',
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
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => caches.match('/index.html'))
    );
    return;
  }
  event.respondWith(
    caches.match(event.request).then(res => res || fetch(event.request).catch(()=> caches.match('/index.html')))
  );
});
