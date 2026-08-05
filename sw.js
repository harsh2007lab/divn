// ── Div Manager — Service Worker ──────────────────────────────────────────────
const CACHE_NAME = 'div-manager-v1';

// Static assets jo offline bhi kaam kare
const PRECACHE = [
  '/',
  '/manifest.json'
];

// ── Install: precache static shell ───────────────────────────────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: purana cache saaf karo ─────────────────────────────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE_NAME)
          .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch strategy ────────────────────────────────────────────────────────────
// API calls  → Network only (data hamesha fresh chahiye)
// Assets     → Network first, cache fallback
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Same-origin only — baaki ignore
  if (url.origin !== self.location.origin) return;

  // API / auth routes → pure network, SW bypass karo
  if (url.pathname.startsWith('/api/')) return;

  // Navigation requests (HTML pages) → network first, offline fallback
  if (e.request.mode === 'navigate') {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          // Fresh response mila — cache update karo
          const clone = res.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
          return res;
        })
        .catch(() =>
          // Offline — cached version do
          caches.match('/').then(r => r || new Response(
            '<h2 style="font-family:sans-serif;padding:40px;">📵 Offline — Internet se connect karo</h2>',
            { headers: { 'Content-Type': 'text/html' } }
          ))
        )
    );
    return;
  }

  // Static assets (JS, CSS, fonts, images) → cache first, network fallback
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        if (!res || res.status !== 200 || res.type === 'opaque') return res;
        const clone = res.clone();
        caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        return res;
      });
    })
  );
});
