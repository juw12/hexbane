// Service worker: makes Gardu installable and lets it open offline.
// Only same-origin files are cached; the app makes no third-party requests.

const CACHE_NAME = "gardu-shell-v1";
const SHELL_FILES = [
  "./",
  "index.html",
  "styles.css",
  "engine.js",
  "scan.js",
  "scanview.js",
  "rules.json",
  "store.js",
  "app.js",
  "manifest.webmanifest",
  "policies/cad-copilot.json",
  "policies/cad-copilot.eval.json",
  "policies/bank-support.json",
  "policies/store-support.json",
  "icons/icon-192.png",
  "icons/icon-512.png",
  "icons/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => (key.startsWith("scopeguard-") || key.startsWith("gardu-")) && key !== CACHE_NAME).map((key) => caches.delete(key)))
    )
  );
  self.clients.claim();
});

// Network first (so updates show up), falling back to the cache when offline.
self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET" || new URL(request.url).origin !== self.location.origin) {
    return;
  }
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request).then((cached) => cached || caches.match("index.html")))
  );
});
