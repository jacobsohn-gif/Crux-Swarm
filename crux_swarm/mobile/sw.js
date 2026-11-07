self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  const data = event.data ? event.data.json() : {};
  const title = data.cell_id ? `[${data.cell_id}] Action Needed` : 'Crux-Swarm Alert';
  const options = {
    body: data.question || 'An agent in the swarm needs your input.',
    data: { question_id: data.question_id, cell_id: data.cell_id }
  };
  event.waitUntil(self.registration.showNotification(title, options));
});
