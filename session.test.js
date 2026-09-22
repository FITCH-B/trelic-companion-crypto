const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const crypto = require('./desktop-remoteCrypto');
const SECRET = '0123456789abcdef'.repeat(4), key = crypto.keyFromSecret(SECRET);
const id = () => crypto.generatePairingSecret();
const tick = () => new Promise(r => setImmediate(r));
function harness() {
  const sockets = [], events = [];
  class Socket {
    static CONNECTING = 0; static OPEN = 1; static CLOSED = 3;
    constructor() { this.readyState = 0; this.sent = []; sockets.push(this); }
    send(text) { if (this.failSend) throw new Error('send failed'); this.sent.push(JSON.parse(text)); }
    close() { this.readyState = 3; this.onclose?.({ code: 1000 }); }
  }
  const ctx = { crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob, console, WebSocket: Socket,
    setTimeout: (fn, ms) => { const h = setTimeout(fn, ms); h.unref(); return h; }, clearTimeout };
  vm.createContext(ctx);
  for (const f of ['companion-crypto.js', 'remoteProtocol.js', 'companion-relayClient.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, f), 'utf8'), ctx);
  const Client = vm.runInContext('RelayClient', ctx), webCrypto = vm.runInContext('RemoteCrypto', ctx);
  const client = new Client({ relayUrl: 'wss://example.invalid', secret: SECRET, clientId: id(), onEvent: e => events.push(e) });
  const receive = msg => client._onMessage(JSON.stringify(crypto.encrypt(key, msg)));
  async function ready() {
    await client.connect(); const socket = client.ws; socket.readyState = 1;
    await client._onMessage(JSON.stringify({ relay: 'joined', desktopOnline: true }));
    const hello = crypto.decrypt(key, socket.sent.at(-1));
    await receive({ ...hello, kind: 'session-ready', desktopSession: id(), ts: Date.now(), nonce: id() });
    assert.equal(client.desktopOnline, true); return socket;
  }
  function frame(extra) { return { protocol: 2, clientId: client.clientId, clientSession: client.clientSession,
    desktopSession: client.desktopSession, id: id(), nonce: id(), ts: Date.now(), ...extra }; }
  async function sentRequest(socket) {
    for (let i = 0; i < 100; i++) { const msg = crypto.decrypt(key, socket.sent.at(-1)); if (msg?.kind === 'cmd') return msg; await tick(); }
    throw new Error('No request sent');
  }
  return { client, sockets, events, ready, receive, frame, sentRequest, webCrypto };
}

test('valid encrypted responses resolve once; stale, future, wrong-session, and unsolicited responses are rejected', async t => {
  const h = harness(); t.after(() => h.client.close()); const socket = await h.ready();
  const result = h.client.request('ping'), request = await h.sentRequest(socket);
  const response = h.frame({ kind: 'res', id: request.id, ok: true, result: { pong: true } });
  for (const bad of [{ ...response, ts: Date.now() - 76000 }, { ...response, ts: Date.now() + 76000 },
    { ...response, desktopSession: id() }, { ...response, clientSession: id() }, { ...response, id: id() }]) {
    await h.receive(bad); assert.equal(h.client.pending.size, 1);
  }
  await h.receive(response); assert.equal((await result).pong, true);
  await h.receive(response); assert.equal(h.client.pending.size, 0);
});
test('events arrive once and duplicate identifiers are rejected even with another nonce', async t => {
  const h = harness(); t.after(() => h.client.close()); await h.ready();
  const event = h.frame({ kind: 'event', event: 'notify' });
  await h.receive(event); await h.receive(event); await h.receive({ ...event, nonce: id() });
  assert.equal(h.events.length, 1);
  await h.receive(h.frame({ kind: 'event', event: 'notify' })); assert.equal(h.events.length, 2);
});
test('recorded responses and events are rejected after disconnect/reconnect', async t => {
  const h = harness(); t.after(() => h.client.close()); let socket = await h.ready();
  const pending = h.client.request('ping'), req = await h.sentRequest(socket);
  const oldResponse = h.frame({ kind: 'res', id: req.id, ok: true, result: 'old' });
  const old = h.frame({ kind: 'event', event: 'notify' });
  h.client.close(); await assert.rejects(pending, /Disconnected/);
  socket = await h.ready();
  const current = h.client.request('ping'), next = await h.sentRequest(socket);
  assert.notEqual(next.id, req.id);
  await h.receive(oldResponse); await h.receive({ ...oldResponse, id: next.id });
  assert.equal(h.client.pending.size, 1);
  await h.receive(h.frame({ kind: 'res', id: next.id, ok: true, result: 'current' }));
  assert.equal(await current, 'current');
  await h.receive(old);
  assert.equal(h.events.length, 0);
  await h.receive(h.frame({ kind: 'event', event: 'notify' })); assert.equal(h.events.length, 1);
});
test('simultaneous connects share one attempt and closing during key derivation creates no socket', async () => {
  const h = harness(), original = h.webCrypto.keyFromSecret; let release;
  h.webCrypto.keyFromSecret = () => new Promise(r => { release = () => original(SECRET).then(r); });
  const first = h.client.connect(), second = h.client.connect(); assert.equal(first, second);
  h.client.close(); await release(); await first;
  assert.equal(h.sockets.length, 0);
});
test('encryption and send failures reject and clean pending requests', async t => {
  const h = harness(); t.after(() => h.client.close()); const socket = await h.ready();
  const original = h.webCrypto.encrypt;
  h.webCrypto.encrypt = async () => { throw new Error('encryption failed'); };
  await assert.rejects(h.client.request('ping'), /encryption failed/); assert.equal(h.client.pending.size, 0);
  h.webCrypto.encrypt = original; socket.failSend = true;
  await assert.rejects(h.client.request('ping'), /send failed/); assert.equal(h.client.pending.size, 0);
});
test('disconnect during encryption rejects immediately and never sends on a replacement socket', async t => {
  const h = harness(); t.after(() => h.client.close()); const socket = await h.ready();
  const before = socket.sent.length, original = h.webCrypto.encrypt; let release;
  h.webCrypto.encrypt = (...args) => new Promise(r => { release = () => original(...args).then(r); });
  const pending = h.client.request('ping'); await tick(); h.client.close();
  await assert.rejects(pending, /Disconnected/); await release(); await tick();
  assert.equal(socket.sent.length, before); assert.equal(h.client.pending.size, 0);
});
test('malformed envelopes cannot trigger events or throw', async t => {
  const h = harness(); t.after(() => h.client.close()); await h.ready();
  for (const text of ['null', '[]', '{', '{"v":1,"iv":"bad","data":"bad"}']) await h.client._onMessage(text);
  assert.equal(h.events.length, 0);
});
