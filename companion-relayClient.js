// Authenticated companion sessions. No application message is accepted
// merely because it decrypts: it must belong to this handshake and socket.
class RelayClient {
  constructor({ relayUrl, secret, clientId, onState, onEvent }) {
    this.relayUrl = relayUrl; this.secret = secret;
    this.clientId = TrelicRemoteProtocol.validId(clientId) ? clientId : RemoteCrypto.nonce();
    this.onState = onState || (() => {}); this.onEvent = onEvent || (() => {});
    this.ws = null; this.pending = new Map(); this.seen = new Map();
    this.generation = 0; this.connecting = null; this.closedByUser = false;
    this.desktopOnline = false; this.authRejected = false; this.reconnectDelay = 3000;
    this.reconnectTimer = null; this.probeTimer = null; this.handshakeTimer = null;
    this.clientSession = null; this.desktopSession = null; this.handshakeId = null;
  }
  state(s) { try { this.onState(s); } catch (_) {} }
  connect() {
    if (this.connecting) return this.connecting;
    if (this.ws && [WebSocket.CONNECTING, WebSocket.OPEN].includes(this.ws.readyState)) return Promise.resolve();
    this.closedByUser = false;
    const generation = ++this.generation;
    this._clearReconnect();
    this.connecting = this._connect(generation).catch(err => {
      if (generation === this.generation && !this.closedByUser) this.state({ phase: 'disconnected', desktopOnline: false, error: err.message });
    }).finally(() => { if (generation === this.generation) this.connecting = null; });
    return this.connecting;
  }
  async _connect(generation) {
    const [key, channel, authKey] = await Promise.all([
      RemoteCrypto.keyFromSecret(this.secret), RemoteCrypto.channelIdFromSecret(this.secret), RemoteCrypto.authKeyFromSecret(this.secret),
    ]);
    if (generation !== this.generation || this.closedByUser) return;
    this.key = key; this.channel = channel; this.authKey = authKey;
    this.authRejected = false; this.desktopOnline = false; this.seen.clear();
    this.state({ phase: 'connecting', desktopOnline: false });
    const ws = new WebSocket(this.relayUrl); this.ws = ws;
    ws.onmessage = ev => {
      if (this.ws !== ws || generation !== this.generation) return;
      this._onMessage(ev.data, ws, generation).catch(() => {});
    };
    ws.onclose = ev => {
      if (this.ws !== ws || generation !== this.generation) return;
      this.ws = null; this._clearProbe(); this._clearHandshake();
      this.desktopOnline = false; this.desktopSession = null;
      this._failAll('Connection lost.');
      if (this.authRejected || ev?.code === 4003) {
        this.authRejected = true; this.state({ phase: 'auth-failed', desktopOnline: false }); return;
      }
      this.state({ phase: ev?.code === 4004 ? 'not-registered' : 'disconnected', desktopOnline: false });
      if (!this.closedByUser) this._scheduleReconnect();
    };
    ws.onerror = () => {};
  }
  close() {
    this.closedByUser = true; ++this.generation; this.connecting = null;
    this._clearReconnect(); this._clearProbe(); this._clearHandshake();
    const ws = this.ws; this.ws = null;
    if (ws) { ws.onopen = ws.onmessage = ws.onclose = ws.onerror = null; try { ws.close(); } catch (_) {} }
    this.desktopOnline = false; this.desktopSession = null; this.clientSession = null;
    this._failAll('Disconnected.'); this.state({ phase: 'disconnected', desktopOnline: false });
  }
  _clearReconnect() { if (this.reconnectTimer) clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
  _clearProbe() { if (this.probeTimer) clearTimeout(this.probeTimer); this.probeTimer = null; }
  _clearHandshake() { if (this.handshakeTimer) clearTimeout(this.handshakeTimer); this.handshakeTimer = null; this.handshakeId = null; }
  _scheduleReconnect() {
    if (this.reconnectTimer || this.closedByUser || this.authRejected) return;
    this.reconnectTimer = setTimeout(() => { this.reconnectTimer = null; if (!this.closedByUser) this.connect(); }, this.reconnectDelay);
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30000);
  }
  probe(timeoutMs = 5000) {
    const socket = this.ws;
    if (this.closedByUser || this.probeTimer || !socket || socket.readyState !== WebSocket.OPEN) return;
    this.probeTimer = setTimeout(() => { this.probeTimer = null; if (this.ws === socket) { try { socket.close(); } catch (_) {} } }, timeoutMs);
    try { socket.send(JSON.stringify({ relay: 'ka' })); }
    catch (_) { this._clearProbe(); try { socket.close(); } catch (_) {} }
  }
  async _beginSession(socket, generation) {
    if (this.handshakeId || this.ws !== socket || generation !== this.generation) return;
    this.desktopOnline = false; this.desktopSession = null; this.clientSession = RemoteCrypto.nonce();
    this._failAll('Starting a new authenticated desktop session.');
    const id = RemoteCrypto.nonce(), session = this.clientSession;
    this.handshakeId = id;
    this.handshakeTimer = setTimeout(() => {
      if (this.handshakeId !== id) return;
      this._clearHandshake();
      this.state({ phase: 'connected', desktopOnline: false, error: 'Update the desktop app and reconnect to establish a secure session.' });
    }, 15000);
    try {
      const envelope = await RemoteCrypto.encrypt(this.key, { protocol: 2, kind: 'session-hello', id, clientId: this.clientId,
        clientSession: session, ts: Date.now(), nonce: RemoteCrypto.nonce() });
      if (this.ws === socket && generation === this.generation && this.handshakeId === id && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(envelope));
    } catch (_) {
      if (this.handshakeId === id) {
        this._clearHandshake();
        this.state({ phase: 'connected', desktopOnline: false, error: 'Secure connection failed. Reconnect to try again.' });
      }
    }
  }
  async _onMessage(text, socket = this.ws, generation = this.generation) {
    if (!socket || socket !== this.ws || generation !== this.generation || typeof text !== 'string' || text.length > 65536) return;
    let raw; try { raw = JSON.parse(text); } catch (_) { return; }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return;
    if (raw.relay) {
      this._clearProbe();
      if (raw.relay === 'challenge' && typeof raw.nonce === 'string') {
        const proof = await RemoteCrypto.helloProof(this.authKey, raw.nonce, this.channel, 'phone');
        if (this.ws === socket && generation === this.generation && socket.readyState === WebSocket.OPEN)
          socket.send(JSON.stringify({ hello: { role: 'phone', channel: this.channel, proof } }));
      } else if (raw.relay === 'bad-auth') this.authRejected = true;
      else if (raw.relay === 'joined' || raw.relay === 'desktop-online') {
        this.reconnectDelay = 3000;
        this.state({ phase: 'connected', desktopOnline: false });
        if (raw.relay === 'desktop-online' || raw.desktopOnline) await this._beginSession(socket, generation);
      } else if (raw.relay === 'desktop-offline') {
        this.desktopOnline = false; this.desktopSession = null; this._clearHandshake(); this._failAll('Desktop is offline.');
        this.state({ phase: 'connected', desktopOnline: false });
      }
      return;
    }
    const msg = await RemoteCrypto.decrypt(this.key, raw);
    if (this.ws !== socket || generation !== this.generation || !msg || msg.clientId !== this.clientId || msg.clientSession !== this.clientSession) return;
    if (msg.kind === 'session-ready') {
      if (!this.handshakeId || msg.id !== this.handshakeId || !TrelicRemoteProtocol.validId(msg.desktopSession) || !TrelicRemoteProtocol.acceptFresh(msg, this.seen)) return;
      this._clearHandshake(); this.desktopSession = msg.desktopSession; this.desktopOnline = true;
      this.state({ phase: 'connected', desktopOnline: true }); return;
    }
    if (!this.desktopOnline || msg.desktopSession !== this.desktopSession || !['res', 'event'].includes(msg.kind)) return;
    if (msg.kind === 'res' && (!this.pending.has(msg.id) || typeof msg.ok !== 'boolean')) return;
    if (!TrelicRemoteProtocol.acceptFresh(msg, this.seen)) return;
    if (msg.kind === 'res') {
      const p = this.pending.get(msg.id); this.pending.delete(msg.id); clearTimeout(p.timer);
      if (msg.ok) p.resolve(msg.result); else p.reject(new Error(msg.error || 'Command failed.'));
    } else { try { this.onEvent(msg); } catch (_) {} }
  }
  request(cmd, params = {}, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
      const socket = this.ws, generation = this.generation, desktopSession = this.desktopSession, clientSession = this.clientSession;
      if (!socket || socket.readyState !== WebSocket.OPEN || !this.desktopOnline || !desktopSession) return reject(new Error('No authenticated desktop session. Reconnect and update both apps.'));
      const id = RemoteCrypto.nonce();
      const timer = setTimeout(() => {
        this.pending.delete(id); reject(new Error('Desktop did not answer in time.'));
        if (this.ws === socket && generation === this.generation) { try { socket.close(); } catch (_) {} }
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      Promise.resolve().then(() => RemoteCrypto.encrypt(this.key, { protocol: 2, kind: 'cmd', id, cmd, params,
        clientId: this.clientId, clientSession, desktopSession, ts: Date.now(), nonce: RemoteCrypto.nonce() })).then(envelope => {
        if (!this.pending.has(id)) return;
        if (this.ws !== socket || generation !== this.generation || this.desktopSession !== desktopSession || this.clientSession !== clientSession || socket.readyState !== WebSocket.OPEN) throw new Error('Connection changed before sending.');
        socket.send(JSON.stringify(envelope));
      }).catch(err => {
        const p = this.pending.get(id); if (!p) return;
        this.pending.delete(id); clearTimeout(p.timer); p.reject(err);
      });
    });
  }
  _failAll(reason) { for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error(reason)); } this.pending.clear(); }
}
