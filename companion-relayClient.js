// relayClient.js -- the phone's connection to the desktop, via the
// relay. Owns the socket, the end-to-end encryption, request/response
// matching, reconnection, and desktop presence.
//
// Usage:
//   const client = new RelayClient({ relayUrl, secret, onState });
//   await client.connect();
//   const tasks = await client.request('get-tasks');

class RelayClient {
  constructor({ relayUrl, secret, onState, onEvent }) {
    this.relayUrl = relayUrl;
    this.secret = secret;
    this.onState = onState || (() => {});
    this.onEvent = onEvent || (() => {});
    this.ws = null;
    this.key = null;
    this.channel = null;
    this.pending = new Map(); // id -> {resolve, reject, timer}
    this.nextId = 1;
    this.desktopOnline = false;
    this.closedByUser = false;
    this.reconnectDelay = 3000;
    this.probeTimer = null;
  }

  // NO background keepalive timer, deliberately. An earlier version
  // pinged every 25s and killed the socket on a missed ack -- browser
  // timer throttling and a not-yet-restarted relay both turned that
  // into constant false disconnects on healthy connections. Half-open
  // sockets are detected by REAL traffic instead: a timed-out request
  // (the UI polls every 20s while visible) closes the socket and the
  // normal reconnect takes over. No timers, no false positives.
  //
  // ...with one gap that detection-by-traffic alone could not cover.
  // While the desktop is believed OFFLINE the UI stops issuing requests,
  // so nothing ever times out, so a half-open socket is never noticed --
  // and the 'desktop-online' message that would clear the banner can
  // never arrive on a dead socket. That is a terminal state: the app sits
  // showing "disconnected" while the desktop is up and reconnected.
  //
  // probe() covers exactly that case. It is called only when the app is
  // visible AND already showing disconnected, so it cannot fire on a
  // healthy connection and cannot recreate the false-positive problem.

  state(s) { this.onState(s); }

  async connect() {
    // One socket at a time. Calling connect() while a connection is
    // already open or mid-handshake must be a no-op -- a second socket
    // here creates a zombie whose close event flashes "reconnecting"
    // and wipes the screen even though the survivor is healthy.
    if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) return;
    this.closedByUser = false;
    // Detach any dead/closing socket completely before replacing it so
    // its late events can't reach the UI.
    if (this.ws) {
      try {
        this.ws.onopen = this.ws.onmessage = this.ws.onclose = this.ws.onerror = null;
        this.ws.close();
      } catch (e) {}
    }
    this.key = await RemoteCrypto.keyFromSecret(this.secret);
    this.channel = await RemoteCrypto.channelIdFromSecret(this.secret);
    this.state({ phase: 'connecting' });

    // Capture the socket: every handler ignores events from a socket
    // that is no longer this.ws (belt over the detach above).
    const ws = new WebSocket(this.relayUrl);
    this.ws = ws;
    ws.onopen = () => {
      if (this.ws !== ws) return;
      ws.send(JSON.stringify({ hello: { role: 'phone', channel: this.channel } }));
    };
    ws.onmessage = (ev) => {
      if (this.ws !== ws) return;
      this._onMessage(ev.data);
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this._clearProbe();
      this.state({ phase: 'disconnected', desktopOnline: false });
      this._failAll('Connection lost.');
      if (!this.closedByUser) this._scheduleReconnect();
    };
    ws.onerror = () => { /* onclose follows */ };
  }

  close() {
    this.closedByUser = true;
    this._clearProbe();
    try { if (this.ws) this.ws.close(); } catch (e) {}
  }

  // Ask the relay to prove this socket is still alive. The relay answers
  // {relay:'ka'} with {relay:'ka-ack'} (see server/src/relay.js) -- it has
  // always supported this; nothing here previously used it. No answer
  // inside the window means the path is dead, so close and let the normal
  // reconnect run.
  probe(timeoutMs = 5000) {
    if (this.closedByUser || this.probeTimer) return;
    const socket = this.ws;
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    this.probeTimer = setTimeout(() => {
      this.probeTimer = null;
      // Only act if this is still the live socket -- a reconnect may have
      // replaced it while the probe was outstanding.
      if (this.ws === socket && socket.readyState === WebSocket.OPEN) {
        try { socket.close(); } catch (e) {}
      }
    }, timeoutMs);
    try {
      socket.send(JSON.stringify({ relay: 'ka' }));
    } catch (e) {
      this._clearProbe();
      try { socket.close(); } catch (e2) {}
    }
  }

  _clearProbe() {
    if (this.probeTimer) { clearTimeout(this.probeTimer); this.probeTimer = null; }
  }

  _scheduleReconnect() {
    setTimeout(() => {
      if (!this.closedByUser) this.connect();
    }, this.reconnectDelay);
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30000);
  }

  async _onMessage(text) {
    let raw = null;
    try { raw = JSON.parse(text); } catch (e) { return; }

    // Relay housekeeping (unauthenticated presence hints).
    if (raw.relay) {
      // Any answer at all proves the socket is alive, so a pending probe
      // is satisfied by the ack specifically but also by anything else
      // arriving -- the point is liveness, not the message.
      if (raw.relay === 'ka-ack') { this._clearProbe(); return; }
      this._clearProbe();
      if (raw.relay === 'joined') {
        this.reconnectDelay = 3000;
        this.desktopOnline = Boolean(raw.desktopOnline);
        this.state({ phase: 'connected', desktopOnline: this.desktopOnline });
      } else if (raw.relay === 'desktop-online') {
        this.desktopOnline = true;
        this.state({ phase: 'connected', desktopOnline: true });
      } else if (raw.relay === 'desktop-offline') {
        this.desktopOnline = false;
        this.state({ phase: 'connected', desktopOnline: false });
      }
      return;
    }

    // Everything else must decrypt with our key or it is ignored.
    const msg = await RemoteCrypto.decrypt(this.key, raw);
    if (!msg) return;
    if (msg.kind === 'res' && this.pending.has(msg.id)) {
      const p = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.ok) p.resolve(msg.result);
      else p.reject(new Error(msg.error || 'Command failed.'));
      return;
    }
    // Desktop-initiated events (new approval, order update...) -- full
    // detail, end-to-end encrypted. The UI refreshes instantly on these.
    if (msg.kind === 'event') {
      try { this.onEvent(msg); } catch (err) { /* UI callback must not kill the socket */ }
    }
  }

  request(cmd, params = {}, timeoutMs = 15000) {
    return new Promise(async (resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        return reject(new Error('Not connected to the relay.'));
      }
      const id = this.nextId++;
      const socket = this.ws;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        // A request that never got an answer on a socket still claiming
        // to be open usually means the socket is half-open (network path
        // died silently). Close it so the normal reconnect takes over --
        // this replaces the old background keepalive with detection by
        // real traffic only.
        if (this.desktopOnline && this.ws === socket && socket.readyState === WebSocket.OPEN) {
          try { socket.close(); } catch (e) {}
        }
        reject(new Error(this.desktopOnline ? 'Desktop did not answer in time.' : 'Desktop is offline.'));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      const envelope = await RemoteCrypto.encrypt(this.key, {
        kind: 'cmd', id, cmd, params, ts: Date.now(), nonce: RemoteCrypto.nonce(),
      });
      this.ws.send(JSON.stringify(envelope));
    });
  }

  _failAll(reason) {
    for (const [, p] of this.pending) { clearTimeout(p.timer); p.reject(new Error(reason)); }
    this.pending.clear();
  }
}
