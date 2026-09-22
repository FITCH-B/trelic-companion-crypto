// Shared verbatim with the companion. Encryption authenticates content;
// these checks bind it to a fresh session and reject duplicate delivery.
(function (root) {
  const MAX_AGE_MS = 75000;
  const validId = value => typeof value === 'string' && /^[a-f0-9]{32,64}$/.test(value);
  function acceptFresh(msg, seen, now = Date.now()) {
    if (!msg || msg.protocol !== 2 || !Number.isFinite(msg.ts) || Math.abs(now - msg.ts) > MAX_AGE_MS ||
        !validId(msg.id) || !validId(msg.nonce)) return false;
    for (const [key, at] of seen) if (now - at > MAX_AGE_MS * 2) seen.delete(key);
    const nonce = `n:${msg.nonce}`, id = `i:${msg.kind}:${msg.id}`;
    if (seen.has(nonce) || seen.has(id) || seen.size >= 10000) return false;
    seen.set(nonce, now); seen.set(id, now);
    return true;
  }
  const api = { MAX_AGE_MS, validId, acceptFresh };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.TrelicRemoteProtocol = api;
})(globalThis);
