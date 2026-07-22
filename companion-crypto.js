// crypto.js -- WebCrypto mirror of the desktop's remoteCrypto.js.
// ANY change to derivations or envelope format there must be made here.
//
//   channelId = sha256("trelic-remote-channel:" + secret) [:32 hex]
//   key       = sha256("trelic-remote-key:" + secret)     (AES-256-GCM)
//   envelope  = {v:1, iv:<b64>, data:<b64 ct||tag>}  (WebCrypto native)

const RemoteCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function normalizeSecret(input) {
    return String(input || '').toLowerCase().replace(/[^a-f0-9]/g, '');
  }

  function toHex(buf) {
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function b64(buf) {
    let s = '';
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s);
  }

  function fromB64(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function channelIdFromSecret(secret) {
    const digest = await crypto.subtle.digest('SHA-256', enc.encode(`trelic-remote-channel:${normalizeSecret(secret)}`));
    return toHex(digest).slice(0, 32);
  }

  async function keyFromSecret(secret) {
    const digest = await crypto.subtle.digest('SHA-256', enc.encode(`trelic-remote-key:${normalizeSecret(secret)}`));
    return crypto.subtle.importKey('raw', digest, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  async function encrypt(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    // WebCrypto AES-GCM output is ciphertext||tag -- exactly the wire format.
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return { v: 1, iv: b64(iv), data: b64(ct) };
  }

  async function decrypt(key, envelope) {
    try {
      if (!envelope || envelope.v !== 1) return null;
      const iv = fromB64(envelope.iv);
      const blob = fromB64(envelope.data);
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, blob);
      return JSON.parse(dec.decode(plain));
    } catch (err) {
      return null;
    }
  }

  function nonce() {
    return toHex(crypto.getRandomValues(new Uint8Array(8)));
  }

  return { normalizeSecret, channelIdFromSecret, keyFromSecret, encrypt, decrypt, nonce };
})();
