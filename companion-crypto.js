// crypto.js -- WebCrypto mirror of the desktop's remoteCrypto.js.
// ANY change to derivations or envelope format there must be made here.
//
//   channelId = HKDF-SHA256(secret, salt, info="trelic-remote-channel")[:16 bytes] -> hex
//   key       = HKDF-SHA256(secret, salt, info="trelic-remote-key")     (32 bytes, AES-256-GCM)
//   envelope  = {v:1, iv:<b64>, data:<b64 ct||tag>}  (WebCrypto native)
//
// Both sides feed HKDF the same inputs: ikm = the UTF-8 bytes of the
// normalised 64-char hex secret, salt = "trelic-remote-v1", and the info
// label above. RFC 5869 is deterministic, so Node's hkdfSync and
// WebCrypto's deriveBits produce identical output for identical inputs --
// that equivalence is worth re-testing if either side is ever touched.
//
// The secret is validated before any derivation: an empty or malformed
// secret would otherwise produce a fixed key that anyone reading this
// file could compute. Do not remove that check.

const RemoteCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const SECRET_HEX_LEN = 64;
  const HKDF_SALT = 'trelic-remote-v1';
  const INFO_CHANNEL = 'trelic-remote-channel';
  const INFO_KEY = 'trelic-remote-key';

  function normalizeSecret(input) {
    return String(input || '').toLowerCase().replace(/[^a-f0-9]/g, '');
  }

  function requireValidSecret(secret) {
    const normalized = normalizeSecret(secret);
    if (normalized.length !== SECRET_HEX_LEN) {
      throw new Error(`Invalid pairing secret: expected ${SECRET_HEX_LEN} hex characters, got ${normalized.length}.`);
    }
    return normalized;
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

  async function hkdfBits(secret, info, bytes) {
    const normalized = requireValidSecret(secret);
    const ikm = await crypto.subtle.importKey('raw', enc.encode(normalized), 'HKDF', false, ['deriveBits']);
    return crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(HKDF_SALT), info: enc.encode(info) },
      ikm,
      bytes * 8,
    );
  }

  async function channelIdFromSecret(secret) {
    return toHex(await hkdfBits(secret, INFO_CHANNEL, 16));
  }

  async function keyFromSecret(secret) {
    const bits = await hkdfBits(secret, INFO_KEY, 32);
    return crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
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

  return { normalizeSecret, requireValidSecret, channelIdFromSecret, keyFromSecret, encrypt, decrypt, nonce };
})();
