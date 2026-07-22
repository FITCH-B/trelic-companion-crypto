// remoteCrypto.js
//
// Crypto for the remote-control channel between this desktop app and
// the trelic mobile companion. Pure Node built-ins; the phone mirrors
// these exact constructions with WebCrypto (see mobile/www/crypto.js) --
// any change here MUST be made there too.
//
// DESIGN: one 32-byte pairing SECRET (shown once in Settings, entered
// on the phone) is the entire trust root. From it both sides derive:
//   - channelId  = sha256("trelic-remote-channel:" + secret) [:32 hex]
//       The relay routes by channelId. One-way: the relay learns the
//       channel but can never recover the secret or the key from it.
//   - key        = sha256("trelic-remote-key:" + secret) (32 bytes)
//       AES-256-GCM key for end-to-end encryption of every message.
//       Different derivation label than the channel id, so knowing one
//       tells you nothing about the other.
//
// Envelope on the wire: {v:1, iv:<b64>, data:<b64 ciphertext||16-byte tag>}
// (ciphertext and tag concatenated -- WebCrypto's native AES-GCM output
// format, so the browser side needs no reassembly).
//
// Replay protection lives in the PLAINTEXT (ts + nonce, checked by the
// receiver in remoteControl.js), so a captured envelope is useless even
// within the channel.

const crypto = require('crypto');

const SECRET_BYTES = 32;
const GCM_TAG_BYTES = 16;

function generatePairingSecret() {
  return crypto.randomBytes(SECRET_BYTES).toString('hex');
}

// Human-friendly grouping for the Settings display (pure formatting --
// the phone strips whitespace before use).
function formatPairingSecret(secret) {
  return String(secret || '').replace(/(.{8})/g, '$1 ').trim();
}

function normalizePairingSecret(input) {
  return String(input || '').toLowerCase().replace(/[^a-f0-9]/g, '');
}

function channelIdFromSecret(secret) {
  return crypto.createHash('sha256').update(`trelic-remote-channel:${normalizePairingSecret(secret)}`).digest('hex').slice(0, 32);
}

function keyFromSecret(secret) {
  return crypto.createHash('sha256').update(`trelic-remote-key:${normalizePairingSecret(secret)}`).digest();
}

function encrypt(key, obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { v: 1, iv: iv.toString('base64'), data: Buffer.concat([ct, tag]).toString('base64') };
}

// Returns the decrypted object, or null for anything invalid -- wrong
// key, tampered ciphertext, malformed envelope. Never throws.
function decrypt(key, envelope) {
  try {
    if (!envelope || envelope.v !== 1) return null;
    const iv = Buffer.from(envelope.iv, 'base64');
    const blob = Buffer.from(envelope.data, 'base64');
    if (iv.length !== 12 || blob.length <= GCM_TAG_BYTES) return null;
    const ct = blob.subarray(0, blob.length - GCM_TAG_BYTES);
    const tag = blob.subarray(blob.length - GCM_TAG_BYTES);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
    return JSON.parse(plain);
  } catch (err) {
    return null;
  }
}

module.exports = {
  generatePairingSecret,
  formatPairingSecret,
  normalizePairingSecret,
  channelIdFromSecret,
  keyFromSecret,
  encrypt,
  decrypt,
};
