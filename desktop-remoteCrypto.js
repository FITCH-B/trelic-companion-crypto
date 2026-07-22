// remoteCrypto.js
//
// Crypto for the remote-control channel between this desktop app and
// the trelic mobile companion. Pure Node built-ins; the phone mirrors
// these exact constructions with WebCrypto (see mobile/www/crypto.js) --
// any change here MUST be made there too.
//
// DESIGN: one 32-byte pairing SECRET (shown once in Settings, entered
// on the phone) is the entire trust root. From it both sides derive two
// independent values with HKDF-SHA256 (RFC 5869), using a different
// `info` label for each:
//   - channelId  = HKDF(secret, info="trelic-remote-channel")[:16 bytes]
//       The relay routes by channelId. One-way: the relay learns the
//       channel but can never recover the secret or the key from it.
//   - key        = HKDF(secret, info="trelic-remote-key") (32 bytes)
//       AES-256-GCM key for end-to-end encryption of every message.
//
// WHY HKDF AND NOT sha256(label + secret): a single hash of a
// high-entropy secret is sound in practice, but HKDF is the construction
// actually designed for deriving multiple independent keys from one
// secret. It gives proper domain separation via `info`, sidesteps the
// length-extension discussion that any prefix-hash construction invites,
// and is what a reviewer expects to see. There is no reason to make
// someone reason about whether the homemade version is safe.
//
// THE SECRET IS VALIDATED BEFORE USE. Deriving from an empty or
// malformed secret would produce a fixed key that anyone reading this
// file could compute, so both derivations reject anything that is not
// exactly 64 hex characters after normalisation. Do not remove this.
//
// Envelope on the wire: {v:1, iv:<b64>, data:<b64 ciphertext||16-byte tag>}
// (ciphertext and tag concatenated -- WebCrypto's native AES-GCM output
// format, so the browser side needs no reassembly).
//
// NONCE BOUND: IVs are 12 random bytes per message. With random IVs,
// AES-GCM should stay under ~2^32 messages per key (NIST SP 800-38D) --
// a repeated IV under the same key is catastrophic, not merely weak. At
// one message per second that bound is ~136 years, so it is not a
// practical concern here, but re-pairing rotates the secret if you ever
// want a fresh key.
//
// NO FORWARD SECRECY: the pairing secret is static for the life of the
// pairing, so anyone who obtains it can decrypt previously captured
// traffic. A handshake (e.g. X25519 per session) would fix that; it is
// not implemented because the threat model here is an honest-but-curious
// relay plus a secret the user types once, not a global adversary
// recording traffic for later.
//
// Replay protection lives in the PLAINTEXT (ts + nonce, checked by the
// receiver in remoteControl.js), so a captured envelope is useless even
// within the channel.

const crypto = require('crypto');

const SECRET_BYTES = 32;
const SECRET_HEX_LEN = SECRET_BYTES * 2;
const GCM_TAG_BYTES = 16;

// Fixed, non-secret salt. HKDF permits an empty salt; a constant one
// keeps this deployment's derivations distinct from any other use of the
// same secret material.
const HKDF_SALT = 'trelic-remote-v1';
const INFO_CHANNEL = 'trelic-remote-channel';
const INFO_KEY = 'trelic-remote-key';

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

// Throws rather than returning a usable-looking key for junk input. A
// caller that hands us a corrupted secret has a bug; deriving a
// predictable key from it would turn that bug into a silent break of the
// channel's confidentiality.
function requireValidSecret(secret) {
  const normalized = normalizePairingSecret(secret);
  if (normalized.length !== SECRET_HEX_LEN) {
    throw new Error(`Invalid pairing secret: expected ${SECRET_HEX_LEN} hex characters, got ${normalized.length}.`);
  }
  return normalized;
}

function hkdf(secret, info, bytes) {
  const normalized = requireValidSecret(secret);
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(normalized, 'utf8'), Buffer.from(HKDF_SALT, 'utf8'), Buffer.from(info, 'utf8'), bytes));
}

function channelIdFromSecret(secret) {
  return hkdf(secret, INFO_CHANNEL, 16).toString('hex');
}

function keyFromSecret(secret) {
  return hkdf(secret, INFO_KEY, 32);
}

function encrypt(key, obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { v: 1, iv: iv.toString('base64'), data: Buffer.concat([ct, tag]).toString('base64') };
}

// Returns the decrypted object, or null for anything invalid -- wrong
// key, tampered ciphertext, malformed envelope. Never throws, so a
// caller cannot accidentally build an error oracle out of it.
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
  requireValidSecret,
  channelIdFromSecret,
  keyFromSecret,
  encrypt,
  decrypt,
};
