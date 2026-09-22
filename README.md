# trelic companion encryption and session protocol

This repository publishes the cryptography and phone relay client used with
trelic desktop 1.1.33. The files are copied from the release sources. Their
SHA-256 hashes are recorded in `release-files.json`.

| File | Purpose |
| --- | --- |
| `desktop-remoteCrypto.js` | Node implementation of key derivation and authenticated encryption |
| `companion-crypto.js` | Matching WebCrypto implementation |
| `companion-relayClient.js` | Phone connection lifecycle, authenticated sessions, requests, and events |
| `remoteProtocol.js` | Shared freshness and duplicate-message checks |

Load the browser files in this order: `companion-crypto.js`,
`remoteProtocol.js`, `companion-relayClient.js`.

## Encryption and relay authentication

A randomly generated 32-byte pairing secret is the trust root. Both endpoints
use HKDF-SHA256 with the fixed salt `trelic-remote-v1` and distinct info labels
to derive the channel identifier, AES-256-GCM encryption key, and relay-auth
key. Malformed secrets are rejected before derivation.

The encrypted envelope is `{v:1, iv, data}`. IVs are random 12-byte values;
`data` holds ciphertext and the GCM authentication tag. Modified ciphertext
and incorrect keys fail authentication.

The relay receives the channel identifier and a separate derived auth key
from the desktop, then checks challenge proofs for joining clients. That key
does not reveal the encryption key. The relay also receives presence/keepalive
messages and kind-only push signals. It can observe metadata such as message
timing and size, but not the encrypted command or response contents.

## Session protocol 2

Decrypting successfully is not sufficient to accept an application message.
The phone starts an encrypted handshake with an unpredictable request ID,
phone session, stable phone ID, nonce, and timestamp. The desktop's matching
response binds the exchange to its current randomly generated session.

Commands, responses, and events carry these session identifiers. Responses
must match an outstanding unpredictable request ID. Both endpoints reject
expired messages, future timestamps outside the 75-second clock window,
repeated message identifiers/nonces, and messages from previous sessions.
These checks apply to application messages in both directions.

Concurrent connection attempts share one operation. Disconnecting invalidates
unfinished key derivation, encryption, requests, and old socket callbacks.
Malformed messages and failed sends do not execute application commands.

Desktop and companion must both support protocol 2. There is no fallback to
accepting legacy application messages. After upgrading the desktop, reopen
the companion so its service worker can load the current files.

## Verification

Run `npm test` with Node 20 or later. No dependencies are required. The tests
use local fake sockets and real WebCrypto/Node encryption. They cover stale,
duplicate, unsolicited, and old-session messages, concurrent connections,
disconnect during derivation/encryption, malformed envelopes, and failed sends.
They do not connect to brokerage accounts or submit trades.

Compare the browser files with the live companion:

- https://trelictech.com/app/crypto.js
- https://trelictech.com/app/relayClient.js
- https://trelictech.com/app/remoteProtocol.js

The desktop command handlers and trading application are not included in this
repository. Publishing these files is not a claim of a complete security audit.

## Limits

Anyone who obtains the pairing secret can impersonate a paired endpoint and
decrypt captured traffic. Session binding does not provide forward secrecy.
Re-pairing rotates the secret. Device security and pairing-secret storage
remain part of the trust boundary. Delivery can fail or be delayed; encryption
cannot guarantee network availability.

The cryptographic primitives are unchanged in 1.1.33. This update strengthens
message freshness, session binding, and connection handling.

Published under the MIT license. See `LICENSE`.
