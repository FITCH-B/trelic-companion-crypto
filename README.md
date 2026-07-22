# trelic — companion encryption

This repository contains the **complete encryption and relay-client code** used
by the [trelic trading app](https://trelictech.com) to talk to its mobile
companion. It is published so the claim below can be checked rather than
trusted.

**The claim:** the relay server that carries messages between your desktop and
your phone cannot read them, and cannot recover the key that would let it.

You do not have to take that on faith. Both halves of the implementation are
here.

## What's in here

| File | Runs on | What it does |
|---|---|---|
| `desktop-remoteCrypto.js` | Desktop app (Node) | Generates the pairing secret, derives the channel id and key, encrypts/decrypts envelopes |
| `companion-crypto.js` | Phone (WebCrypto) | The browser mirror of the above — must derive byte-identical values |
| `companion-relayClient.js` | Phone | WebSocket client: connects to the relay, sends and receives encrypted envelopes |

Publishing both halves is deliberate: it lets you verify that the phone and the
desktop derive the same key from the same secret, and that neither one sends
anything to the relay in the clear.

## The design

One 32-byte **pairing secret** is generated on the desktop, displayed once in
Settings, and typed into the phone. Everything else is derived from it:

```
channelId = sha256("trelic-remote-channel:" + secret)[:32 hex]
key       = sha256("trelic-remote-key:"     + secret)      (AES-256-GCM)
envelope  = { v:1, iv:<base64>, data:<base64 ciphertext||tag> }
```

The relay is given the **`channelId`** so it knows which two devices to connect,
and the **`envelope`** to pass along. That is all it ever receives.

Because `channelId` and `key` are separate one-way derivations of the same
secret, knowing the channel id reveals nothing about the key. The relay can see
*that* your devices are talking. It cannot see *what* they say, and it cannot
work backwards from what it holds to the key or the secret.

Every message is AES-256-GCM, which is authenticated: a modified ciphertext
fails to decrypt rather than producing altered plaintext. `decrypt()` returns
`null` on any failure — wrong key, tampered data, malformed envelope — and never
throws.

## What this does *not* cover

Being precise about scope matters more than sounding secure:

- **Your broker credentials and AI API key are not in this system at all.** They
  are encrypted by your operating system's secure storage on your own machine
  and are never transmitted anywhere — not to the relay, not to trelic's
  servers. They never enter an envelope because they never leave the desktop.
- **The pairing secret is as strong as how you handle it.** Anyone who obtains
  it can read the channel. It is shown once, and you can rotate it by
  re-pairing.
- **The relay learns metadata**: that a channel exists, roughly when messages
  flow, and their size. It does not learn contents.
- **This is not an audited implementation.** It is standard primitives
  (SHA-256, AES-256-GCM) used in a straightforward way, published so it can be
  reviewed. If you find a flaw, please open an issue — that is the point of
  this repository.

## Verifying it matches what actually ships

The companion is a web app, so the code your phone runs is served directly and
can be compared against this repository:

```
https://trelictech.com/app/crypto.js
https://trelictech.com/app/relayClient.js
```

If those differ from the files here in any way that matters, that is a bug worth
reporting.

## About

trelic is a desktop app that runs AI trading strategies against your own
brokerage account. It never holds your funds and never receives your
credentials. More at [trelictech.com](https://trelictech.com).

Published under the MIT license so you can read, test, and reuse it.
