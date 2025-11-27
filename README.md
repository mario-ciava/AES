
# AES Encryption Library

## Overview
This repository contains a dependency-free implementation of the **Advanced Encryption Standard (AES)** written in modern JavaScript.  
The goal is to keep the code readable, auditable and easy to embed in projects where pulling in third-party crypto packages is not an option.  
All primitives – AES core, PKCS#7, SHA‑256, HMAC-SHA256, PBKDF2-HMAC – are implemented in pure JS.

## Features
- AES-128, AES-192, AES-256 (fixed 128-bit blocks).
- Modes: ECB, CBC, PCBC, CTR, CFB, OFB, GCM (with native auth tag).
- Automatic or explicit PKCS#7 padding for block modes.
- Optional PBKDF2 key derivation; MAC key is always derived separately via HMAC-SHA256 expand.
- Streaming API for CTR/CFB/OFB with hex/text inputs, no dependencies.
- Pure utility exports (`sha256`, `hmacSha256`, `pbkdf2Sha256`, `timingSafeEqualHex`, etc.).
- Large regression suite: NIST KATs, fuzzing, 256 KiB block stress test.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Configuration Options](#configuration-options)
- [Examples](#examples)
- [Running Tests](#running-tests)
- [Security Notes](#security-notes)
- [Future Work](#future-work)
- [License](#license)

## Installation
1. **Clone**
   ```bash
   git clone https://github.com/mario-ciava/AES.git
   cd AES
   ```

2. **Environment**
   - Tested with Node.js ≥ 20.18.0. Any recent Node 18+ build should work.
   - No npm install required. Everything lives in `*.mjs`.

## Usage
Import what you need from `cipher.mjs`. The default export is the `AES` class; `createAES` is a convenience factory; helper functions are exported for lower-level use.

```javascript
import {
  AES,
  createAES,
  getDefaultAESOptions,
  sha256,
  hmacSha256,
  pbkdf2Sha256,
  timingSafeEqualHex,
} from './cipher.mjs';
```

### RNG requirement
The library relies on a **secure random source**. If `globalThis.crypto.getRandomValues` is missing (e.g. some sandboxed environments), you must provide `options.rng = (len) => Uint8Array`.

### Text vs hex input
- Plaintext and keys can be supplied as UTF-8 strings or hex strings. Non-hex inputs are transparently encoded as UTF-8 hex.
- Ciphertext must be hex.

### Default behaviour
Out of the box:
- Mode: `CBC`.
- Padding: PKCS#7 enabled.
- HMAC-SHA256 on `(IV || salt || ciphertext)` using a MAC-only key derived from the provided secret.
- Random IV generated per encryption.
- No implicit key stretching unless `deriveKey` is true.
- When `mode: 'GCM'`, the library disables HMAC automatically and returns the GCM authentication tag.

## Configuration Options

| Option        | Default | Description                                                                                       | Accepted values                          |
|---------------|---------|---------------------------------------------------------------------------------------------------|------------------------------------------|
| `bits`        | 128     | Key size (drives key length checks / PBKDF2 output).                                              | `128`, `192`, `256`                      |
| `mode`        | `CBC`   | AES mode. Streaming modes ignore PKCS#7.                                                          | `'ECB'`, `'CBC'`, `'PCBC'`, `'CTR'`, `'CFB'`, `'OFB'`, `'GCM'` |
| `deriveKey`   | `false` | When true, PBKDF2-HMAC-SHA256 derives the working key.                                            | `true`, `false`                          |
| `addSalt`     | `false` | Attach a salt to outputs; mandatory when `deriveKey` is true.                                     | `true`, `false`                          |
| `usePKCS7`    | `true`  | Enable PKCS#7 padding (block modes only). When false, plaintext length must be a multiple of 16.  | `true`, `false`                          |
| `addHMAC`     | `true`  | Calculate HMAC-SHA256 (skipped automatically for GCM).                                            | `true`, `false`                          |
| `IV`          | `null`  | Initialization vector. Auto-generated if omitted (16 bytes for block/stream modes, 12/16 for GCM).| 24 or 32 hex chars                       |
| `salt`        | `null`  | Hex salt for PBKDF2. Auto-generated when `rng` is available.                                      | Even-length hex                          |
| `iterations`  | 100000  | PBKDF2 iteration count.                                                                            | Positive integer                         |
| `AAD`         | `null`  | Additional authenticated data (GCM only).                                                         | Even-length hex                          |
| `tag`         | `null`  | Authentication tag expected during GCM decrypt.                                                   | 32 hex chars (16 bytes)                  |
| `rng`         | system  | Function returning a `Uint8Array` of random bytes.                                                | `(len:number)=>Uint8Array`               |

Retrieve a copy of the defaults at runtime:
```javascript
const defaults = getDefaultAESOptions();
```

## Examples

### Basic CBC encryption with auto IV/HMAC
```javascript
import { AES } from './cipher.mjs';

const aes = new AES(); // defaults: CBC, HMAC enabled, PKCS#7 enabled

const { message, IV, HMAC } = aes.encrypt('Top secret note', 'my password');
const { message: decrypted } = aes.decrypt(message, 'my password', { IV, HMAC });

// decrypted is a hex string; convert to text if you need the original message
const text = Buffer.from(decrypted, 'hex').toString('utf8');
console.log(text);
```

### Using PBKDF2 (salt generated automatically)
```javascript
const aes = new AES();
const opts = { deriveKey: true, addSalt: true, iterations: 200000 };

const encrypted = aes.encrypt('plaintext', 'passphrase', opts);
const decrypted = aes.decrypt(encrypted.message, 'passphrase', {
  ...opts,
  IV: encrypted.IV,
  salt: encrypted.salt,
  HMAC: encrypted.HMAC,
});
```

### Authenticated AES-GCM with AAD
```javascript
const aes = new AES();
const opts = {
  mode: 'GCM',
  IV: 'cafebabefacedbaddecaf888',    // 12-byte nonce (in hex)
  AAD: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
};

const enc = aes.encrypt('Sensitive Data Here', 'ComplexKey', opts);
console.log('Ciphertext:', enc.message);
console.log('Tag:', enc.tag);

const dec = aes.decrypt(enc.message, 'ComplexKey', {
  ...opts,
  tag: enc.tag,
});
console.log('Plain (hex):', dec.message);
```

### Streaming CTR (no padding, no HMAC)
```javascript
const aes = new AES();
const key = '00112233445566778899aabbccddeeff';
const iv = '11223344556677889900aabbccddeeff';

const encStream = aes.createEncryptStream(key, { mode: 'CTR', IV: iv, addHMAC: false });
const c1 = encStream.update('streaming ');
const c2 = encStream.update('cipher');
encStream.final(); // flushes nothing (CTR is streaming)

const decStream = aes.createDecryptStream(key, { mode: 'CTR', IV: encStream.IV, addHMAC: false });
const p1 = decStream.update(c1);
const p2 = decStream.update(c2);
decStream.final();

const plainHex = p1 + p2; // hex string
console.log(Buffer.from(plainHex, 'hex').toString('utf8'));
```

### Creating a preconfigured instance
```javascript
import { createAES } from './cipher.mjs';
import { randomBytes } from 'node:crypto'; // or your own Uint8Array source

const aes256 = createAES({
  bits: 256,
  addHMAC: false,
  rng: (len) => randomBytes(len),
});

const { message } = aes256.encrypt('hex only demo', '00112233445566778899aabbccddeeff', { mode: 'ECB', usePKCS7: false });
```

### Reusing utilities
```javascript
import { sha256, hmacSha256, pbkdf2Sha256 } from './cipher.mjs';

const digest = sha256(new TextEncoder().encode('hello'));
const hmac = hmacSha256(new Uint8Array([0x00, 0x01]), new Uint8Array([0x02, 0x03]));
const derived = pbkdf2Sha256(
  new TextEncoder().encode('password'),
  new TextEncoder().encode('salt'),
  100000,
  32,
);
```

## Running Tests
Everything lives in `test.mjs`. It covers:
- NIST AES-ECB/CBC/CTR/CFB/OFB/GCM Known Answer Tests (128/192/256-bit keys).
- Regression tests for CBC/PCBC round-trips, PKCS#7 errors, missing IV, etc.
- A 256 KiB payload encryption/decryption sanity check.
- A chaos fuzz harness mixing valid/invalid option combinations.

Execute the full battery with:
```bash
node test.mjs
```

Environment variables:
- `CHAOS_ITERATIONS=1000` — increase fuzz depth.
- `CHAOS_SEED=feedface` — reproduce a specific random stream.

## Security Notes
- This project is for educational / controlled usage. Pure-JS crypto is inherently slower and more side-channel-prone than native implementations.
- There is **no Math.random fallback**. If a secure RNG is not available, the constructor throws; provide a custom `rng` that returns a `Uint8Array`.
- HMAC is enabled by default for block/stream modes; AES-GCM provides its own authentication tag and ignores `addHMAC`.
- Streaming helpers currently support CTR/CFB/OFB and intentionally disable HMAC to avoid buffering; use the buffered API when you need MACs on large payloads.

## Future Work
- Streaming API for incremental encrypt/decrypt without buffering entire payloads.
- Additional authenticated constructions (GCM-SIV, SIV, XTS) and key-wrapping helpers.
- Benchmark suite and performance tuning of GF arithmetic / GCM multiplication.

## License
See [LICENSE](./LICENSE).
