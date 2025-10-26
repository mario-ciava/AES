// Utility helpers, no deps.

// normalizeHex: trim, drop prefix, lowercase.
export const normalizeHex = (value, { allowEmpty = false } = {}) => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed.length) return allowEmpty && value.length === 0 ? '' : null;
  const hasPrefix = /^0x/i.test(trimmed);
  const cleaned = trimmed.toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
  if (!cleaned.length) return allowEmpty && !hasPrefix ? '' : null;
  return /^[0-9a-f]+$/.test(cleaned) ? cleaned : null;
};

// isHex: canonical check.
export const isHex = (s) => normalizeHex(s, { allowEmpty: true }) !== null;

// toHexByte: byte -> hex.
export const toHexByte = (n) => (n & 0xff).toString(16).padStart(2, '0');

// bytesToHex: Uint8Array -> hex.
export const bytesToHex = (u8) => {
  if (!(u8 instanceof Uint8Array)) throw new Error('bytesToHex: expected Uint8Array');
  return Array.from(u8, toHexByte).join('');
};

// hexToBytes: hex -> Uint8Array.
export const hexToBytes = (hex) => {
  if (hex instanceof Uint8Array) return new Uint8Array(hex);
  const normalized = normalizeHex(hex, { allowEmpty: true });
  if (normalized === null || normalized.length % 2 !== 0) throw new Error('hexToBytes: invalid hex');
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(normalized.substr(i * 2, 2), 16);
  return out;
};

// Lazy TextEncoder/TextDecoder fetch.
const getTextEncoder = () => (typeof TextEncoder !== 'undefined' ? new TextEncoder() : null);
const getTextDecoder = () => (typeof TextDecoder !== 'undefined' ? new TextDecoder() : null);

// textToBytes: UTF-8 encode.
export const textToBytes = (str) => {
  const te = getTextEncoder();
  if (te) return te.encode(str);
  if (typeof Buffer !== 'undefined') return Uint8Array.from(Buffer.from(str, 'utf-8'));
  throw new Error('No UTF-8 encoder available');
};

// bytesToText: UTF-8 decode.
export const bytesToText = (u8) => {
  const td = getTextDecoder();
  if (td) return td.decode(u8);
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('utf-8');
  throw new Error('No UTF-8 decoder available');
};

// textToHex: text -> hex.
export const textToHex = (str) => bytesToHex(textToBytes(str));
// hexToText: hex -> text.
export const hexToText = (hex) => bytesToText(hexToBytes(hex));

// concatBytes: append arrays.
export const concatBytes = (a, b) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
};

// xorBytes: bytewise XOR.
export const xorBytes = (a, b) => {
  if (a.length !== b.length) throw new Error('xorBytes: length mismatch');
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
};

// pkcs7PadBytes: strict PKCS#7.
export const pkcs7PadBytes = (plain, blockSize = 16) => {
  const mod = plain.length % blockSize;
  const padLen = mod === 0 ? blockSize : (blockSize - mod);
  const out = new Uint8Array(plain.length + padLen);
  out.set(plain, 0);
  out.fill(padLen, plain.length);
  return out;
};

// pkcs7UnpadBytes: validate padding.
export const pkcs7UnpadBytes = (padded, blockSize = 16) => {
  if (padded.length === 0 || padded.length % blockSize !== 0) throw new Error('Bad PKCS7 length');
  const padLen = padded[padded.length - 1];
  if (padLen < 1 || padLen > blockSize) throw new Error('Bad PKCS7 padding');
  for (let i = 1; i <= padLen; i++) if (padded[padded.length - i] !== padLen) throw new Error('Bad PKCS7 padding');
  return padded.subarray(0, padded.length - padLen);
};

// addPKCS7Hex: hex pad helper.
export const addPKCS7Hex = (hex, blockSize = 16) => bytesToHex(pkcs7PadBytes(hexToBytes(hex), blockSize));
// removePKCS7Hex: hex unpad helper.
export const removePKCS7Hex = (hex, blockSize = 16) => bytesToHex(pkcs7UnpadBytes(hexToBytes(hex), blockSize));

// SHA-256 primitives.
const ROTR = (x, n) => (x >>> n) | (x << (32 - n));
const Σ0 = (x) => ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
const Σ1 = (x) => ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
const σ0 = (x) => ROTR(x, 7) ^ ROTR(x, 18) ^ (x >>> 3);
const σ1 = (x) => ROTR(x, 17) ^ ROTR(x, 19) ^ (x >>> 10);
const Ch = (x, y, z) => (x & y) ^ (~x & z);
const Maj = (x, y, z) => (x & y) ^ (x & z) ^ (y & z);

// SHA-256 constants.
const K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

// sha256: digest bytes.
export const sha256 = (msgBytes) => {
  let h0=0x6a09e667, h1=0xbb67ae85, h2=0x3c6ef372, h3=0xa54ff53a,
      h4=0x510e527f, h5=0x9b05688c, h6=0x1f83d9ab, h7=0x5be0cd19;

  const ml = msgBytes.length * 8;

  // append padding bit
  const withOne = new Uint8Array(msgBytes.length + 1);
  withOne.set(msgBytes); withOne[msgBytes.length] = 0x80;

  const k = (56 - (withOne.length % 64) + 64) % 64;
  const padded = new Uint8Array(withOne.length + k + 8);
  padded.set(withOne);

  const dv = new DataView(padded.buffer);
  const n = padded.length;
  dv.setUint32(n - 8, Math.floor(ml / 0x100000000)); // high bits
  dv.setUint32(n - 4, ml >>> 0);                      // low bits

  const W = new Uint32Array(64);

  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) {
      const j = i + t * 4;
      W[t] = (padded[j] << 24) | (padded[j+1] << 16) | (padded[j+2] << 8) | (padded[j+3]);
    }
    for (let t = 16; t < 64; t++) W[t] = (σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]) >>> 0;
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let t = 0; t < 64; t++) {
      const T1 = (h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]) >>> 0;
      const T2 = (Σ0(a) + Maj(a,b,c)) >>> 0;
      h = g; g = f; f = e;
      e = (d + T1) >>> 0;
      d = c; c = b; b = a;
      a = (T1 + T2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const dvOut = new DataView(out.buffer);
  dvOut.setUint32(0, h0); dvOut.setUint32(4, h1); dvOut.setUint32(8, h2); dvOut.setUint32(12, h3);
  dvOut.setUint32(16, h4); dvOut.setUint32(20, h5); dvOut.setUint32(24, h6); dvOut.setUint32(28, h7);
  return out;
};

// sha256Hex hashes hex input directly.
export const sha256Hex = (hex) => bytesToHex(sha256(hexToBytes(hex)));
// sha256Text hashes UTF-8 text straight to hex.
export const sha256Text = (str) => bytesToHex(sha256(textToBytes(str)));

// SHA-256 uses 64-byte blocks.
const blockSize = 64;

// hmacSha256: RFC2104.
export const hmacSha256 = (keyBytes, dataBytes) => {
  let k = keyBytes;
  if (k.length > blockSize) k = sha256(k);
  if (k.length < blockSize) {
    const kk = new Uint8Array(blockSize); kk.set(k); k = kk;
  }
  const o = new Uint8Array(blockSize), i = new Uint8Array(blockSize);
  for (let idx = 0; idx < blockSize; idx++) { o[idx] = 0x5c ^ k[idx]; i[idx] = 0x36 ^ k[idx]; }
  return sha256(concatBytes(o, sha256(concatBytes(i, dataBytes))));
};

// hmacSha256Hex: hex wrapper.
export const hmacSha256Hex = (keyHex, dataHex) =>
  bytesToHex(hmacSha256(hexToBytes(keyHex), hexToBytes(dataHex)));

// int32BE: big-endian 32-bit.
const int32BE = (i) => new Uint8Array([ (i>>>24)&0xff, (i>>>16)&0xff, (i>>>8)&0xff, i&0xff ]);

// pbkdf2Sha256: RFC 8018.
export const pbkdf2Sha256 = (passwordBytes, saltBytes, iterations, dkLen) => {
  if (!Number.isInteger(iterations) || iterations <= 0) throw new Error('PBKDF2: invalid iterations');
  if (!Number.isInteger(dkLen) || dkLen <= 0) throw new Error('PBKDF2: invalid dkLen');

  const hLen = 32;
  const l = Math.ceil(dkLen / hLen);
  const r = dkLen - (l - 1) * hLen;
  const DK = new Uint8Array(dkLen);

  for (let i = 1; i <= l; i++) {
    let U = hmacSha256(passwordBytes, concatBytes(saltBytes, int32BE(i)));
    let T = U.slice();
    for (let j = 2; j <= iterations; j++) {
      U = hmacSha256(passwordBytes, U);
      for (let k = 0; k < T.length; k++) T[k] ^= U[k];
    }
    const destPos = (i - 1) * hLen;
    const len = (i === l) ? r : hLen;
    DK.set(T.subarray(0, len), destPos);
  }
  return DK;
};

// pbkdf2Sha256Hex: hex wrapper.
export const pbkdf2Sha256Hex = (passwordHex, saltHex, iterations, dkLen) =>
  bytesToHex(pbkdf2Sha256(hexToBytes(passwordHex), hexToBytes(saltHex), iterations, dkLen));

// timingSafeEqualHex: constant-time compare.
export const timingSafeEqualHex = (aHex, bHex) => {
  if (!isHex(aHex) || !isHex(bHex)) return false;
  if (aHex.length !== bHex.length) return false;
  let diff = 0;
  for (let i = 0; i < aHex.length; i++) diff |= aHex.charCodeAt(i) ^ bHex.charCodeAt(i);
  return diff === 0;
};
