// AES core with local primitives.

import { rCon, sBoxReverse, genSBoxValue } from './assets.mjs';
import { normalizeHex, textToHex as utf8ToHex } from './prototypeExtensions.mjs';

// --- hex/byte helpers ---
const isHex = (s) => normalizeHex(s, { allowEmpty: true }) !== null;
const toHexByte = (n) => (n & 0xff).toString(16).padStart(2, '0');
const bytesToHex = (u8) => Array.from(u8, toHexByte).join('');
const hexToBytes = (hex) => {
  if (hex instanceof Uint8Array) return new Uint8Array(hex);
  const normalized = normalizeHex(hex, { allowEmpty: true });
  if (normalized === null || normalized.length % 2 !== 0) throw new Error('Invalid hex input');
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(normalized.substr(i * 2, 2), 16);
  return out;
};
const concatBytes = (a, b) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
};
const xorBytes = (a, b) => {
  if (a.length !== b.length) throw new Error('xor: length mismatch');
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
};
const xorBlock = (a, b) => {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
  return out;
};

const inc32 = (block) => {
  const out = new Uint8Array(block);
  for (let i = 15; i >= 12; i--) {
    out[i] = (out[i] + 1) & 0xff;
    if (out[i] !== 0) break;
  }
  return out;
};

const inc32InPlace = (block) => {
  for (let i = 15; i >= 12; i--) {
    block[i] = (block[i] + 1) & 0xff;
    if (block[i] !== 0) break;
  }
  return block;
};

const shiftRightOne = (block) => {
  const out = new Uint8Array(block.length);
  let carry = 0;
  for (let i = 0; i < block.length; i++) {
    const byte = block[i];
    out[i] = ((byte >>> 1) | (carry << 7)) & 0xff;
    carry = byte & 1;
  }
  return out;
};

const encodeLengthBlock = (aBits, cBits) => {
  const out = new Uint8Array(16);
  const view = new DataView(out.buffer);
  const highA = Math.floor(aBits / 0x100000000);
  const lowA = aBits >>> 0;
  const highC = Math.floor(cBits / 0x100000000);
  const lowC = cBits >>> 0;
  view.setUint32(0, highA);
  view.setUint32(4, lowA);
  view.setUint32(8, highC);
  view.setUint32(12, lowC);
  return out;
};

const gcmMultiply = (X, Y) => {
  let Z = new Uint8Array(16);
  let V = new Uint8Array(Y);
  for (let i = 0; i < 128; i++) {
    const xi = (X[i >>> 3] >>> (7 - (i & 7))) & 1;
    if (xi) Z = xorBlock(Z, V);
    const lsb = V[15] & 1;
    V = shiftRightOne(V);
    if (lsb) V[0] ^= 0xe1;
  }
  return Z;
};

const processBlocks = (data) => {
  if (data.length === 0) return [];
  const blocks = [];
  for (let i = 0; i < data.length; i += 16) {
    const chunk = data.subarray(i, i + 16);
    if (chunk.length === 16) blocks.push(new Uint8Array(chunk));
    else {
      const pad = new Uint8Array(16);
      pad.set(chunk, 0);
      blocks.push(pad);
    }
  }
  return blocks;
};

const ghash = (H, A, C) => {
  let X = new Uint8Array(16);
  const blocksA = processBlocks(A);
  for (const block of blocksA) {
    X = gcmMultiply(xorBlock(X, block), H);
  }
  const blocksC = processBlocks(C);
  for (const block of blocksC) {
    X = gcmMultiply(xorBlock(X, block), H);
  }
  const lenBlock = encodeLengthBlock(A.length * 8, C.length * 8);
  X = gcmMultiply(xorBlock(X, lenBlock), H);
  return X;
};

const buildJ0 = (H, ivBytes) => {
  if (ivBytes.length === 12) {
    const J0 = new Uint8Array(16);
    J0.set(ivBytes, 0);
    J0[15] = 1;
    return J0;
  }
  return ghash(H, new Uint8Array(0), ivBytes);
};

const ensureHexString = (value, { label, allowEmpty, allowTextFallback }) => {
  if (value instanceof Uint8Array) {
    const hex = bytesToHex(value);
    if (!hex.length && !allowEmpty) throw new Error(`${label} cannot be empty`);
    return hex;
  }
  if (value === null || value === undefined) throw new Error(`${label} is required`);
  const str = typeof value === 'string' ? value : String(value);
  const normalized = normalizeHex(str, { allowEmpty });
  if (normalized !== null) {
    if (!normalized.length && !allowEmpty) throw new Error(`${label} cannot be empty`);
    if (normalized.length % 2 !== 0) throw new Error(`${label} hex string must have an even length`);
    return normalized;
  }
  if (!allowTextFallback) throw new Error(`${label} must be hex`);
  const hex = utf8ToHex(str);
  if (!hex.length && !allowEmpty) throw new Error(`${label} cannot be empty`);
  return hex;
};

const defaultRandomBytes = (length) => {
  const out = new Uint8Array(length);
  const crypto = globalThis.crypto;
  if (crypto && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(out);
    return out;
  }
  throw new Error('Secure RNG unavailable: provide options.rng returning Uint8Array');
};

const BASE_DEFAULTS = Object.freeze({
  bits: 128,
  mode: 'CBC',
  deriveKey: false,
  addSalt: false,
  usePKCS7: true,
  addHMAC: true,
  salt: null,
  IV: null,
  HMAC: null,
  iterations: 100000,
  rng: defaultRandomBytes,
  AAD: null,
  tag: null,
});

export const getDefaultAESOptions = () => ({ ...BASE_DEFAULTS });

// --- PKCS#7 helpers ---
const pkcs7Pad = (plain, blockSize = 16) => {
  const mod = plain.length % blockSize;
  const padLen = mod === 0 ? blockSize : (blockSize - mod);
  const out = new Uint8Array(plain.length + padLen);
  out.set(plain, 0);
  out.fill(padLen, plain.length);
  return out;
};
const pkcs7Unpad = (padded, blockSize = 16) => {
  if (padded.length === 0 || padded.length % blockSize !== 0) throw new Error('Bad PKCS7 length');
  const padLen = padded[padded.length - 1];
  if (padLen < 1 || padLen > blockSize) throw new Error('Bad PKCS7 padding');
  for (let i = 1; i <= padLen; i++) if (padded[padded.length - i] !== padLen) throw new Error('Bad PKCS7 padding');
  return padded.subarray(0, padded.length - padLen);
};

// --- SHA-256 primitives ---
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

export const sha256 = (msgBytes) => {
  // init state
  let h0=0x6a09e667, h1=0xbb67ae85, h2=0x3c6ef372, h3=0xa54ff53a,
      h4=0x510e527f, h5=0x9b05688c, h6=0x1f83d9ab, h7=0x5be0cd19;

  const ml = msgBytes.length * 8;

  // pad message
  const withOne = new Uint8Array(msgBytes.length + 1);
  withOne.set(msgBytes); withOne[msgBytes.length] = 0x80;

  let k = (56 - (withOne.length % 64) + 64) % 64; // pad to 56 mod 64
  const padded = new Uint8Array(withOne.length + k + 8);
  padded.set(withOne);

  const dv = new DataView(padded.buffer);
  const totalLen = padded.length;
  dv.setUint32(totalLen - 8, Math.floor(ml / 0x100000000)); // high bits
  dv.setUint32(totalLen - 4, ml >>> 0); // low bits

  const W = new Uint32Array(64);

  for (let i = 0; i < padded.length; i += 64) {
    // expand schedule
    for (let t = 0; t < 16; t++) {
      const j = i + t * 4;
      W[t] = (padded[j] << 24) | (padded[j+1] << 16) | (padded[j+2] << 8) | (padded[j+3]);
    }
    for (let t = 16; t < 64; t++) {
      W[t] = (σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]) >>> 0;
    }

    // compression rounds
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

// --- HMAC & PBKDF2 ---
const blockSize = 64; // SHA-256 block size
export const hmacSha256 = (keyBytes, dataBytes) => {
  let k = keyBytes;
  if (k.length > blockSize) k = sha256(k);
  if (k.length < blockSize) {
    const kk = new Uint8Array(blockSize); kk.set(k); k = kk;
  }
  const o = new Uint8Array(blockSize), i = new Uint8Array(blockSize);
  for (let idx = 0; idx < blockSize; idx++) {
    o[idx] = 0x5c ^ k[idx];
    i[idx] = 0x36 ^ k[idx];
  }
  return sha256(concatBytes(o, sha256(concatBytes(i, dataBytes))));
};

const int32BE = (i) => new Uint8Array([ (i>>>24)&0xff, (i>>>16)&0xff, (i>>>8)&0xff, i&0xff ]);

export const pbkdf2Sha256 = (passwordBytes, saltBytes, iterations, dkLen) => {
  if (!Number.isInteger(iterations) || iterations <= 0) throw new Error('PBKDF2: invalid iterations');
  if (!Number.isInteger(dkLen) || dkLen <= 0) throw new Error('PBKDF2: invalid dkLen');

  const hLen = 32;
  const l = Math.ceil(dkLen / hLen);
  const r = dkLen - (l - 1) * hLen;
  const DK = new Uint8Array(dkLen);

  for (let i = 1; i <= l; i++) {
    // U1 = HMAC(password, salt || INT(i))
    let U = hmacSha256(passwordBytes, concatBytes(saltBytes, int32BE(i)));
    let T = U.slice(); // copy
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

// timingSafeEqualHex: constant-time compare.
export const timingSafeEqualHex = (aHex, bHex) => {
  if (!isHex(aHex) || !isHex(bHex)) return false;
  if (aHex.length !== bHex.length) return false;
  let diff = 0;
  for (let i = 0; i < aHex.length; i++) {
    diff |= aHex.charCodeAt(i) ^ bHex.charCodeAt(i);
  }
  return diff === 0;
};

// --- AES tables/rounds ---
const Nb = 4;
const SBOX = (() => {
  const t = new Uint8Array(256);
  for (let i = 0; i < 256; i++) t[i] = parseInt(genSBoxValue(i), 16);
  return t;
})();
const INV_SBOX = (() => {
  const t = new Uint8Array(256);
  for (let hi = 0; hi < 16; hi++) for (let lo = 0; lo < 16; lo++) t[(hi<<4)|lo] = parseInt(sBoxReverse[hi][lo], 16);
  return t;
})();

const rotWord = (w) => (w << 8) | ((w >>> 24) & 0xff);
const subWord = (w) =>
  ((SBOX[(w >>> 24) & 0xff] << 24) |
   (SBOX[(w >>> 16) & 0xff] << 16) |
   (SBOX[(w >>>  8) & 0xff] <<  8) |
   (SBOX[(w       ) & 0xff]      )) >>> 0;
const rconWord = (i) => (parseInt(rCon[i - 1][0], 16) << 24) >>> 0;

const keyExpansion = (keyBytes) => {
  const Nk = keyBytes.length / 4;
  if (![4,6,8].includes(Nk)) throw new Error('Invalid key size (Nk)');
  const Nr = Nk + 6;
  const w = new Uint32Array(Nb * (Nr + 1));
  for (let i = 0; i < Nk; i++) {
    w[i] =
      (keyBytes[4*i] << 24) |
      (keyBytes[4*i+1] << 16) |
      (keyBytes[4*i+2] << 8) |
      (keyBytes[4*i+3]);
  }
  for (let i = Nk; i < Nb * (Nr + 1); i++) {
    let temp = w[i - 1];
    if (i % Nk === 0) temp = subWord(rotWord(temp)) ^ rconWord(i / Nk);
    else if (Nk > 6 && i % Nk === 4) temp = subWord(temp);
    w[i] = (w[i - Nk] ^ temp) >>> 0;
  }
  return { w, Nr };
};

const addRoundKey = (state, w, round) => {
  for (let c = 0; c < Nb; c++) {
    const word = w[round * Nb + c];
    state[0 + 4 * c] ^= (word >>> 24) & 0xff;
    state[1 + 4 * c] ^= (word >>> 16) & 0xff;
    state[2 + 4 * c] ^= (word >>> 8) & 0xff;
    state[3 + 4 * c] ^= (word) & 0xff;
  }
};

const shiftRows = (s) => {
  const t = s.slice();
  s[1]  = t[5];  s[5]  = t[9];  s[9]  = t[13]; s[13] = t[1];
  s[2]  = t[10]; s[6]  = t[14]; s[10] = t[2];  s[14] = t[6];
  s[3]  = t[15]; s[7]  = t[3];  s[11] = t[7];  s[15] = t[11];
};
const invShiftRows = (s) => {
  const t = s.slice();
  s[1]  = t[13]; s[5]  = t[1];  s[9]  = t[5];  s[13] = t[9];
  s[2]  = t[10]; s[6]  = t[14]; s[10] = t[2];  s[14] = t[6];
  s[3]  = t[7];  s[7]  = t[11]; s[11] = t[15]; s[15] = t[3];
};

const xtime = (x) => ((x & 0x80) ? (((x << 1) ^ 0x1b) & 0xff) : ((x << 1) & 0xff));
const mul = (a, b) => {
  let res = 0, aa = a, bb = b;
  while (bb) { if (bb & 1) res ^= aa; aa = xtime(aa); bb >>= 1; }
  return res & 0xff;
};

const mixColumns = (s) => {
  for (let c = 0; c < 4; c++) {
    const i = 4 * c;
    const a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
    s[i]   = (mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3) & 0xff;
    s[i+1] = (a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3) & 0xff;
    s[i+2] = (a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3)) & 0xff;
    s[i+3] = (mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2)) & 0xff;
  }
};
const invMixColumns = (s) => {
  for (let c = 0; c < 4; c++) {
    const i = 4 * c;
    const a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
    s[i]   = (mul(a0,14) ^ mul(a1,11) ^ mul(a2,13) ^ mul(a3, 9)) & 0xff;
    s[i+1] = (mul(a0, 9) ^ mul(a1,14) ^ mul(a2,11) ^ mul(a3,13)) & 0xff;
    s[i+2] = (mul(a0,13) ^ mul(a1, 9) ^ mul(a2,14) ^ mul(a3,11)) & 0xff;
    s[i+3] = (mul(a0,11) ^ mul(a1,13) ^ mul(a2, 9) ^ mul(a3,14)) & 0xff;
  }
};

const subBytes = (state) => { for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]]; };
const invSubBytes = (state) => { for (let i = 0; i < 16; i++) state[i] = INV_SBOX[state[i]]; };

const encryptBlock = (in16, w, Nr) => {
  const s = new Uint8Array(in16);
  addRoundKey(s, w, 0);
  for (let round = 1; round < Nr; round++) {
    subBytes(s); shiftRows(s); mixColumns(s); addRoundKey(s, w, round);
  }
  subBytes(s); shiftRows(s); addRoundKey(s, w, Nr);
  return s;
};
const decryptBlock = (in16, w, Nr) => {
  const s = new Uint8Array(in16);
  addRoundKey(s, w, Nr);
  invShiftRows(s); invSubBytes(s);
  for (let round = Nr - 1; round >= 1; round--) {
    addRoundKey(s, w, round); invMixColumns(s); invShiftRows(s); invSubBytes(s);
  }
  addRoundKey(s, w, 0);
  return s;
};

const ensureMultipleOfBlock = (bytes, mode) => {
  if (bytes.length % 16 !== 0) throw new Error(`${mode} requires input length to be a multiple of 16 bytes (enable PKCS7 to pad)`);
};

const encryptECBBytes = (plain, w, Nr) => {
  const out = new Uint8Array(plain.length);
  for (let off = 0; off < plain.length; off += 16) {
    out.set(encryptBlock(plain.subarray(off, off + 16), w, Nr), off);
  }
  return out;
};

const decryptECBBytes = (cipher, w, Nr) => {
  const out = new Uint8Array(cipher.length);
  for (let off = 0; off < cipher.length; off += 16) {
    out.set(decryptBlock(cipher.subarray(off, off + 16), w, Nr), off);
  }
  return out;
};

const encryptCBCBytes = (plain, w, Nr, ivBytes) => {
  const out = new Uint8Array(plain.length);
  let prev = new Uint8Array(ivBytes);
  for (let off = 0; off < plain.length; off += 16) {
    const block = plain.subarray(off, off + 16);
    const x = xorBytes(block, prev);
    const c = encryptBlock(x, w, Nr);
    out.set(c, off);
    prev = c;
  }
  return out;
};

const decryptCBCBytes = (cipher, w, Nr, ivBytes) => {
  const out = new Uint8Array(cipher.length);
  let prev = new Uint8Array(ivBytes);
  for (let off = 0; off < cipher.length; off += 16) {
    const block = cipher.subarray(off, off + 16);
    const dec = decryptBlock(block, w, Nr);
    const plain = xorBytes(dec, prev);
    out.set(plain, off);
    prev = new Uint8Array(block);
  }
  return out;
};

const encryptPCBCBytes = (plain, w, Nr, ivBytes) => {
  const out = new Uint8Array(plain.length);
  let prevPlain = new Uint8Array(ivBytes);
  let prevCipher = new Uint8Array(ivBytes);
  for (let off = 0; off < plain.length; off += 16) {
    const block = new Uint8Array(plain.subarray(off, off + 16));
    const mix = xorBlock(block, xorBlock(prevPlain, prevCipher));
    const cipher = encryptBlock(mix, w, Nr);
    out.set(cipher, off);
    prevPlain = block;
    prevCipher = cipher;
  }
  return out;
};

const decryptPCBCBytes = (cipher, w, Nr, ivBytes) => {
  const out = new Uint8Array(cipher.length);
  let prevPlain = new Uint8Array(ivBytes);
  let prevCipher = new Uint8Array(ivBytes);
  for (let off = 0; off < cipher.length; off += 16) {
    const block = new Uint8Array(cipher.subarray(off, off + 16));
    const mix = decryptBlock(block, w, Nr);
    const plain = xorBlock(mix, xorBlock(prevPlain, prevCipher));
    out.set(plain, off);
    prevPlain = plain;
    prevCipher = block;
  }
  return out;
};

const encryptCTRBytes = (plain, w, Nr, ivBytes) => {
  const out = new Uint8Array(plain.length);
  const counter = new Uint8Array(ivBytes);
  for (let off = 0; off < plain.length; off += 16) {
    const keystream = encryptBlock(counter, w, Nr);
    const chunkLen = Math.min(16, plain.length - off);
    for (let i = 0; i < chunkLen; i++) out[off + i] = plain[off + i] ^ keystream[i];
    inc32InPlace(counter);
  }
  return out;
};

const encryptCFBBytes = (plain, w, Nr, ivBytes) => {
  ensureMultipleOfBlock(plain, 'CFB');
  const out = new Uint8Array(plain.length);
  let state = new Uint8Array(ivBytes);
  for (let off = 0; off < plain.length; off += 16) {
    const keystream = encryptBlock(state, w, Nr);
    const block = plain.subarray(off, off + 16);
    const cipher = xorBytes(block, keystream);
    out.set(cipher, off);
    state = cipher;
  }
  return out;
};

const decryptCFBBytes = (cipher, w, Nr, ivBytes) => {
  ensureMultipleOfBlock(cipher, 'CFB');
  const out = new Uint8Array(cipher.length);
  let state = new Uint8Array(ivBytes);
  for (let off = 0; off < cipher.length; off += 16) {
    const keystream = encryptBlock(state, w, Nr);
    const block = cipher.subarray(off, off + 16);
    const plain = xorBytes(block, keystream);
    out.set(plain, off);
    state = new Uint8Array(block);
  }
  return out;
};

const processOFB = (input, w, Nr, ivBytes) => {
  const out = new Uint8Array(input.length);
  let state = new Uint8Array(ivBytes);
  for (let off = 0; off < input.length; off += 16) {
    state = encryptBlock(state, w, Nr);
    const chunkLen = Math.min(16, input.length - off);
    for (let i = 0; i < chunkLen; i++) out[off + i] = input[off + i] ^ state[i];
  }
  return out;
};

const encryptGCMBytes = (plain, w, Nr, ivBytes, aadBytes) => {
  const H = encryptBlock(new Uint8Array(16), w, Nr);
  const J0 = buildJ0(H, ivBytes);
  const counter = new Uint8Array(J0);
  inc32InPlace(counter);
  const ciphertext = new Uint8Array(plain.length);
  for (let off = 0; off < plain.length; off += 16) {
    const keystream = encryptBlock(counter, w, Nr);
    const chunkLen = Math.min(16, plain.length - off);
    for (let i = 0; i < chunkLen; i++) ciphertext[off + i] = plain[off + i] ^ keystream[i];
    inc32InPlace(counter);
  }
  const tagInput = ghash(H, aadBytes, ciphertext);
  const tagBlock = encryptBlock(J0, w, Nr);
  const tag = xorBlock(tagBlock, tagInput);
  return { ciphertext, tag };
};

const decryptGCMBytes = (cipher, w, Nr, ivBytes, aadBytes) => {
  const H = encryptBlock(new Uint8Array(16), w, Nr);
  const J0 = buildJ0(H, ivBytes);
  const counter = new Uint8Array(J0);
  inc32InPlace(counter);
  const plain = new Uint8Array(cipher.length);
  for (let off = 0; off < cipher.length; off += 16) {
    const keystream = encryptBlock(counter, w, Nr);
    const chunkLen = Math.min(16, cipher.length - off);
    for (let i = 0; i < chunkLen; i++) plain[off + i] = cipher[off + i] ^ keystream[i];
    inc32InPlace(counter);
  }
  const expectedTagInput = ghash(H, aadBytes, cipher);
  const tagBlock = encryptBlock(J0, w, Nr);
  const expectedTag = xorBlock(tagBlock, expectedTagInput);
  return { plain, expectedTag };
};
// --- AES wrapper ---
export const AES = class {
  #defaultSettings;

  static #validSettings = {
    bits: [128, 192, 256],
    mode: ['ECB', 'CBC', 'CTR', 'CFB', 'OFB', 'PCBC', 'GCM'],
    deriveKey: [true, false],
    addSalt: [true, false],
    usePKCS7: [true, false],
    addHMAC: [true, false],
    salt: (v) => {
      if (v == null) return null;
      const normalized = normalizeHex(v, { allowEmpty: false });
      if (normalized === null || normalized.length % 2 !== 0) throw new Error('Invalid salt');
      return normalized;
    },
    IV: (v) => {
      if (v == null) return null;
      const normalized = normalizeHex(v, { allowEmpty: false });
      if (normalized === null) throw new Error('Invalid IV hex');
      if (normalized.length !== 32 && normalized.length !== 24) throw new Error('Invalid IV length (expect 12 or 16 bytes hex)');
      return normalized;
    },
    HMAC: (v) => {
      if (v == null) return null;
      const normalized = normalizeHex(v, { allowEmpty: false });
      if (normalized === null || normalized.length !== 64) throw new Error('Invalid HMAC hex');
      return normalized;
    },
    iterations: (v) => {
      if (v == null) return 100000;
      if (!Number.isInteger(v) || v <= 0) throw new Error('Invalid iterations');
      return v;
    },
    rng: (fn) => {
      if (fn == null) return null;
      if (typeof fn !== 'function') throw new Error('rng must be a function');
      return fn;
    },
    AAD: (v) => {
      if (v == null) return null;
      const normalized = normalizeHex(v, { allowEmpty: true });
      if (normalized === null) throw new Error('Invalid AAD hex');
      if (normalized.length % 2 !== 0) throw new Error('AAD hex string must have an even length');
      return normalized;
    },
    tag: (v) => {
      if (v == null) return null;
      const normalized = normalizeHex(v, { allowEmpty: false });
      if (normalized === null || normalized.length !== 32) throw new Error('Invalid GCM tag hex (must be 16 bytes)');
      return normalized;
    },
  };

  #initialize() {
    return { ...BASE_DEFAULTS };
  }

  constructor(defaults = {}) {
    this.#defaultSettings = this.#initialize();
    if (defaults && Object.keys(defaults).length > 0) this.setDefaultSettings(defaults);
  }
  getDefaultSettings() { return { ...this.#defaultSettings }; }
  setDefaultSettings(options = {}) { this.#validateSettings(options); this.#defaultSettings = { ...this.#defaultSettings, ...options }; return this; }
  reset() { this.#defaultSettings = this.#initialize(); return this; }
  generateRandomBytes(length = 16) {
    if (!Number.isInteger(length) || length <= 0) throw new Error('length must be a positive integer');
    const rngFn = this.#defaultSettings.rng || defaultRandomBytes;
    return bytesToHex(rngFn(length));
  }

  encrypt(plainTextHex, plainKeyHex, options = {}) {
    const { hexText, hexKey, settings } = this.#validateEncryptionInput(plainTextHex, plainKeyHex, options);
    const { cipherHex, tagHex } = this.#performEncryption(hexText, hexKey, settings);

    const macDataBytes = concatBytes(
      settings.IV ? hexToBytes(settings.IV) : new Uint8Array(0),
      settings.addSalt && settings.salt ? hexToBytes(settings.salt) : new Uint8Array(0)
    );
    const macFull = concatBytes(macDataBytes, hexToBytes(cipherHex));
    const hmacHex = settings.addHMAC ? bytesToHex(hmacSha256(hexToBytes(hexKey), macFull)) : null;

    return {
      message: cipherHex,
      IV: settings.IV || null,
      salt: settings.addSalt ? settings.salt : null,
      HMAC: hmacHex,
      tag: tagHex,
      AAD: settings.AAD || null,
      instance: this,
    };
  }

  decrypt(cipherTextHex, plainKeyHex, options = {}) {
    const { hexText, hexKey, settings } = this.#validateDecryptionInput(cipherTextHex, plainKeyHex, options);

    if (settings.HMAC) {
      const macDataBytes = concatBytes(
        settings.IV ? hexToBytes(settings.IV) : new Uint8Array(0),
        settings.addSalt && settings.salt ? hexToBytes(settings.salt) : new Uint8Array(0)
      );
      const macFull = concatBytes(macDataBytes, hexToBytes(hexText));
      const exp = bytesToHex(hmacSha256(hexToBytes(hexKey), macFull));
      if (!timingSafeEqualHex(exp, settings.HMAC)) throw new Error('HMAC verification failed');
    } else if (settings.addHMAC) {
      throw new Error('HMAC required but not provided');
    }

    const { plainHex } = this.#performDecryption(hexText, hexKey, settings);
    return {
      message: plainHex,
      IV: settings.IV || null,
      salt: settings.addSalt ? settings.salt : null,
      HMAC: settings.HMAC || null,
      tag: settings.tag || null,
      AAD: settings.AAD || null,
      instance: this,
    };
  }

  // --- validation / derivation ---
  #validateSettings(options) {
    Object.entries(options).forEach(([key, val]) => {
      if (!(key in AES.#validSettings)) return;
      const rule = AES.#validSettings[key];
      if (Array.isArray(rule)) {
        if (!rule.includes(val)) throw new Error(`Invalid value for ${key}: ${val}`);
      } else if (typeof rule === 'function') {
        options[key] = rule(val);
      }
    });
    return true;
  }

  #validateEncryptionInput(plainInput, keyInput, options) {
    this.#validateSettings(options);
    const settings = { ...this.#defaultSettings, ...options };

    const plainHex = ensureHexString(plainInput, { label: 'Plaintext', allowEmpty: true, allowTextFallback: true });
    const keyHex = ensureHexString(keyInput, { label: 'Key', allowEmpty: false, allowTextFallback: true });

    const { finalKeyHex, usedSalt } = this.#transformKey(keyHex, settings, /*forDecryption=*/false);
    settings.salt = usedSalt;

    const streamingModes = new Set(['CTR', 'CFB', 'OFB', 'GCM']);
    if (streamingModes.has(settings.mode)) settings.usePKCS7 = false;
    if (settings.mode === 'GCM') settings.addHMAC = false;

    const modesRequiringIV = new Set(['CBC', 'CTR', 'CFB', 'OFB', 'PCBC', 'GCM']);
    if (modesRequiringIV.has(settings.mode)) {
      const requiredBytes = settings.mode === 'GCM' ? 12 : 16;
      if (settings.IV) {
        const normalized = AES.#validSettings.IV(settings.IV);
        const ivLen = normalized.length / 2;
        if (settings.mode === 'GCM') {
          if (ivLen !== 12 && ivLen !== 16) throw new Error('GCM IV must be 12 or 16 bytes');
        } else if (ivLen !== 16) {
          throw new Error(`${settings.mode} IV must be 16 bytes`);
        }
        settings.IV = normalized;
      } else {
        if (!settings.rng) throw new Error(`${settings.mode} requires an IV (provide options.IV or options.rng)`);
        const generated = settings.rng(requiredBytes);
        if (!(generated instanceof Uint8Array) || generated.length !== requiredBytes) throw new Error('options.rng must return a Uint8Array of the requested length');
        settings.IV = bytesToHex(generated);
      }
    } else {
      settings.IV = null;
    }

    settings.tag = null;

    return { hexText: plainHex, hexKey: finalKeyHex, settings };
  }

  #validateDecryptionInput(cipherInput, keyInput, options) {
    this.#validateSettings(options);
    const settings = { ...this.#defaultSettings, ...options };

    const cipherHex = ensureHexString(cipherInput, { label: 'Ciphertext', allowEmpty: false, allowTextFallback: false });
    const keyHex = ensureHexString(keyInput, { label: 'Key', allowEmpty: false, allowTextFallback: true });

    const { finalKeyHex } = this.#transformKey(keyHex, settings, /*forDecryption=*/true);

    const streamingModes = new Set(['CTR', 'CFB', 'OFB', 'GCM']);
    if (streamingModes.has(settings.mode)) settings.usePKCS7 = false;
    if (settings.mode === 'GCM') settings.addHMAC = false;

    const modesRequiringIV = new Set(['CBC', 'CTR', 'CFB', 'OFB', 'PCBC', 'GCM']);
    if (modesRequiringIV.has(settings.mode)) {
      if (!settings.IV) throw new Error(`IV required for ${settings.mode} decryption`);
      const normalized = AES.#validSettings.IV(settings.IV);
      const ivLen = normalized.length / 2;
      if (settings.mode === 'GCM') {
        if (ivLen !== 12 && ivLen !== 16) throw new Error('GCM IV must be 12 or 16 bytes');
      } else if (ivLen !== 16) {
        throw new Error(`${settings.mode} IV must be 16 bytes`);
      }
      settings.IV = normalized;
    } else {
      settings.IV = null;
    }

    if (settings.mode === 'GCM') {
      if (!settings.tag) throw new Error('GCM decryption requires options.tag');
      settings.tag = AES.#validSettings.tag(settings.tag);
    } else {
      settings.tag = null;
    }

    return { hexText: cipherHex, hexKey: finalKeyHex, settings };
  }

  #transformKey(keyHex, settings, forDecryption) {
    const keyBytesLen = settings.bits / 8;

    if (settings.deriveKey) {
      // PBKDF2 needs a salt.
      let saltHex = settings.salt;
      if (!saltHex) {
        if (settings.addSalt && settings.rng && !forDecryption) saltHex = bytesToHex(settings.rng(16));
        else throw new Error('PBKDF2 requires a salt (provide options.salt or options.rng)');
      }
      const dk = pbkdf2Sha256(hexToBytes(keyHex), hexToBytes(saltHex), settings.iterations ?? 100000, keyBytesLen);
      return { finalKeyHex: bytesToHex(dk), usedSalt: saltHex };
    }

    if (keyHex.length !== keyBytesLen * 2) throw new Error(`Invalid key size | Expected ${settings.bits}-bit key`);
    return { finalKeyHex: keyHex, usedSalt: settings.addSalt ? (settings.salt || null) : null };
  }

  // --- encrypt/decrypt ---
  #performEncryption(plainHex, keyHex, settings) {
    const key = hexToBytes(keyHex);
    const { w, Nr } = keyExpansion(key);
    const plain = hexToBytes(plainHex);

    switch (settings.mode) {
      case 'ECB': {
        const input = settings.usePKCS7 ? pkcs7Pad(plain, 16) : (ensureMultipleOfBlock(plain, 'ECB'), plain);
        const cipherBytes = encryptECBBytes(input, w, Nr);
        return { cipherHex: bytesToHex(cipherBytes), tagHex: null };
      }
      case 'CBC': {
        const input = settings.usePKCS7 ? pkcs7Pad(plain, 16) : (ensureMultipleOfBlock(plain, 'CBC'), plain);
        const cipherBytes = encryptCBCBytes(input, w, Nr, hexToBytes(settings.IV));
        return { cipherHex: bytesToHex(cipherBytes), tagHex: null };
      }
      case 'PCBC': {
        const input = settings.usePKCS7 ? pkcs7Pad(plain, 16) : (ensureMultipleOfBlock(plain, 'PCBC'), plain);
        const cipherBytes = encryptPCBCBytes(input, w, Nr, hexToBytes(settings.IV));
        return { cipherHex: bytesToHex(cipherBytes), tagHex: null };
      }
      case 'CTR': {
        const cipherBytes = encryptCTRBytes(plain, w, Nr, hexToBytes(settings.IV));
        return { cipherHex: bytesToHex(cipherBytes), tagHex: null };
      }
      case 'CFB': {
        const input = settings.usePKCS7 ? pkcs7Pad(plain, 16) : plain;
        if (!settings.usePKCS7) ensureMultipleOfBlock(input, 'CFB');
        const cipherBytes = encryptCFBBytes(input, w, Nr, hexToBytes(settings.IV));
        return { cipherHex: bytesToHex(cipherBytes), tagHex: null };
      }
      case 'OFB': {
        const cipherBytes = processOFB(plain, w, Nr, hexToBytes(settings.IV));
        return { cipherHex: bytesToHex(cipherBytes), tagHex: null };
      }
      case 'GCM': {
        const aadBytes = settings.AAD ? hexToBytes(settings.AAD) : new Uint8Array(0);
        const { ciphertext, tag } = encryptGCMBytes(plain, w, Nr, hexToBytes(settings.IV), aadBytes);
        return { cipherHex: bytesToHex(ciphertext), tagHex: bytesToHex(tag) };
      }
      default:
        throw new Error(`Unsupported mode: ${settings.mode}`);
    }
  }

  #performDecryption(cipherHex, keyHex, settings) {
    const key = hexToBytes(keyHex);
    const { w, Nr } = keyExpansion(key);

    const cipher = hexToBytes(cipherHex);

    switch (settings.mode) {
      case 'ECB': {
        ensureMultipleOfBlock(cipher, 'ECB');
        let plain = decryptECBBytes(cipher, w, Nr);
        if (settings.usePKCS7) plain = pkcs7Unpad(plain, 16);
        return { plainHex: bytesToHex(plain) };
      }
      case 'CBC': {
        ensureMultipleOfBlock(cipher, 'CBC');
        let plain = decryptCBCBytes(cipher, w, Nr, hexToBytes(settings.IV));
        if (settings.usePKCS7) plain = pkcs7Unpad(plain, 16);
        return { plainHex: bytesToHex(plain) };
      }
      case 'PCBC': {
        ensureMultipleOfBlock(cipher, 'PCBC');
        let plain = decryptPCBCBytes(cipher, w, Nr, hexToBytes(settings.IV));
        if (settings.usePKCS7) plain = pkcs7Unpad(plain, 16);
        return { plainHex: bytesToHex(plain) };
      }
      case 'CTR': {
        const plain = encryptCTRBytes(cipher, w, Nr, hexToBytes(settings.IV));
        return { plainHex: bytesToHex(plain) };
      }
      case 'CFB': {
        ensureMultipleOfBlock(cipher, 'CFB');
        let plain = decryptCFBBytes(cipher, w, Nr, hexToBytes(settings.IV));
        if (settings.usePKCS7) plain = pkcs7Unpad(plain, 16);
        return { plainHex: bytesToHex(plain) };
      }
      case 'OFB': {
        const plain = processOFB(cipher, w, Nr, hexToBytes(settings.IV));
        return { plainHex: bytesToHex(plain) };
      }
      case 'GCM': {
        const aadBytes = settings.AAD ? hexToBytes(settings.AAD) : new Uint8Array(0);
        const tagBytes = hexToBytes(settings.tag);
        const { plain, expectedTag } = decryptGCMBytes(cipher, w, Nr, hexToBytes(settings.IV), aadBytes);
        if (!timingSafeEqualHex(bytesToHex(expectedTag), bytesToHex(tagBytes))) throw new Error('GCM tag verification failed');
        return { plainHex: bytesToHex(plain) };
      }
      default:
        throw new Error(`Unsupported mode: ${settings.mode}`);
    }
  }
};

export const createAES = (defaults = {}) => new AES(defaults);
