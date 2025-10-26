// AES tables and GF helpers.

const AES_POLY = 0x11b; // AES irreducible polynomial

// GF multiplies two bytes in GF(2^8).
export const GF = function (a, b) {
  // mask to 8-bit
  a &= 0xff;
  b &= 0xff;
  let res = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) res ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= AES_POLY & 0xff;
    b >>= 1;
  }
  return res & 0xff;
};

// xtime: multiply by x mod 0x11b.
const xtime = (x) => {
  x &= 0xff;
  const hi = x & 0x80;
  x = (x << 1) & 0xff;
  return hi ? (x ^ 0x1b) : x;
};

// gfPow: exponentiation in GF(2^8).
const gfPow = (a, e) => {
  a &= 0xff;
  let result = 1;
  let base = a;
  let exp = e >>> 0;
  while (exp > 0) {
    if (exp & 1) result = GF(result, base);
    base = GF(base, base);
    exp >>>= 1;
  }
  return result & 0xff;
};

// GFInverse: multiplicative inverse (0 -> 0).
export const GFInverse = function (byte) {
  byte &= 0xff;
  if (byte === 0) return 0;
  return gfPow(byte, 254);
};

// affineTransform: AES affine map.
const affineTransform = (x) => {
  x &= 0xff;
  const rot1 = ((x << 1) | (x >>> 7)) & 0xff;
  const rot2 = ((x << 2) | (x >>> 6)) & 0xff;
  const rot3 = ((x << 3) | (x >>> 5)) & 0xff;
  const rot4 = ((x << 4) | (x >>> 4)) & 0xff;
  return (0x63 ^ x ^ rot1 ^ rot2 ^ rot3 ^ rot4) & 0xff;
};

// genSBoxValue: inverse + affine.
export const genSBoxValue = function (byte) {
  const inv = GFInverse(byte & 0xff);
  const sb = affineTransform(inv);
  return sb.toString(16).padStart(2, '0');
};

// Precompute S-Box and inverse.
const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
(() => {
  for (let i = 0; i < 256; i++) {
    const s = parseInt(genSBoxValue(i), 16);
    SBOX[i] = s;
  }
  for (let i = 0; i < 256; i++) {
    INV_SBOX[SBOX[i]] = i;
  }
})();

// Convert flat table to 16x16 hex grid.
const toHexMatrix16x16 = (arr) => {
  const out = [];
  for (let r = 0; r < 16; r++) {
    const row = [];
    for (let c = 0; c < 16; c++) {
      const v = arr[r * 16 + c];
      row.push(v.toString(16).padStart(2, '0'));
    }
    out.push(row);
  }
  return out;
};

// sBoxReverse: 16x16 inverse S-Box.
export const sBoxReverse = toHexMatrix16x16(INV_SBOX);

// buildRcon: xtime sequence.
const buildRcon = (n = 10) => {
  const out = [];
  let r = 0x01;
  for (let i = 0; i < n; i++) {
    out.push([r.toString(16).padStart(2, '0'), '00', '00', '00']);
    // next r = xtime(r)
    r = xtime(r);
  }
  return out;
};

// rCon: classic round constants.
export const rCon = buildRcon(10);
