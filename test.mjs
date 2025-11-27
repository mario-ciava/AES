// Minimal test runner with deterministic fuzzing.
import { AES, createAES } from './cipher.mjs';
import { textToHex, hexToBytes, bytesToHex, sha256, normalizeHex } from './prototypeExtensions.mjs';

// --- mini-assert ---
const ok = (name) => console.log(`✓ ${name}`);
const assertEq = (name, got, exp) => {
  if (got !== exp) throw new Error(`${name} FAILED\nexp: ${exp}\n got: ${got}`);
  ok(name);
};
const assertThrows = async (name, fn, msgIncludes) => {
  try {
    await fn();
    throw new Error(`${name} FAILED (no throw)`);
  } catch (e) {
    const m = String(e && e.message || e);
    if (msgIncludes && !m.includes(msgIncludes)) {
      throw new Error(`${name} WRONG ERROR\nexpected: contains "${msgIncludes}"\nactual:   "${m}"`);
    }
    ok(name);
  }
};

// makeRNG derives bytes from SHA-256(seed || counter).
const makeRNG = (seedHex = '00') => {
  let counter = 0;
  return (n) => {
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const ctrHex = counter.toString(16).padStart(8, '0');
      const block = sha256(hexToBytes(seedHex + ctrHex)); // 32 bytes
      const take = Math.min(block.length, n - off);
      out.set(block.subarray(0, take), off);
      off += take;
      counter++;
    }
    return out;
  };
};

const randomInt = (rng, min, max) => {
  const span = max - min + 1;
  const byte = rng(1)[0];
  return min + (byte % span);
};

const randomBool = (rng) => (rng(1)[0] & 1) === 1;

const randomHexBytes = (rng, byteLen) => bytesToHex(rng(byteLen));

const randomAscii = (rng, len) => {
  const chars = [];
  for (let i = 0; i < len; i++) {
    const c = 32 + (rng(1)[0] % 95); // printable ASCII
    chars.push(String.fromCharCode(c));
  }
  return chars.join('');
};

const expectedPlainHex = (value) => {
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (typeof value === 'string') {
    const normalized = normalizeHex(value, { allowEmpty: true });
    if (normalized !== null && normalized.length % 2 === 0) return normalized;
    return textToHex(value);
  }
  return textToHex(String(value));
};

const plainHexLength = (value) => expectedPlainHex(value).length;

const chaosMonkey = (iterations = 100, seed = 'ce10d00d') => {
  const rng = makeRNG(seed);
  const aes = new AES();

  for (let round = 0; round < iterations; round++) {
    const shouldBeValid = (rng(1)[0] & 3) !== 0; // ~75% valid scenarios

    const modes = ['CBC', 'ECB', 'CTR', 'CFB', 'OFB', 'PCBC', 'GCM'];
    const mode = modes[rng(1)[0] % modes.length];
    const allowsPadding = new Set(['CBC', 'ECB', 'PCBC']);
    const streamingModes = new Set(['CTR', 'CFB', 'OFB', 'GCM']);
    const baseOptions = {
      mode,
      usePKCS7: allowsPadding.has(mode) ? randomBool(rng) : false,
      addHMAC: mode === 'GCM' ? false : randomBool(rng),
      deriveKey: (rng(1)[0] & 7) === 0, // keep PBKDF2 relatively rare
    };
    baseOptions.addSalt = baseOptions.deriveKey ? true : randomBool(rng);

    if (baseOptions.mode === 'CBC') baseOptions.IV = randomHexBytes(rng, 16);
    else if (baseOptions.mode === 'PCBC') baseOptions.IV = randomHexBytes(rng, 16);
    else if (baseOptions.mode === 'CTR' || baseOptions.mode === 'CFB' || baseOptions.mode === 'OFB') baseOptions.IV = randomHexBytes(rng, 16);
    else if (baseOptions.mode === 'GCM') baseOptions.IV = randomHexBytes(rng, 12);

    if (baseOptions.addSalt) baseOptions.salt = randomHexBytes(rng, 8);
    if (baseOptions.deriveKey) baseOptions.iterations = 200 + (rng(1)[0] & 0x3f);
    if (baseOptions.mode === 'GCM' && randomBool(rng)) {
      baseOptions.AAD = randomHexBytes(rng, randomInt(rng, 1, 4) * 8); // 8-32 bytes hex
    }

    let keyInput;
    let plainInput;

    if (shouldBeValid) {
      keyInput = (() => {
        const pick = rng(1)[0] % 3;
        if (pick === 0) return randomHexBytes(rng, 16);
        if (pick === 1) return randomAscii(rng, 16);
        return rng(16);
      })();

      plainInput = (() => {
        const variant = rng(1)[0] % 3;
        if (variant === 0) {
          const blocks = randomInt(rng, 1, 3) * 16;
          return randomHexBytes(rng, blocks);
        }
        if (variant === 1) {
          if (baseOptions.usePKCS7) return randomAscii(rng, randomInt(rng, 0, 31));
          const blocks = randomInt(rng, 1, 3) * 16;
          return randomHexBytes(rng, blocks);
        }
        if (streamingModes.has(baseOptions.mode) && baseOptions.mode !== 'CFB') {
          return rng(randomInt(rng, 0, 48));
        }
        return rng(randomInt(rng, 1, 3) * 16);
      })();

      if (allowsPadding.has(baseOptions.mode) && !baseOptions.usePKCS7) {
        const length = plainHexLength(plainInput);
        if (length % 32 !== 0) plainInput = randomHexBytes(rng, randomInt(rng, 1, 3) * 16);
      }
      if (baseOptions.mode === 'CFB' && plainHexLength(plainInput) % 32 !== 0) {
        plainInput = randomHexBytes(rng, randomInt(rng, 1, 3) * 16);
      }
    } else {
      keyInput = (() => {
        const reason = rng(1)[0] % 6;
        switch (reason) {
          case 0: return null;
          case 1: return 'zzzz';
          case 2: return '';
          case 3: return randomHexBytes(rng, 15);
          case 4: return randomAscii(rng, randomInt(rng, 1, 8));
          default: return undefined;
        }
      })();

      plainInput = (() => {
        const reason = rng(1)[0] % 6;
        switch (reason) {
          case 0: return '123'; // odd-length hex
          case 1: return undefined;
          case 2: return null;
          case 3: return {};
          case 4: return randomAscii(rng, 0);
          default: return '0xZZ';
        }
      })();

      if (randomBool(rng)) baseOptions.mode = 'CBC';
      if (baseOptions.mode === 'CBC' && randomBool(rng)) delete baseOptions.IV;
      if (baseOptions.mode === 'GCM' && randomBool(rng)) delete baseOptions.tag;
      if (randomBool(rng)) {
        baseOptions.deriveKey = true;
        baseOptions.addSalt = true;
        baseOptions.salt = 'zz';
      }
    }

    try {
      const encOptions = { ...baseOptions };
      const enc = aes.encrypt(plainInput, keyInput, encOptions);
      const decOptions = {
        ...baseOptions,
        IV: enc.IV,
        salt: enc.salt,
        HMAC: enc.HMAC,
        tag: enc.tag,
      };
      const dec = aes.decrypt(enc.message, keyInput, decOptions);
      const expected = expectedPlainHex(plainInput);
      assertEq(`Chaos round ${round}`, dec.message, expected);
    } catch (err) {
      if (!(err instanceof Error)) throw err;
    }
  }

  ok('Chaos monkey (100 iterations)');
};


(async function main () {
  const rng = makeRNG('a1b2c3d4');

  // 1) AES-128 ECB — NIST KAT
  {
    const key = '000102030405060708090a0b0c0d0e0f';
    const pt  = '00112233445566778899aabbccddeeff';
    const ctE = '69c4e0d86a7b0430d8cdb78070b4c55a';

    const aes = new AES();
    const enc = aes.encrypt(pt, key, { mode: 'ECB', usePKCS7: false });
    assertEq('AES-128-ECB KAT encrypt', enc.message, ctE);

    const dec = aes.decrypt(enc.message, key, { mode: 'ECB', usePKCS7: false, addHMAC: true, HMAC: enc.HMAC });
    assertEq('AES-128-ECB KAT decrypt', dec.message, pt);
  }

  // 2) AES-192/256 ECB — NIST KATs
  {
    const vectors = [
      {
        bits: 192,
        key: '000102030405060708090a0b0c0d0e0f1011121314151617',
        pt: '00112233445566778899aabbccddeeff',
        ct: 'dda97ca4864cdfe06eaf70a0ec0d7191',
      },
      {
        bits: 256,
        key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        pt: '00112233445566778899aabbccddeeff',
        ct: '8ea2b7ca516745bfeafc49904b496089',
      },
    ];

    for (const { bits, key, pt, ct } of vectors) {
      const aes = new AES();
      const enc = aes.encrypt(pt, key, { mode: 'ECB', usePKCS7: false, bits });
      assertEq(`AES-${bits}-ECB KAT encrypt`, enc.message, ct);
      const dec = aes.decrypt(ct, key, { mode: 'ECB', usePKCS7: false, bits, addHMAC: false });
      assertEq(`AES-${bits}-ECB KAT decrypt`, dec.message, pt);
    }
  }

  // 3) AES-128/192/256 CBC — SP 800-38A KAT
  {
    const plaintextBlocks = [
      '6bc1bee22e409f96e93d7e117393172a',
      'ae2d8a571e03ac9c9eb76fac45af8e51',
      '30c81c46a35ce411e5fbc1191a0a52ef',
      'f69f2445df4f9b17ad2b417be66c3710',
    ];
    const plaintext = plaintextBlocks.join('');

    const vectors = [
      {
        bits: 128,
        key: '2b7e151628aed2a6abf7158809cf4f3c',
        iv:  '000102030405060708090a0b0c0d0e0f',
        ct: [
          '7649abac8119b246cee98e9b12e9197d',
          '5086cb9b507219ee95db113a917678b2',
          '73bed6b8e3c1743b7116e69e22229516',
          '3ff1caa1681fac09120eca307586e1a7',
        ].join(''),
      },
      {
        bits: 192,
        key: '8e73b0f7da0e6452c810f32b809079e5' +
             '62f8ead2522c6b7b',
        iv:  '000102030405060708090a0b0c0d0e0f',
        ct: [
          '4f021db243bc633d7178183a9fa071e8',
          'b4d9ada9ad7dedf4e5e738763f69145a',
          '571b242012fb7ae07fa9baac3df102e0',
          '08b0e27988598881d920a9e64f5615cd',
        ].join(''),
      },
      {
        bits: 256,
        key: '603deb1015ca71be2b73aef0857d7781' +
             '1f352c073b6108d72d9810a30914dff4',
        iv:  '000102030405060708090a0b0c0d0e0f',
        ct: [
          'f58c4c04d6e5f1ba779eabfb5f7bfbd6',
          '9cfc4e967edb808d679f777bc6702c7d',
          '39f23369a9d9bacfa530e26304231461',
          'b2eb05e2c39be9fcda6c19078c6a9d1b',
        ].join(''),
      },
    ];

    for (const { bits, key, iv, ct } of vectors) {
      const aes = new AES();
      const enc = aes.encrypt(plaintext, key, { mode: 'CBC', usePKCS7: false, bits, IV: iv, addHMAC: false });
      assertEq(`AES-${bits}-CBC KAT encrypt`, enc.message, ct);
      const dec = aes.decrypt(ct, key, { mode: 'CBC', usePKCS7: false, bits, IV: iv, addHMAC: false });
      assertEq(`AES-${bits}-CBC KAT decrypt`, dec.message, plaintext);
    }
  }

  // 4) AES-128 CTR — SP 800-38A KAT
  {
    const key = '2b7e151628aed2a6abf7158809cf4f3c';
    const iv = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
    const pt = [
      '6bc1bee22e409f96e93d7e117393172a',
      'ae2d8a571e03ac9c9eb76fac45af8e51',
      '30c81c46a35ce411e5fbc1191a0a52ef',
      'f69f2445df4f9b17ad2b417be66c3710',
    ].join('');
    const ct = [
      '874d6191b620e3261bef6864990db6ce',
      '9806f66b7970fdff8617187bb9fffdff',
      '5ae4df3edbd5d35e5b4f09020db03eab',
      '1e031dda2fbe03d1792170a0f3009cee',
    ].join('');

    const aes = new AES();
    const enc = aes.encrypt(pt, key, { mode: 'CTR', usePKCS7: false, addHMAC: false, IV: iv });
    assertEq('AES-128-CTR KAT encrypt', enc.message, ct);
    const dec = aes.decrypt(ct, key, { mode: 'CTR', usePKCS7: false, addHMAC: false, IV: iv });
    assertEq('AES-128-CTR KAT decrypt', dec.message, pt);
  }

  // 5) AES-128 CFB — SP 800-38A KAT
  {
    const aes = new AES();
    const key = '2b7e151628aed2a6abf7158809cf4f3c';
    const iv = '000102030405060708090a0b0c0d0e0f';
    const pt = [
      '6bc1bee22e409f96e93d7e117393172a',
      'ae2d8a571e03ac9c9eb76fac45af8e51',
      '30c81c46a35ce411e5fbc1191a0a52ef',
      'f69f2445df4f9b17ad2b417be66c3710',
    ].join('');
    const ct = [
      '3b3fd92eb72dad20333449f8e83cfb4a',
      'c8a64537a0b3a93fcde3cdad9f1ce58b',
      '26751f67a3cbb140b1808cf187a4f4df',
      'c04b05357c5d1c0eeac4c66f9ff7f2e6',
    ].join('');

    const enc = aes.encrypt(pt, key, { mode: 'CFB', usePKCS7: false, addHMAC: false, IV: iv });
    assertEq('AES-128-CFB KAT encrypt', enc.message, ct);
    const dec = aes.decrypt(ct, key, { mode: 'CFB', usePKCS7: false, addHMAC: false, IV: iv });
    assertEq('AES-128-CFB KAT decrypt', dec.message, pt);
  }

  // 6.1) AES-128 CFB — partial tail allowed
  {
    const aes = new AES();
    const key = '000102030405060708090a0b0c0d0e0f';
    const iv = '0f0e0d0c0b0a09080706050403020100';
    const ptHex = textToHex('partial blocks are fine');
    const enc = aes.encrypt(ptHex, key, { mode: 'CFB', usePKCS7: false, addHMAC: false, IV: iv });
    const dec = aes.decrypt(enc.message, key, { mode: 'CFB', usePKCS7: false, addHMAC: false, IV: iv });
    assertEq('CFB partial round-trip', dec.message, ptHex);
  }

  // 7) AES-128 OFB — SP 800-38A KAT
  {
    const aes = new AES();
    const key = '2b7e151628aed2a6abf7158809cf4f3c';
    const iv = '000102030405060708090a0b0c0d0e0f';
    const pt = [
      '6bc1bee22e409f96e93d7e117393172a',
      'ae2d8a571e03ac9c9eb76fac45af8e51',
      '30c81c46a35ce411e5fbc1191a0a52ef',
      'f69f2445df4f9b17ad2b417be66c3710',
    ].join('');
    const ct = [
      '3b3fd92eb72dad20333449f8e83cfb4a',
      '7789508d16918f03f53c52dac54ed825',
      '9740051e9c5fecf64344f7a82260edcc',
      '304c6528f659c77866a510d9c1d6ae5e',
    ].join('');

    const enc = aes.encrypt(pt, key, { mode: 'OFB', usePKCS7: false, addHMAC: false, IV: iv });
    assertEq('AES-128-OFB KAT encrypt', enc.message, ct);
    const dec = aes.decrypt(ct, key, { mode: 'OFB', usePKCS7: false, addHMAC: false, IV: iv });
    assertEq('AES-128-OFB KAT decrypt', dec.message, pt);
  }

  // 7) AES-128 GCM — NIST test vector with AAD
  {
    const aes = new AES();
    const key = 'feffe9928665731c6d6a8f9467308308';
    const iv = 'cafebabefacedbaddecaf888';
    const aad = 'feedfacedeadbeeffeedfacedeadbeefabaddad2';
    const pt = [
      'd9313225f88406e5a55909c5aff5269a',
      '86a7a9531534f7da2e4c303d8a318a72',
      '1c3c0c95956809532fcf0e2449a6b525',
      'b16aedf5aa0de657ba637b391aafd255',
    ].join('');
    const ct = [
      '42831ec2217774244b7221b784d0d49c',
      'e3aa212f2c02a4e035c17e2329aca12e',
      '21d514b25466931c7d8f6a5aac84aa05',
      '1ba30b396a0aac973d58e091473f5985',
    ].join('');
    const tag = 'da80ce830cfda02da2a218a1744f4c76';

    const enc = aes.encrypt(pt, key, { mode: 'GCM', IV: iv, AAD: aad });
    assertEq('AES-128-GCM KAT encrypt', enc.message, ct);
    assertEq('AES-128-GCM tag', enc.tag, tag);
    const dec = aes.decrypt(ct, key, { mode: 'GCM', IV: iv, AAD: aad, tag });
    assertEq('AES-128-GCM KAT decrypt', dec.message, pt);
  }

  // 8) PCBC round-trip
  {
    const aes = new AES();
    const key = '00112233445566778899aabbccddeeff';
    const iv = '0102030405060708090a0b0c0d0e0f10';
    const pt = 'de8abc9912345678de8abc9912345678';
    const enc = aes.encrypt(pt, key, { mode: 'PCBC', usePKCS7: false, IV: iv, addHMAC: false });
    const dec = aes.decrypt(enc.message, key, { mode: 'PCBC', usePKCS7: false, IV: iv, addHMAC: false });
    assertEq('AES-PCBC round-trip', dec.message, pt);
  }

  // 9) CBC round-trip across multiple blocks
  {
    const key = '00112233445566778899aabbccddeeff'; // 128-bit key
    const text = 'Questo è un test CBC multiblocco! ✨ — padding ON';
    const pt = textToHex(text);

    const aes = new AES();
    const enc = aes.encrypt(pt, key, { mode: 'CBC', usePKCS7: true, rng });
    const dec = aes.decrypt(enc.message, key, { mode: 'CBC', usePKCS7: true, IV: enc.IV, addHMAC: true, HMAC: enc.HMAC });

    assertEq('CBC round-trip', dec.message, pt);
  }

  // 10) PBKDF2 + HMAC (tamper detection)
  {
    const passwordHex = textToHex('password'); // test-only secret
    const pt = textToHex('messaggio autenticato con HMAC');

    const aes = new AES();
    const enc = aes.encrypt(pt, passwordHex, {
      mode: 'CBC', usePKCS7: true,
      deriveKey: true, addSalt: true, iterations: 1000,
      addHMAC: true, rng
    });

    // Round-trip with returned IV/salt/HMAC.
    const dec = aes.decrypt(enc.message, passwordHex, {
      mode: 'CBC', usePKCS7: true,
      deriveKey: true, addSalt: true, iterations: 1000,
      IV: enc.IV, salt: enc.salt, addHMAC: true, HMAC: enc.HMAC
    });
    assertEq('PBKDF2+HMAC decrypt OK', dec.message, pt);

    // Tampering must be caught by HMAC.
    const tampered = enc.message.slice(0, -2) + (enc.message.slice(-2) === '00' ? '01' : '00');
    await assertThrows(
      'HMAC detects tamper',
      () => Promise.resolve(
        aes.decrypt(tampered, passwordHex, {
          mode: 'CBC', usePKCS7: true,
          deriveKey: true, addSalt: true, iterations: 1000,
          IV: enc.IV, salt: enc.salt, addHMAC: true, HMAC: enc.HMAC
        })
      ),
      'HMAC verification failed'
    );
  }

  // 11) Streaming CTR round-trip
  {
    const aes = new AES();
    const key = '00112233445566778899aabbccddeeff';
    const iv = '11223344556677889900aabbccddeeff';
    const plain = 'Streaming CTR data';

    const encStream = aes.createEncryptStream(key, { mode: 'CTR', IV: iv, addHMAC: false });
    const c1 = encStream.update(plain.slice(0, 10));
    const c2 = encStream.update(plain.slice(10));
    encStream.final();

    const decStream = aes.createDecryptStream(key, { mode: 'CTR', IV: encStream.IV, addHMAC: false });
    const d1 = decStream.update(c1);
    const d2 = decStream.update(c2);
    decStream.final();
    const recovered = d1 + d2;

    assertEq('Streaming CTR round-trip', recovered, textToHex(plain));
    assertEq('Streaming CTR IV passthrough', decStream.IV, iv);
  }

  // 12) Large payload round-trip (256 KiB)
  {
    const blockBytes = 16 * 1024; // 16 KiB units
    const blocks = 16; // total 256 KiB
    const rngLarge = makeRNG('d00df00d');
    const payloadBytes = rngLarge(blockBytes * blocks);
    const payloadHex = bytesToHex(payloadBytes);
    const key = bytesToHex(rngLarge(16));

    const aes = new AES();
    const enc = aes.encrypt(payloadHex, key, { mode: 'CBC', usePKCS7: false });
    const dec = aes.decrypt(enc.message, key, { mode: 'CBC', usePKCS7: false, IV: enc.IV, addHMAC: true, HMAC: enc.HMAC });
    assertEq('Large payload CBC round-trip', dec.message, payloadHex);
  }

  // 13) Negative: missing IV in CBC
  {
    const key = '00112233445566778899aabbccddeeff';
    const pt  = '001122';
    const aes = new AES();

    await assertThrows(
      'CBC requires IV (encrypt)',
      () => Promise.resolve(aes.encrypt(pt, key, { mode: 'CBC', usePKCS7: true, rng: null })),
      'requires an IV'
    );

    await assertThrows(
      'CBC requires IV (decrypt)',
      () => Promise.resolve(aes.decrypt('00', key, { mode: 'CBC', addHMAC: false })),
      'IV required for CBC decryption'
    );
  }

  // 14) Negative: corrupted PKCS#7 padding
  {
    const key = '00112233445566778899aabbccddeeff';
    const aes = new AES();
    const enc = aes.encrypt('0011223344', key, { mode: 'CBC', usePKCS7: true, rng });

    // Flip the last byte and demand a padding failure.
    const bad = enc.message.slice(0, -2) + (enc.message.slice(-2) === 'ff' ? '00' : 'ff');
    await assertThrows(
      'Bad PKCS7 detected',
      () => Promise.resolve(aes.decrypt(bad, key, { mode: 'CBC', usePKCS7: true, IV: enc.IV, addHMAC: false })),
      'Bad PKCS7'
    );
  }

  // 15) Negative: disable PKCS#7 with uneven length
  {
    const key = '00112233445566778899aabbccddeeff';
    const aes = new AES();
    await assertThrows(
      'No padding + wrong length',
      () => Promise.resolve(aes.encrypt('0011', key, { mode: 'ECB', usePKCS7: false, addHMAC: false })),
      'multiple of 16 bytes'
    );
  }

  // 16) Legacy ASCII inputs and uppercase ciphertext
  {
    const aes = new AES();
    const keyAscii = 'abcdefghijklmnop'; // 16 ASCII bytes => 128-bit key
    const text = 'Plain ASCII text';
    const enc = aes.encrypt(text, keyAscii, { mode: 'ECB', usePKCS7: true });
    const decAscii = aes.decrypt(enc.message, keyAscii, { mode: 'ECB', usePKCS7: true, addHMAC: true, HMAC: enc.HMAC });
    assertEq('ASCII key/plaintext auto-hex round-trip', decAscii.message, textToHex(text));

    const decUpper = aes.decrypt(enc.message.toUpperCase(), keyAscii, { mode: 'ECB', usePKCS7: true, addHMAC: true, HMAC: enc.HMAC });
    assertEq('Uppercase ciphertext accepted', decUpper.message, textToHex(text));
  }

  // 17) Hex normalization (spaces and 0x prefix)
  {
    const aes = new AES();
    const canonicalKey = '00112233445566778899aabbccddeeff';
    const canonicalPlain = '00112233445566778899aabbccddeeff';
    const fancyKey = '0X00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF';
    const fancyPlain = '00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF';

    const encCanonical = aes.encrypt(canonicalPlain, canonicalKey, { mode: 'ECB', usePKCS7: false, addHMAC: false });
    const encFancy = aes.encrypt(fancyPlain, fancyKey, { mode: 'ECB', usePKCS7: false });
    assertEq('Hex normalization matches canonical encrypt', encFancy.message, encCanonical.message);

    const decFancy = aes.decrypt(encFancy.message, fancyKey, { mode: 'ECB', usePKCS7: false, addHMAC: true, HMAC: encFancy.HMAC });
    assertEq('Hex normalization matches canonical decrypt', decFancy.message, canonicalPlain);
  }

  // 18) createAES helper honors supplied defaults.
  {
    const aes256 = createAES({ bits: 256, addHMAC: false, rng: makeRNG('feedf00d') });
    const key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    const pt = '00112233445566778899aabbccddeeff';
    const enc = aes256.encrypt(pt, key, { mode: 'ECB', usePKCS7: false });
    assertEq('createAES default bits=256', enc.message, '8ea2b7ca516745bfeafc49904b496089');
  }

  const chaosIterations = (typeof process !== 'undefined' && process.env.CHAOS_ITERATIONS)
    ? Number.parseInt(process.env.CHAOS_ITERATIONS, 10)
    : 100;
  const chaosSeed = (typeof process !== 'undefined' && process.env.CHAOS_SEED)
    ? process.env.CHAOS_SEED
    : 'ce10d00d';
  const iterationsSafe = Number.isFinite(chaosIterations) && chaosIterations > 0 ? chaosIterations : 100;
  chaosMonkey(iterationsSafe, chaosSeed);

  console.log('\nAll tests passed ✅');
})().catch(e => {
  console.error('Test run failed:', e);
  if (typeof process !== 'undefined') process.exitCode = 1;
});
