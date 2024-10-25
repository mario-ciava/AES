import { AES } from './cipher.mjs';

const simpleTest = () => {
  const aes = new AES();
  const key = '0123456789abcdef0123456789abcdef';
  const plaintext = '00112233445566778899aabbccddeeff';
  const options = {
    bits: 128,
    mode: 'CBC',
    usePKCS7: false,
    IV: '00000000000000000000000000000000',
  };

  const encrypted = aes.encrypt(plaintext, key, options);
  console.log(`Encrypted: ${encrypted.message}`);

  const decrypted = aes.decrypt(encrypted.message, key, options);
  console.log(`Decrypted: ${decrypted.message}`);

  console.assert(decrypted.message === plaintext, 'Decryption failed');

  console.log('Simple encryption/decryption test completed.');
};

simpleTest();

const runTests = () => {
  const aes = new AES();

  const testGroups = [
    {
      options: {
        bits: 128,
        mode: 'CBC',
        usePKCS7: false,
        IV: '00000000000000000000000000000000',
      },
      operation: 'encrypt',
      testCases: [
        {
          count: 0,
          key: '00000000000000000000000000000000',
          plaintext: 'f34481ec3cc627bacd5dc3fb08f273e6',
          expected: '0336763e966d92595a567cc9ce537f5e',
        },
        {
          count: 1,
          key: '00000000000000000000000000000000',
          plaintext: '9798c4640bad75c7c3227db910174e72',
          expected: 'a9a1631bf4996954ebc093957b234589',
        },
        {
          count: 2,
          key: '00000000000000000000000000000000',
          plaintext: '96ab5c2ff612d9dfaae8c31f30c42168',
          expected: 'ff4f8391a6a40ca5b25d23bedd44a597',
        },
        {
          count: 3,
          key: '00000000000000000000000000000000',
          plaintext: '6a118a874519e64e9963798a503f1d35',
          expected: 'dc43be40be0e53712f7e2bf5ca707209',
        },
        {
          count: 4,
          key: '00000000000000000000000000000000',
          plaintext: 'cb9fceec81286ca3e989bd979b0cb284',
          expected: '92beedab1895a94faa69b632e5cc47ce',
        },
        {
          count: 5,
          key: '00000000000000000000000000000000',
          plaintext: 'b26aeb1874e47ca8358ff22378f09144',
          expected: '459264f4798f6a78bacb89c15ed3d601',
        },
        {
          count: 6,
          key: '00000000000000000000000000000000',
          plaintext: '58c8e00b2631686d54eab84b91f0aca1',
          expected: '08a4e2efec8a8e3312ca7460b9040bbf',
        },
      ],
    },
    {
      options: {
        bits: 128,
        mode: 'CBC',
        usePKCS7: false,
        IV: '00000000000000000000000000000000',
      },
      operation: 'decrypt',
      testCases: [
        {
          count: 0,
          key: '00000000000000000000000000000000',
          ciphertext: '0336763e966d92595a567cc9ce537f5e',
          expected: 'f34481ec3cc627bacd5dc3fb08f273e6',
        },
        {
          count: 1,
          key: '00000000000000000000000000000000',
          ciphertext: 'a9a1631bf4996954ebc093957b234589',
          expected: '9798c4640bad75c7c3227db910174e72',
        },
        {
          count: 2,
          key: '00000000000000000000000000000000',
          ciphertext: 'ff4f8391a6a40ca5b25d23bedd44a597',
          expected: '96ab5c2ff612d9dfaae8c31f30c42168',
        },
        {
          count: 3,
          key: '00000000000000000000000000000000',
          ciphertext: 'dc43be40be0e53712f7e2bf5ca707209',
          expected: '6a118a874519e64e9963798a503f1d35',
        },
        {
          count: 4,
          key: '00000000000000000000000000000000',
          ciphertext: '92beedab1895a94faa69b632e5cc47ce',
          expected: 'cb9fceec81286ca3e989bd979b0cb284',
        },
        {
          count: 5,
          key: '00000000000000000000000000000000',
          ciphertext: '459264f4798f6a78bacb89c15ed3d601',
          expected: 'b26aeb1874e47ca8358ff22378f09144',
        },
        {
          count: 6,
          key: '00000000000000000000000000000000',
          ciphertext: '08a4e2efec8a8e3312ca7460b9040bbf',
          expected: '58c8e00b2631686d54eab84b91f0aca1',
        },
      ],
    },
    {
      options: {
        bits: 192,
        mode: 'CBC',
        usePKCS7: false,
        IV: '00000000000000000000000000000000',
      },
      operation: 'encrypt',
      testCases: [
        {
          count: 0,
          key: '000000000000000000000000000000000000000000000000',
          plaintext: '1b077a6af4b7f98229de786d7516b639',
          expected: '275cfc0413d8ccb70513c3859b1d0f72',
        },
        {
          count: 1,
          key: '000000000000000000000000000000000000000000000000',
          plaintext: '9c2d8842e5f48f57648205d39a239af1',
          expected: 'c9b8135ff1b5adc413dfd053b21bd96d',
        },
        {
          count: 2,
          key: '000000000000000000000000000000000000000000000000',
          plaintext: 'bff52510095f518ecca60af4205444bb',
          expected: '4a3650c3371ce2eb35e389a171427440',
        },
        {
          count: 3,
          key: '000000000000000000000000000000000000000000000000',
          plaintext: '51719783d3185a535bd75adc65071ce1',
          expected: '4f354592ff7c8847d2d0870ca9481b7c',
        },
        {
          count: 4,
          key: '000000000000000000000000000000000000000000000000',
          plaintext: '26aa49dcfe7629a8901a69a9914e6dfd',
          expected: 'd5e08bf9a182e857cf40b3a36ee248cc',
        },
        {
          count: 5,
          key: '000000000000000000000000000000000000000000000000',
          plaintext: '941a4773058224e1ef66d10e0a6ee782',
          expected: '067cd9d3749207791841562507fa9626',
        },
      ],
    },
    {
      options: {
        bits: 192,
        mode: 'CBC',
        usePKCS7: false,
        IV: '00000000000000000000000000000000',
      },
      operation: 'decrypt',
      testCases: [
        {
          count: 0,
          key: '000000000000000000000000000000000000000000000000',
          ciphertext: '275cfc0413d8ccb70513c3859b1d0f72',
          expected: '1b077a6af4b7f98229de786d7516b639',
        },
        {
          count: 1,
          key: '000000000000000000000000000000000000000000000000',
          ciphertext: 'c9b8135ff1b5adc413dfd053b21bd96d',
          expected: '9c2d8842e5f48f57648205d39a239af1',
        },
        {
          count: 2,
          key: '000000000000000000000000000000000000000000000000',
          ciphertext: '4a3650c3371ce2eb35e389a171427440',
          expected: 'bff52510095f518ecca60af4205444bb',
        },
        {
          count: 3,
          key: '000000000000000000000000000000000000000000000000',
          ciphertext: '4f354592ff7c8847d2d0870ca9481b7c',
          expected: '51719783d3185a535bd75adc65071ce1',
        },
        {
          count: 4,
          key: '000000000000000000000000000000000000000000000000',
          ciphertext: 'd5e08bf9a182e857cf40b3a36ee248cc',
          expected: '26aa49dcfe7629a8901a69a9914e6dfd',
        },
        {
          count: 5,
          key: '000000000000000000000000000000000000000000000000',
          ciphertext: '067cd9d3749207791841562507fa9626',
          expected: '941a4773058224e1ef66d10e0a6ee782',
        },
      ],
    },
    {
      options: {
        bits: 256,
        mode: 'CBC',
        usePKCS7: false,
        IV: '00000000000000000000000000000000',
      },
      operation: 'encrypt',
      testCases: [
        {
          count: 0,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          plaintext: '014730f80ac625fe84f026c60bfd547d',
          expected: '5c9d844ed46f9885085e5d6a4f94c7d7',
        },
        {
          count: 1,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          plaintext: '0b24af36193ce4665f2825d7b4749c98',
          expected: 'a9ff75bd7cf6613d3731c77c3b6d0c04',
        },
        {
          count: 2,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          plaintext: '761c1fe41a18acf20d241650611d90f1',
          expected: '623a52fcea5d443e48d9181ab32c7421',
        },
        {
          count: 3,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          plaintext: '8a560769d605868ad80d819bdba03771',
          expected: '38f2c7ae10612415d27ca190d27da8b4',
        },
        {
          count: 4,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          plaintext: '91fbef2d15a97816060bee1feaa49afe',
          expected: '1bc704f1bce135ceb810341b216d7abe',
        },
      ],
    },
    {
      options: {
        bits: 256,
        mode: 'CBC',
        usePKCS7: false,
        IV: '00000000000000000000000000000000',
      },
      operation: 'decrypt',
      testCases: [
        {
          count: 0,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          ciphertext: '5c9d844ed46f9885085e5d6a4f94c7d7',
          expected: '014730f80ac625fe84f026c60bfd547d',
        },
        {
          count: 1,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          ciphertext: 'a9ff75bd7cf6613d3731c77c3b6d0c04',
          expected: '0b24af36193ce4665f2825d7b4749c98',
        },
        {
          count: 2,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          ciphertext: '623a52fcea5d443e48d9181ab32c7421',
          expected: '761c1fe41a18acf20d241650611d90f1',
        },
        {
          count: 3,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          ciphertext: '38f2c7ae10612415d27ca190d27da8b4',
          expected: '8a560769d605868ad80d819bdba03771',
        },
        {
          count: 4,
          key: '0000000000000000000000000000000000000000000000000000000000000000',
          ciphertext: '1bc704f1bce135ceb810341b216d7abe',
          expected: '91fbef2d15a97816060bee1feaa49afe',
        },
      ],
    },
    {
      options: {
        bits: 128,
        mode: 'CBC',
        usePKCS7: false,
        IV: '00000000000000000000000000000000',
      },
      operation: 'encrypt',
      testCases: [
        {
          count: 0,
          key: '10a58869d74be5a374cf867cfb473859',
          plaintext: '00000000000000000000000000000000',
          expected: '6d251e6944b051e04eaa6fb4dbf78465',
        },
        {
          count: 1,
          key: 'caea65cdbb75e9169ecd22ebe6e54675',
          plaintext: '00000000000000000000000000000000',
          expected: '6e29201190152df4ee058139def610bb',
        },
        {
          count: 2,
          key: 'a2e2fa9baf7d20822ca9f0542f764a41',
          plaintext: '00000000000000000000000000000000',
          expected: 'c3b44b95d9d2f25670eee9a0de099fa3',
        },
        {
          count: 3,
          key: 'b6364ac4e1de1e285eaf144a2415f7a0',
          plaintext: '00000000000000000000000000000000',
          expected: '5d9b05578fc944b3cf1ccf0e746cd581',
        },
        {
          count: 4,
          key: '64cf9c7abc50b888af65f49d521944b2',
          plaintext: '00000000000000000000000000000000',
          expected: 'f7efc89d5dba578104016ce5ad659c05',
        },
        {
          count: 5,
          key: '47d6742eefcc0465dc96355e851b64d9',
          plaintext: '00000000000000000000000000000000',
          expected: '0306194f666d183624aa230a8b264ae7',
        },
        {
          count: 6,
          key: '3eb39790678c56bee34bbcdeccf6cdb5',
          plaintext: '00000000000000000000000000000000',
          expected: '858075d536d79ccee571f7d7204b1f67',
        },
        {
          count: 7,
          key: '64110a924f0743d500ccadae72c13427',
          plaintext: '00000000000000000000000000000000',
          expected: '35870c6a57e9e92314bcb8087cde72ce',
        },
        {
          count: 8,
          key: '18d8126516f8a12ab1a36d9f04d68e51',
          plaintext: '00000000000000000000000000000000',
          expected: '6c68e9be5ec41e22c825b7c7affb4363',
        },
        {
          count: 9,
          key: 'f530357968578480b398a3c251cd1093',
          plaintext: '00000000000000000000000000000000',
          expected: 'f5df39990fc688f1b07224cc03e86cea',
        },
        {
          count: 10,
          key: 'da84367f325d42d601b4326964802e8e',
          plaintext: '00000000000000000000000000000000',
          expected: 'bba071bcb470f8f6586e5d3add18bc66',
        },
        {
          count: 11,
          key: 'e37b1c6aa2846f6fdb413f238b089f23',
          plaintext: '00000000000000000000000000000000',
          expected: '43c9f7e62f5d288bb27aa40ef8fe1ea8',
        },
        {
          count: 12,
          key: '6c002b682483e0cabcc731c253be5674',
          plaintext: '00000000000000000000000000000000',
          expected: '3580d19cff44f1014a7c966a69059de5',
        },
        {
          count: 13,
          key: '143ae8ed6555aba96110ab58893a8ae1',
          plaintext: '00000000000000000000000000000000',
          expected: '806da864dd29d48deafbe764f8202aef',
        },
        {
          count: 14,
          key: 'b69418a85332240dc82492353956ae0c',
          plaintext: '00000000000000000000000000000000',
          expected: 'a303d940ded8f0baff6f75414cac5243',
        },
        {
          count: 15,
          key: '71b5c08a1993e1362e4d0ce9b22b78d5',
          plaintext: '00000000000000000000000000000000',
          expected: 'c2dabd117f8a3ecabfbb11d12194d9d0',
        },
        {
          count: 16,
          key: 'e234cdca2606b81f29408d5f6da21206',
          plaintext: '00000000000000000000000000000000',
          expected: 'fff60a4740086b3b9c56195b98d91a7b',
        },
        {
          count: 17,
          key: '13237c49074a3da078dc1d828bb78c6f',
          plaintext: '00000000000000000000000000000000',
          expected: '8146a08e2357f0caa30ca8c94d1a0544',
        },
        {
          count: 18,
          key: '3071a2a48fe6cbd04f1a129098e308f8',
          plaintext: '00000000000000000000000000000000',
          expected: '4b98e06d356deb07ebb824e5713f7be3',
        },
        {
          count: 19,
          key: '90f42ec0f68385f2ffc5dfc03a654dce',
          plaintext: '00000000000000000000000000000000',
          expected: '7a20a53d460fc9ce0423a7a0764c6cf2',
        },
        {
          count: 20,
          key: 'febd9a24d8b65c1c787d50a4ed3619a9',
          plaintext: '00000000000000000000000000000000',
          expected: 'f4a70d8af877f9b02b4c40df57d45b17',
        },
      ],
    },
    {
      options: {
        bits: 128,
        mode: 'CBC',
        usePKCS7: false,
        IV: '00000000000000000000000000000000',
      },
      operation: 'decrypt',
      testCases: [
        {
          count: 0,
          key: '10a58869d74be5a374cf867cfb473859',
          ciphertext: '6d251e6944b051e04eaa6fb4dbf78465',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 1,
          key: 'caea65cdbb75e9169ecd22ebe6e54675',
          ciphertext: '6e29201190152df4ee058139def610bb',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 2,
          key: 'a2e2fa9baf7d20822ca9f0542f764a41',
          ciphertext: 'c3b44b95d9d2f25670eee9a0de099fa3',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 3,
          key: 'b6364ac4e1de1e285eaf144a2415f7a0',
          ciphertext: '5d9b05578fc944b3cf1ccf0e746cd581',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 4,
          key: '64cf9c7abc50b888af65f49d521944b2',
          ciphertext: 'f7efc89d5dba578104016ce5ad659c05',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 5,
          key: '47d6742eefcc0465dc96355e851b64d9',
          ciphertext: '0306194f666d183624aa230a8b264ae7',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 6,
          key: '3eb39790678c56bee34bbcdeccf6cdb5',
          ciphertext: '858075d536d79ccee571f7d7204b1f67',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 7,
          key: '64110a924f0743d500ccadae72c13427',
          ciphertext: '35870c6a57e9e92314bcb8087cde72ce',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 8,
          key: '18d8126516f8a12ab1a36d9f04d68e51',
          ciphertext: '6c68e9be5ec41e22c825b7c7affb4363',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 9,
          key: 'f530357968578480b398a3c251cd1093',
          ciphertext: 'f5df39990fc688f1b07224cc03e86cea',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 10,
          key: 'da84367f325d42d601b4326964802e8e',
          ciphertext: 'bba071bcb470f8f6586e5d3add18bc66',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 11,
          key: 'e37b1c6aa2846f6fdb413f238b089f23',
          ciphertext: '43c9f7e62f5d288bb27aa40ef8fe1ea8',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 12,
          key: '6c002b682483e0cabcc731c253be5674',
          ciphertext: '3580d19cff44f1014a7c966a69059de5',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 13,
          key: '143ae8ed6555aba96110ab58893a8ae1',
          ciphertext: '806da864dd29d48deafbe764f8202aef',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 14,
          key: 'b69418a85332240dc82492353956ae0c',
          ciphertext: 'a303d940ded8f0baff6f75414cac5243',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 15,
          key: '71b5c08a1993e1362e4d0ce9b22b78d5',
          ciphertext: 'c2dabd117f8a3ecabfbb11d12194d9d0',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 16,
          key: 'e234cdca2606b81f29408d5f6da21206',
          ciphertext: 'fff60a4740086b3b9c56195b98d91a7b',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 17,
          key: '13237c49074a3da078dc1d828bb78c6f',
          ciphertext: '8146a08e2357f0caa30ca8c94d1a0544',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 18,
          key: '3071a2a48fe6cbd04f1a129098e308f8',
          ciphertext: '4b98e06d356deb07ebb824e5713f7be3',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 19,
          key: '90f42ec0f68385f2ffc5dfc03a654dce',
          ciphertext: '7a20a53d460fc9ce0423a7a0764c6cf2',
          expected: '00000000000000000000000000000000',
        },
        {
          count: 20,
          key: 'febd9a24d8b65c1c787d50a4ed3619a9',
          ciphertext: 'f4a70d8af877f9b02b4c40df57d45b17',
          expected: '00000000000000000000000000000000',
        },
      ],
    },
  ];

  const runTestCases = (aes, testCases, options, operation) => {
    testCases.forEach(({ count, key, plaintext, ciphertext, expected }) => {
      const input = plaintext || ciphertext;
      const result = aes[operation](input, key, options);
      const output = result.message;
      console.assert(
        output === expected,
        `${operation === 'encrypt' ? 'Encryption' : 'Decryption'} Test ${count} failed. Expected: ${expected}, got: ${output}`
      );
    });
  };

  testGroups.forEach(({ testCases, options, operation }) => {
    runTestCases(aes, testCases, options, operation);
  });

  console.log('All tests completed.');
};

//runTests(); //UNCOMMENT TO DO THESE TESTS