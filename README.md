
# AES Encryption Library

## Overview
This project implements the **Advanced Encryption Standard (AES)** algorithm in **JavaScript** using Node.js. The goal is to provide a flexible and self-contained library for encrypting and decrypting data without external dependencies. 

## Features
- **Support for 128, 192, and 256-bit keys**.
- **Two modes**: Electronic Codebook (ECB) and Cipher Block Chaining (CBC).
- **PKCS7 Padding**: Automated or manual padding support.
- **Configurable HMAC** for message authentication.
- **Extensible and modular code** design for easy maintenance and enhancements.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Configuration Options](#configuration-options)
- [Example](#example)
- [Running Tests](#running-tests)
- [Future Goals](#future-goals)
- [License](#license)

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/mario-ciava/AES.git
   cd AES
   ```

2. **Install Node.js**:
   This project has been tested with Node.js version 20.18.0. It is recommended to use Node.js version 14 or higher to ensure compatibility and stability. No additional dependencies are required. You can download Node.js from the official [Node.js website](https://nodejs.org/).

## Usage
Import the AES class and create an instance:

```javascript
import { AES } from './cipher_v1.0.mjs';

const aes = new AES();
const options = {
    bits: 128,
    mode: 'CBC',
    deriveKey: true,
    usePKCS7: true,
    addSalt: true,
    addHMAC: true
};

// Example encryption
const { message, IV, salt, HMAC } = aes.encrypt('Hello, World!', 'secret-key', options);

// Example decryption
const decryptedMessage = aes.decrypt(message, 'secret-key', { ...options, IV, salt, HMAC });
console.log(decryptedMessage);
```

## Configuration Options
Below are the available configuration options and their accepted values:

| Option       | Description                                      | Accepted Values                  |
|--------------|--------------------------------------------------|----------------------------------|
| `bits`       | Key size in bits                                 | `[128, 192, 256]`                |
| `mode`       | Encryption mode                                  | `['ECB', 'CBC']`                 |
| `deriveKey`  | Whether to derive a key using a KDF              | `[true, false]`                  |
| `addSalt`    | Whether to add salt during key transformation    | `[true, false]`                  |
| `usePKCS7`   | Enable PKCS7 padding                             | `[true, false]`                  |
| `addHMAC`    | Add HMAC for message authentication              | `[true, false]`                  |

## Example
This example demonstrates encrypting and decrypting a message using a 256-bit key and CBC mode with a derived key and HMAC enabled.

```javascript
const aes = new AES();
const options = {
    bits: 256,
    mode: 'CBC',
    deriveKey: true,
    addSalt: true,
    usePKCS7: true,
    addHMAC: true
};

const result = aes.encrypt('Sensitive Data Here', 'ComplexKey', options);
console.log('Encrypted Message:', result.message);
console.log('IV:', result.IV);
console.log('Salt:', result.salt);
console.log('HMAC:', result.HMAC);

// Decrypting
const decryptedMessage = aes.decrypt(result.message, 'ComplexKey', {
    ...options,
    IV: result.IV,
    salt: result.salt,
    HMAC: result.HMAC
});
console.log('Decrypted Message:', decryptedMessage);
```

## Running Tests
The tests executed are primarily Known-Answer Tests (KAT), designed to verify the correctness of the encryption and decryption processes by comparing the results against pre-validated outputs. These tests ensure that the implementation matches the expected outputs for given inputs. A file containing a subset of the tests that have been executed without errors is available for review. The test data was sourced from the [NIST Cryptographic Algorithm Validation Program (CAVP)](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers). In the future, more extensive debugging and additional test cases will be added to cover edge cases and improve overall reliability.

To perform a simple test, run the following command:

```bash
node test.mjs
```

This will execute a basic encryption and decryption test with predefined values. You can modify the \`key\`, \`plaintext\`, and other options within the \`simpleTest\` function to test different scenarios as needed. This allows for easy experimentation and verification of the implementation's behavior with different configurations.

## Future Goals
- **Support for Additional Modes**: Implement modes like GCM, PCBC, CFB, OFB, and CTR.
- **Enhanced Error Handling**: Build more comprehensive error handling and recovery mechanisms.
- **Optimize Galois Field Operations**: Refactor the operations to eliminate tables like RCON and improve efficiency.
- **Design a Generic Cipher Class**: Make AES an extension of a more generic Cipher class for supporting various cryptographic algorithms.

## License
Copyright © 2024 Mario G. Ciavarella

All rights reserved. This code and all associated files and documentation (the "Software")
are protected by copyright law. Unauthorized copying of this file, via any medium, is
strictly prohibited unless explicitly authorized by the copyright holder.

Permission is hereby granted to use, reproduce, or modify this Software exclusively
for educational, non-commercial, or internal purposes. Any other use requires the prior
written consent of the copyright holder.

DISCLAIMER: This Software is provided "as is", without any warranty of any kind.

For inquiries regarding licensing or use of this code, contact: mariog.ciavarella@icloud.com
