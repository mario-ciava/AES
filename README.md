# Legacy Version of AES

## Overview

This branch contains the **legacy version** of the AES implementation. It serves as a historical reference for the project's initial development stages. This version is very limited and only supports encrypting single 128-bit blocks at a time. It does not support additional features or extended modes of operation.

## Important Notice

This version is maintained here for archival purposes and to demonstrate the evolution of the project. **It is not intended for practical use** due to its limited functionality.

## Usage Example (For Reference Only)

To use the legacy implementation, follow this basic usage structure:

```javascript
// Example usage for encryption (16-character text and password)
const encrypted = new AES(128).encrypt("16charplaintext", "16charpassword1");

// Example usage for decryption (16-character text and password)
const decrypted = new AES(128).decrypt(encrypted, "16charpassword1");
```

### Parameters:
- `bits`: AES key size, which can be 128 bits.
- `text`: A message of exactly 16 characters you want to encrypt or decrypt.
- `password`: A 16-character key used for the encryption or decryption.
