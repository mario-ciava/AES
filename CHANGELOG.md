# Changelog
All notable changes to this project will be documented in this file.
This project adheres to [Keep a Changelog](https://keepachangelog.com/) and uses [Semantic Versioning](https://semver.org/).

## [Unreleased]
- (placeholder)

## [0.2.0] - 2025-10-26
### Added
- AES modes **CTR**, **CFB**, **OFB**, **PCBC** and **GCM** implemented in pure JavaScript (including GHASH for GCM).
- `createAES()` factory, `getDefaultAESOptions()` and direct exports for `sha256`, `hmacSha256`, `pbkdf2Sha256`, `timingSafeEqualHex`.
- Support for GCM authentication tags and optional Additional Authenticated Data (`AAD`).
- Extensive Known Answer Tests for CTR/CFB/OFB/GCM plus a 256 KiB CBC stress test.

### Changed
- RNG fallback to `Math.random` removed; a secure RNG must exist or be supplied via `options.rng`.
- `encrypt` / `decrypt` return objects now include `tag` and `AAD` metadata; HMAC is automatically disabled for GCM.
- Chaos fuzzing covers all supported modes and both valid/invalid parameter combinations.
- README rewritten with new examples, configuration details and usage notes for streaming/authenticated modes.

### Fixed
- Normalised handling of legacy UTF-8 vs hex inputs across the new streaming/authenticated modes.
- Consistent IV validation (12-byte support for GCM, 16-byte otherwise) with clearer error messaging.

### Removed
- Legacy prototype augmentation helper (`attachToPrototypes`).

## [0.1.0] - 2024-10-25
### Added
- Initial AES core with ECB and CBC modes (PKCS#7 padding, optional HMAC).
- Pure JS SHA-256, HMAC-SHA256, PBKDF2 helpers.
- Prototype extensions for hex/text conversions.
- Known Answer Tests for AES-128-ECB/CBC.
