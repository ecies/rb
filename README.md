# eciesrb

[![Gem Version](https://badge.fury.io/rb/eciesrb.svg)](https://badge.fury.io/rb/eciesrb)
[![License](https://img.shields.io/github/license/ecies/rb.svg)](https://github.com/ecies/rb)
[![CI](https://img.shields.io/github/actions/workflow/status/ecies/rb/ci.yml)](https://github.com/ecies/rb/actions)

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Ruby.

This is a Ruby port of [eciespy](https://github.com/ecies/py).

## Prerequisite

Make sure you have secp256k1 and openssl installed, if not:

```bash
brew install secp256k1 openssl
```

Then set environment variables:

```bash
export C_INCLUDE_PATH=$(brew --prefix secp256k1)/include
```

## Install

```bash
gem install eciesrb
```

## Quick Start

```ruby
# examples/quickstart.rb
require "ecies"

# Generate a secret key
sk = Ecies.generate_key
raw_sk = Ecies.decode_hex(sk.send(:serialize))
raw_pk = sk.pubkey.serialize(compressed: false)

# Encrypt data with the receiver's public key
plaintext = "Hello, World!"
encrypted = Ecies.encrypt(raw_pk, plaintext)

# Decrypt data with the receiver's secret key
decrypted = Ecies.decrypt(raw_sk, encrypted)
puts decrypted  # => "Hello, World!"
```

## Sponsors

<a href="https://dotenvx.com"><img alt="dotenvx" src="https://dotenvx.com/logo.png" width="200" height="200"/></a>

## Configuration

You can customize the encryption behavior using a `Config` object:

```ruby
# examples/config.rb
require "ecies"

Ecies::DEFAULT_CONFIG.is_ephemeral_key_compressed = true   # Use compressed ephemeral public key
Ecies::DEFAULT_CONFIG.is_hkdf_key_compressed = true        # Use compressed key for HKDF
Ecies::DEFAULT_CONFIG.symmetric_nonce_length = 16          # Nonce length for AES-GCM (default: 16)
```

### Configuration Parameters

- `is_ephemeral_key_compressed` (Boolean): Whether to use compressed format for the ephemeral public key. Default: `false`
- `is_hkdf_key_compressed` (Boolean): Whether to use compressed format for HKDF key derivation. Default: `false`
- `symmetric_nonce_length` (Integer): The nonce length for AES-GCM encryption. Options: `12`, `16`. Default: `16`

## API Reference

### `encrypt(receiver_pk, data, config = DEFAULT_CONFIG)`

Encrypts data using the receiver's public key.

**Parameters:**

- `receiver_pk` (String): The receiver's public key (raw bytes, serialized)
- `data` (String): The plaintext data to encrypt (raw bytes)
- `config` (Ecies::Config): Optional configuration object

**Returns:** (String) The encrypted data (ephemeral public key + encrypted data)

### `decrypt(receiver_sk, data, config = DEFAULT_CONFIG)`

Decrypts data using the receiver's secret key.

**Parameters:**

- `receiver_sk` (String): The receiver's secret key (raw bytes, serialized)
- `data` (String): The encrypted data (ephemeral public key + encrypted data)
- `config` (Ecies::Config): Optional configuration object

**Returns:** (String) The decrypted plaintext data (raw bytes)

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).
