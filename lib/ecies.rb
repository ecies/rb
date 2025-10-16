# frozen_string_literal: true

require "ecies/config"
require "ecies/hex"
require "ecies/hash"
require "ecies/elliptic"
require "ecies/symmetric"

module Ecies
  COMPRESSED_PUBLIC_KEY_SIZE = 33
  UNCOMPRESSED_PUBLIC_KEY_SIZE = 65

  # Encrypt with receiver's public key
  #
  # @param [String] receiver_pk The receiver's public key (serialized, raw bytes).
  # @param [String] data The plaintext data to encrypt (raw bytes).
  # @param [Ecies::Config] config The configuration object (optional).
  # @return [String] The encrypted data (ephemeral public key + encrypted data).
  def encrypt(receiver_pk, data, config = DEFAULT_CONFIG)
    ephemeral_sk = generate_key
    raw_ephemeral_sk = decode_hex(ephemeral_sk.send(:serialize))
    ephemeral_pk = ephemeral_sk.pubkey.serialize(compressed: config.is_ephemeral_key_compressed)
    sym_key = encapsulate(raw_ephemeral_sk, receiver_pk, config.is_hkdf_key_compressed)
    encrypted = sym_encrypt(:"aes-256-gcm", sym_key, data, config.symmetric_nonce_length)
    ephemeral_pk + encrypted
  end

  # Decrypt with receiver's secret key
  #
  # @param [String] receiver_sk The receiver's secret key (serialized, raw bytes).
  # @param [String] data The encrypted data (ephemeral public key + encrypted data).
  # @param [Ecies::Config] config The configuration object (optional).
  # @return [String] The decrypted plaintext data (raw bytes).
  def decrypt(receiver_sk, data, config = DEFAULT_CONFIG)
    pk_size = config.is_ephemeral_key_compressed ?
      COMPRESSED_PUBLIC_KEY_SIZE : UNCOMPRESSED_PUBLIC_KEY_SIZE
    ephemeral_pk = data[0, pk_size]
    encrypted = data[pk_size..]
    sym_key = decapsulate(ephemeral_pk, receiver_sk, config.is_hkdf_key_compressed)
    sym_decrypt(:"aes-256-gcm", sym_key, encrypted, config.symmetric_nonce_length)
  end

  module_function :encrypt, :decrypt
end
