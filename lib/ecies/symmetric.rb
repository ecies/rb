# frozen_string_literal: true

require "openssl"

module Ecies
  AEAD_TAG_LENGTH = 16

  # Encrypts plain text using symmetric AES-256-GCM encryption.
  #
  # @param algorithm [Symbol] The encryption algorithm to use (must be :aes-256-gcm)
  # @param key [String] The encryption key (must be 32 bytes for AES-256)
  # @param plain_text [String] The data to encrypt
  # @param nonce_length [Integer] The length of the nonce/IV to generate
  # @param aad [String] Additional authenticated data (optional, defaults to empty string)
  #
  # @return [String] The encrypted data formatted as: nonce + auth_tag + cipher_text
  #
  # @raise [ArgumentError] If the algorithm is not :aes-256-gcm
  #
  # @example
  #   key = OpenSSL::Random.random_bytes(32)
  #   encrypted = Ecies.sym_encrypt(:"aes-256-gcm", key, "Hello World", 12)
  def sym_encrypt(algorithm, key, plain_text, nonce_length, aad = "")
    if algorithm != :"aes-256-gcm"
      raise ArgumentError, "Unsupported algorithm: #{algorithm}"
    end

    nonce = OpenSSL::Random.random_bytes(nonce_length)
    cipher = OpenSSL::Cipher.new(algorithm.to_s).encrypt
    cipher.key = key
    cipher.iv_len = nonce_length
    cipher.iv = nonce
    cipher.auth_data = aad

    cipher_text = cipher.update(plain_text) + cipher.final
    tag = cipher.auth_tag
    nonce + tag + cipher_text
  end

  # Decrypts cipher text that was encrypted using symmetric AES-256-GCM encryption.
  #
  # @param algorithm [Symbol] The encryption algorithm to use (must be :aes-256-gcm)
  # @param key [String] The decryption key (must match the encryption key)
  # @param cipher_text [String] The encrypted data (formatted as: nonce + auth_tag + cipher_text)
  # @param nonce_length [Integer] The length of the nonce/IV used during encryption
  # @param aad [String] Additional authenticated data (must match the value used during encryption)
  #
  # @return [String] The decrypted plain text
  #
  # @raise [ArgumentError] If the algorithm is not :aes-256-gcm
  # @raise [OpenSSL::Cipher::CipherError] If authentication fails or decryption fails
  #
  # @example
  #   key = OpenSSL::Random.random_bytes(32)
  #   encrypted = Ecies.sym_encrypt(:"aes-256-gcm", key, "Hello World", 12)
  #   decrypted = Ecies.sym_decrypt(:"aes-256-gcm", key, encrypted, 12)
  def sym_decrypt(algorithm, key, cipher_text, nonce_length, aad = "")
    if algorithm != :"aes-256-gcm"
      raise ArgumentError, "Unsupported algorithm: #{algorithm}"
    end

    nonce = cipher_text[0, nonce_length]
    tag = cipher_text[nonce_length, AEAD_TAG_LENGTH]
    encrypted = cipher_text[nonce_length + AEAD_TAG_LENGTH..]
    decipher = OpenSSL::Cipher.new(algorithm.to_s).decrypt
    decipher.key = key
    decipher.iv_len = nonce_length
    decipher.iv = nonce
    decipher.auth_tag = tag
    decipher.auth_data = aad
    decipher.update(encrypted) + decipher.final
  end

  module_function :sym_encrypt, :sym_decrypt
end
