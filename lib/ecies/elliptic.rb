# frozen_string_literal: true

require "secp256k1"
require_relative "symmetric"
require_relative "hash"

module Ecies
  # Generates a new random Secp256k1 private key.
  # @return [Secp256k1::PrivateKey] The generated private key.
  def generate_key
    loop do
      sk = Secp256k1::PrivateKey.new
      return sk
    rescue ArgumentError
    end
  end

  # Performs elliptic key encapsulation.
  #
  # @param private_key [String] Private key bytes
  # @param peer_public_key [String] Peer's public key bytes
  # @param is_compressed [Boolean] Whether to use compressed format (default: false)
  #
  # @return [String] HKDF-SHA256 derived 32-byte key
  def encapsulate(private_key, peer_public_key, is_compressed = false)
    sk = Secp256k1::PrivateKey.new(privkey: private_key, raw: true)
    peer_pk = Secp256k1::PublicKey.new(pubkey: peer_public_key, raw: true)
    shared_point = peer_pk.tweak_mul(private_key)

    master = sk.pubkey.serialize(compressed: is_compressed) +
      shared_point.serialize(compressed: is_compressed)
    derive_key(master)
  end

  # Performs elliptic key decapsulation.
  # @param public_key [String] Public key bytes
  # @param peer_private_key [String] Peer's private key bytes
  # @param is_compressed [Boolean] Whether to use compressed format (default: false)
  # @return [String] HKDF-SHA256 derived 32-byte key
  def decapsulate(public_key, peer_private_key, is_compressed = false)
    pk = Secp256k1::PublicKey.new(pubkey: public_key, raw: true)
    shared_point = pk.tweak_mul(peer_private_key)
    master = pk.serialize(compressed: is_compressed) +
      shared_point.serialize(compressed: is_compressed)
    derive_key(master)
  end

  module_function :generate_key, :encapsulate, :decapsulate
end
