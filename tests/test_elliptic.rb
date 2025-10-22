# frozen_string_literal: true

require "minitest/autorun"

require "ecies/elliptic"
require "ecies/hex"

class TestElliptic < Minitest::Test
  include Ecies

  def setup
    @raw_sk = "\x00" * 31 + "\x02" # Private key 2
    @raw_peer_sk = "\x00" * 31 + "\x03" # Private key 3
  end

  def test_encapsulate_decapsulate_with_known_values
    sk = Secp256k1::PrivateKey.new(privkey: @raw_sk, raw: true)
    raw_pk = sk.pubkey.serialize(compressed: true)
    peer_sk = Secp256k1::PrivateKey.new(privkey: @raw_peer_sk, raw: true)
    raw_peer_pk = peer_sk.pubkey.serialize(compressed: true)

    # compressed: false
    encapsulated = encapsulate(@raw_sk, raw_peer_pk)
    assert_equal encapsulated, decapsulate(raw_pk, @raw_peer_sk)

    expected = decode_hex("6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82")
    assert_equal expected, encapsulated

    # compressed: true
    encapsulated = encapsulate(@raw_sk, raw_peer_pk, true)
    assert_equal encapsulated, decapsulate(raw_pk, @raw_peer_sk, true)
    expected = decode_hex("b192b226edb3f02da11ef9c6ce4afe1c7e40be304e05ae3b988f4834b1cb6c69")
    assert_equal expected, encapsulated
  end
end
