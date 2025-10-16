# frozen_string_literal: true

require "minitest/autorun"
require "openssl"

require "ecies/symmetric"

class TestSymmetric < Minitest::Test
  include Ecies

  def setup
    @algorithm = :"aes-256-gcm"
    @key = OpenSSL::Random.random_bytes(32)
    @nonce_length = 16
    @plain_text = "Hello, World!"
  end

  def test_sym_decrypt_with_known_values
    plain_text = decode_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000")
    cipher_text = decode_hex("28e1c5232f4ee8161dbe4c036309e0b3254e9212bef0a93431ce5e5604c8f6a73c18a3183018b770")
    key = decode_hex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
    nonce = decode_hex("5c2ea9b695fcf6e264b96074d6bfa572")
    tag = decode_hex("d5808a1bd11a01129bf3c6919aff2339")
    decrypted = sym_decrypt(@algorithm, key, nonce + tag + cipher_text, @nonce_length)
    assert_equal plain_text, decrypted
  end

  def test_sym_encrypt_returns_correct_format
    cipher_text = sym_encrypt(@algorithm, @key, @plain_text, @nonce_length)

    # Should return nonce + tag + ciphertext
    # nonce: 16 bytes, tag: 16 bytes, ciphertext: at least as long as plaintext
    assert cipher_text.length >= @nonce_length + 16 + @plain_text.length
  end

  def test_sym_encrypt_decrypt_round_trip
    cipher_text = sym_encrypt(@algorithm, @key, @plain_text, @nonce_length)
    decrypted = sym_decrypt(@algorithm, @key, cipher_text, @nonce_length)

    assert_equal @plain_text, decrypted
  end

  def test_sym_encrypt_with_aad
    aad = "additional authenticated data"
    cipher_text = sym_encrypt(@algorithm, @key, @plain_text, @nonce_length, aad)
    decrypted = sym_decrypt(@algorithm, @key, cipher_text, @nonce_length, aad)

    assert_equal @plain_text, decrypted
  end

  def test_sym_decrypt_fails_with_wrong_aad
    aad = "additional authenticated data"
    wrong_aad = "wrong aad"
    cipher_text = sym_encrypt(@algorithm, @key, @plain_text, @nonce_length, aad)

    assert_raises(OpenSSL::Cipher::CipherError) do
      sym_decrypt(@algorithm, @key, cipher_text, @nonce_length, wrong_aad)
    end
  end

  def test_sym_decrypt_fails_with_wrong_key
    cipher_text = sym_encrypt(@algorithm, @key, @plain_text, @nonce_length)
    wrong_key = OpenSSL::Random.random_bytes(32)

    assert_raises(OpenSSL::Cipher::CipherError) do
      sym_decrypt(@algorithm, wrong_key, cipher_text, @nonce_length)
    end
  end

  def test_sym_decrypt_fails_with_tampered_ciphertext
    cipher_text = sym_encrypt(@algorithm, @key, @plain_text, @nonce_length)
    # Tamper with the last byte
    tampered = cipher_text.dup
    tampered[-1] = (tampered[-1].ord ^ 1).chr

    assert_raises(OpenSSL::Cipher::CipherError) do
      sym_decrypt(@algorithm, @key, tampered, @nonce_length)
    end
  end

  def test_sym_encrypt_uses_random_nonce
    cipher_text1 = sym_encrypt(@algorithm, @key, @plain_text, @nonce_length)
    cipher_text2 = sym_encrypt(@algorithm, @key, @plain_text, @nonce_length)

    # Nonces should be different
    nonce1 = cipher_text1[0, @nonce_length]
    nonce2 = cipher_text2[0, @nonce_length]
    refute_equal nonce1, nonce2
  end

  def test_sym_encrypt_with_empty_plaintext
    empty_text = ""
    cipher_text = sym_encrypt(@algorithm, @key, empty_text, @nonce_length)
    decrypted = sym_decrypt(@algorithm, @key, cipher_text, @nonce_length)

    assert_equal empty_text, decrypted
  end

  def test_sym_encrypt_with_binary_data
    binary_data = "\x00\x01\x02\xFF\xFE\xFD"
    cipher_text = sym_encrypt(@algorithm, @key, binary_data, @nonce_length)
    decrypted = sym_decrypt(@algorithm, @key, cipher_text, @nonce_length)

    assert_equal binary_data.bytes, decrypted.bytes
  end

  def test_sym_encrypt_with_large_plaintext
    large_text = "A" * 10000
    cipher_text = sym_encrypt(@algorithm, @key, large_text, @nonce_length)
    decrypted = sym_decrypt(@algorithm, @key, cipher_text, @nonce_length)

    assert_equal large_text, decrypted
  end

  def test_sym_encrypt_raises_on_unsupported_algorithm
    error = assert_raises(ArgumentError) do
      sym_encrypt(:"aes-128-cbc", @key, @plain_text, @nonce_length)
    end
    assert_match(/Unsupported algorithm/, error.message)
  end

  def test_sym_decrypt_raises_on_unsupported_algorithm
    cipher_text = sym_encrypt(@algorithm, @key, @plain_text, @nonce_length)

    error = assert_raises(ArgumentError) do
      sym_decrypt(:"aes-128-cbc", @key, cipher_text, @nonce_length)
    end
    assert_match(/Unsupported algorithm/, error.message)
  end

  def test_sym_encrypt_with_different_nonce_lengths
    [12, 16].each do |nonce_len|
      cipher_text = sym_encrypt(@algorithm, @key, @plain_text, nonce_len)
      decrypted = sym_decrypt(@algorithm, @key, cipher_text, nonce_len)

      assert_equal @plain_text, decrypted
    end
  end
end
