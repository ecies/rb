# frozen_string_literal: true

require "minitest/autorun"

require "ecies"
require "ecies/elliptic"
require "ecies/hex"

class TestEcies < Minitest::Test
  include Ecies

  def setup
    @data = "Hello, World!"
    @python_backend = "https://demo.ecies.org/"
  end

  def _call_api(data)
    require "net/http"
    require "uri"

    uri = URI.parse(@python_backend)
    request = Net::HTTP::Post.new(uri)
    request["Content-Type"] = "application/x-www-form-urlencoded"
    request.body = data.map { |k, v| "#{k}=#{v}" }.join("&")

    Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
      http.request(request)
    end
  end

  private :_call_api

  def test_encrypt_decrypt
    sk = generate_key
    raw_sk = decode_hex(sk.send(:serialize))
    raw_pk = sk.pubkey.serialize(compressed: false)
    encrypted = encrypt(raw_pk, @data)
    decrypted = decrypt(raw_sk, encrypted)
    assert_equal @data, decrypted
  end

  def test_encrypt_decrypt_with_config
    config = Config.new(
      is_ephemeral_key_compressed: true,
      is_hkdf_key_compressed: true,
      symmetric_nonce_length: 12
    )
    sk = generate_key
    raw_sk = decode_hex(sk.send(:serialize))
    raw_pk = sk.pubkey.serialize(compressed: false)
    encrypted = encrypt(raw_pk, @data, config)
    decrypted = decrypt(raw_sk, encrypted, config)
    assert_equal @data, decrypted
  end

  def test_encrypt_decrypt_with_known_values
    raw_sk = decode_hex("5b5b1a0ff51e4350badd6f58d9e6fa6f57fbdbde6079d12901770dda3b803081")
    raw_pk = decode_hex("048e41409f2e109f2d704f0afd15d1ab53935fd443729913a7e8536b4cef8cf5773d4db7bbd99e9ed64595e24a251c9836f35d4c9842132443c17f6d501b3410d2")
    encrypted = encrypt(raw_pk, @data)
    decrypted = decrypt(raw_sk, encrypted)
    assert_equal @data, decrypted
  end

  def test_encrypt_with_python_backend
    sk = generate_key
    raw_sk = decode_hex(sk.send(:serialize))
    raw_pk = sk.pubkey.serialize(compressed: false)

    # Encrypt with Python backend
    response = _call_api(
      {
        "pub" => encode_hex(raw_pk),
        "data" => @data
      }
    )
    encrypted = decode_hex(response.body)
    # Decrypt with our implementation
    decrypted = decrypt(raw_sk, encrypted)
    assert_equal @data, decrypted
  end

  def test_decrypt_with_python_backend
    sk = generate_key
    raw_sk = decode_hex(sk.send(:serialize))
    raw_pk = sk.pubkey.serialize(compressed: false)

    # Encrypt with our implementation
    encrypted = encrypt(raw_pk, @data)
    # Decrypt with Python backend
    response = _call_api(
      {
        "prv" => encode_hex(raw_sk),
        "data" => encode_hex(encrypted)
      }
    )
    decrypted = response.body
    assert_equal @data, decrypted
  end
end
