# frozen_string_literal: true

require "minitest/autorun"
require "minitest/unit"
require "openssl"

require "ecies/hash"
require "ecies/hex"

class TestHash < Minitest::Test
  include Ecies

  def test_known
    derived = derive_key(decode_hex("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
    expected = decode_hex("0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")
    assert_equal expected, derived
  end
end
