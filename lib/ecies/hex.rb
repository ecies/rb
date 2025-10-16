# frozen_string_literal: true

module Ecies
  # Decodes a hex string (with optional "0x" prefix) into raw bytes.
  # @param [String] str The hex string to decode.
  # return [String] The decoded raw bytes.
  def decode_hex(str)
    if str.start_with?("0x", "0X")
      str = str[2..]
    end
    [str].pack("H*")
  end

  # Encodes raw bytes into a hex string without "0x" prefix.
  # @param [String] bytes The raw bytes to encode.
  # @return [String] The encoded hex string without "0x" prefix.
  def encode_hex(bytes)
    bytes.unpack1("H*")
  end

  module_function :decode_hex, :encode_hex
end
