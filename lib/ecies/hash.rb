# frozen_string_literal: true

require "openssl"

module Ecies
  # Derives a 32-byte key from the given master key using HKDF with SHA256.
  #
  # @param master [String] The input master key (binary string).
  # @return [String] The derived 32-byte key (binary string).
  def derive_key(master)
    OpenSSL::KDF.hkdf(master, salt: "", info: "", length: 32, hash: "SHA256")
  end

  module_function :derive_key
end
