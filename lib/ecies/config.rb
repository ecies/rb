# frozen_string_literal: true

module Ecies
  # Configuration class for ECIES settings.
  class Config
    attr_accessor :is_ephemeral_key_compressed, :is_hkdf_key_compressed, :symmetric_nonce_length

    def initialize(
      is_ephemeral_key_compressed: false,
      is_hkdf_key_compressed: false,
      symmetric_nonce_length: 16
    )
      @is_ephemeral_key_compressed = is_ephemeral_key_compressed
      @is_hkdf_key_compressed = is_hkdf_key_compressed
      @symmetric_nonce_length = symmetric_nonce_length
    end
  end

  DEFAULT_CONFIG = Config.new
end
