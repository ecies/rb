require "ecies"

Ecies::DEFAULT_CONFIG.is_ephemeral_key_compressed = true   # Use compressed ephemeral public key
Ecies::DEFAULT_CONFIG.is_hkdf_key_compressed = true        # Use compressed key for HKDF
Ecies::DEFAULT_CONFIG.symmetric_nonce_length = 16          # Nonce length for AES-GCM (default: 16)

require_relative "quickstart"
