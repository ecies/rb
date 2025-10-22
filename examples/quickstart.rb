require "ecies"

# Generate a secret key
sk = Ecies.generate_key
raw_sk = Ecies.decode_hex(sk.send(:serialize))
raw_pk = sk.pubkey.serialize(compressed: false)

# Encrypt data with the receiver's public key
plaintext = "Hello, World🌍!"
encrypted = Ecies.encrypt(raw_pk, plaintext)

# Decrypt data with the receiver's secret key
decrypted = Ecies.decrypt(raw_sk, encrypted)
puts decrypted  # => "Hello, World🌍!"
