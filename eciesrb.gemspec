Gem::Specification.new do |s|
  s.name = "eciesrb"
  s.version = "0.0.1"
  s.summary = "Elliptic Curve Integrated Encryption Scheme for secp256k1 in Ruby"
  s.description = "Elliptic Curve Integrated Encryption Scheme for secp256k1 in Ruby, based on libsecp256k1 and OpenSSL."
  s.authors = ["Weiliang Li"]
  s.email = "to.be.impressive@gmail.com"
  s.files = Dir["lib/**/**.rb"] + ["eciesrb.gemspec", "README.md", "LICENSE", "CHANGELOG.md"]
  s.homepage = "https://github.com/ecies/rb"
  s.license = "MIT"
  s.add_dependency "libsecp256k1", "~> 0.6.1"
  s.add_dependency "openssl", "~> 3.3"
  s.required_ruby_version = ">= 3.2"
end
