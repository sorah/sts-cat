#!/usr/bin/env ruby
require 'bundler/inline'
gemfile do
  source 'https://rubygems.org'
  gem 'openssl'
  gem 'aws-sdk-kms'
end

require 'openssl'
require 'aws-sdk-kms'

arn = ARGV[0] or abort "Usage: #{$0} <kms-key-arn> <pem-path>"
pem_path = ARGV[1] or abort "Usage: #{$0} <kms-key-arn> <pem-path>"

rsa_key = OpenSSL::PKey::RSA.new(File.read(pem_path))
pkcs8_der = rsa_key.private_to_der

kms = Aws::KMS::Client.new

params = kms.get_parameters_for_import(
  key_id: arn,
  wrapping_key_spec: 'RSA_4096',
  wrapping_algorithm: 'RSA_AES_KEY_WRAP_SHA_256',
)

wrapping_pubkey = OpenSSL::PKey::RSA.new(params.public_key)
import_token = params.import_token

# RSA_AES_KEY_WRAP_SHA_256:
# 1. Generate random AES-256 key
# 2. AES-KWP (RFC 5649) wrap the PKCS#8 DER key material
# 3. RSA-OAEP-SHA256 encrypt the AES key
# 4. Concatenate encrypted AES key + wrapped key material
aes_key = OpenSSL::Random.random_bytes(32)
cipher = OpenSSL::Cipher.new('id-aes256-wrap-pad')
cipher.encrypt
cipher.key = aes_key
wrapped_key_material = cipher.update(pkcs8_der) + cipher.final
encrypted_aes_key = wrapping_pubkey.encrypt(aes_key, rsa_padding_mode: 'oaep', rsa_oaep_md: 'sha256')
encrypted_key_material = encrypted_aes_key + wrapped_key_material

kms.import_key_material(
  key_id: arn,
  encrypted_key_material: encrypted_key_material,
  import_token: import_token,
  expiration_model: 'KEY_MATERIAL_DOES_NOT_EXPIRE',
)

puts "Imported key material into #{arn}"
