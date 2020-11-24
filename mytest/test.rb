#!/usr/bin/env ruby
#!/usr/bin/env ruby
require 'openssl'
require 'base64'

# cipher = OpenSSL::Cipher.new 'AES-256-CBC'
# cipher.encrypt
# iv = cipher.random_iv

# pwd = 'some hopefully not to easily guessable password'
# salt = OpenSSL::Random.random_bytes 16
# iter = 20000
# key_len = cipher.key_len
# digest = OpenSSL::Digest::SHA256.new

# key = OpenSSL::PKCS5.pbkdf2_hmac(pwd, salt, iter, key_len, digest)
# cipher.key = key
# puts "#{key.unpack('H*')[0].upcase}"
# puts "#{iv.unpack('H*')[0].upcase}"



# encrypted = cipher.update 'A top secret'
# encrypted << cipher.final
# puts "#{encrypted}"

# open 'encrypted.data', 'w' do |io|
#   io.write encrypted
# end

# cipher = OpenSSL::Cipher.new 'AES-256-CBC'
# cipher.decrypt
# cipher.iv = iv # the one generated with #random_iv

# pwd = 'some hopefully not to easily guessable password'
# # salt = ... # the one generated above
# iter = 20000
# key_len = cipher.key_len
# digest = OpenSSL::Digest::SHA256.new

# key = OpenSSL::PKCS5.pbkdf2_hmac(pwd, salt, iter, key_len, digest)
# cipher.key = key


# decrypted = cipher.update encrypted
# decrypted << cipher.final

# puts "#{decrypted}"

enc_key = Base64.decode64('6DE95F046ABA7BC0BDFD16C9659372A7C11D18386046EB8674C038502C8C49B0')
enc_iv =  Base64.decode64('BD6525736534075422B04474A3487061')

cipher = OpenSSL::Cipher.new 'AES-256-CBC'
cipher.encrypt
iv = enc_iv


iter = 20000
key_len = cipher.key_len
digest = OpenSSL::Digest::SHA256.new

key = enc_key[0..31]
cipher.key = key
cipher.iv = iv[0..15]
# puts "#{key.unpack('H*')[0].upcase}"
# puts "#{iv.unpack('H*')[0].upcase}"



encrypted = cipher.update 'A top secret'
encrypted << cipher.final
puts "#{encrypted}"


# cipher = OpenSSL::Cipher.new 'AES-256-CBC'
# cipher.decrypt
# # cipher.iv = enc_iv[0..16] # the one generated with #random_iv
# # cipher.iv = cipher.random_iv

# pwd = 'some hopefully not to easily guessable password'
# # # salt = ... # the one generated above
# # salt = OpenSSL::Random.random_bytes 16
# iter = 20000
# key_len = cipher.key_len
# digest = OpenSSL::Digest::SHA256.new

# key = OpenSSL::PKCS5.pbkdf2_hmac(pwd, salt, iter, key_len, digest)
# cipher.key = enc_key[0..31]


# decrypted = cipher.update encrypted
# decrypted << cipher.final

# puts "#{decrypted}"