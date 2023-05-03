require 'fluent/filter'
require 'openssl'
require 'base64'

module Fluent
  class EncryptFilter < Filter
    Fluent::Plugin.register_filter('encrypt', self)


    SUPPORTED_ALGORITHMS = {
      aes_256_cbc: { name: "AES-256-CBC", use_iv: true, key_len: 32, iv_len: 16},
      aes_192_cbc: { name: "AES-192-CBC", use_iv: true, key_len: 32, iv_len: 16},
      aes_128_cbc: { name: "AES-128-CBC", use_iv: true, key_len: 32, iv_len: 16},
      aes_256_ecb: { name: "AES-256-ECB", use_iv: false, key_len: 32, iv_len: 16},
      aes_192_ecb: { name: "AES-192-ECB", use_iv: false, key_len: 32, iv_len: 16},
      aes_128_ecb: { name: "AES-128-ECB", use_iv: false, key_len: 32, iv_len: 16},
      aes_256_gcm: { name: "AES-256-GCM", use_iv: false, key_len: 32, iv_len: 12},
    }

    config_param :algorithm, :enum, list: SUPPORTED_ALGORITHMS.keys, default: :aes_256_cbc
    config_param :encrypt_key_hex, :string
    config_param :encrypt_iv_hex, :string, default: nil

    config_param :key,  :string, default: nil
    config_param :keys, :array, default: []


    attr_reader :target_keys

    def configure(conf)
      super

      @target_keys = @keys + [@key]
      if @target_keys.empty?
        raise Fluent::ConfigError, "no keys specified to be encrypted"
      end

      algorithm = SUPPORTED_ALGORITHMS[@algorithm]
      if algorithm[:use_iv] && !@encrypt_iv_hex
        raise Fluent::ConfigError, "Encryption algorithm #{@algorithm} requires 'encrypt_iv_hex'"
      end


      req_key_len = SUPPORTED_ALGORITHMS[@algorithm][:key_len]
      req_iv_len =  SUPPORTED_ALGORITHMS[@algorithm][:iv_len]

      @enc_key = [@encrypt_key_hex].pack('H*')
      @enc_key = @enc_key.ljust(32, "\0")#
      

      @enc_iv = if @encrypt_iv_hex
                  [@encrypt_iv_hex].pack('H*')[0, req_iv_len]
                else
                  nil
                end

      @algo = algorithm[:name]

      @enc_generator = ->(){
        enc = OpenSSL::Cipher.new(@algo)
        enc.key = @enc_key
        enc.iv  = @enc_iv if @enc_iv
        enc.encrypt
        enc
      }
    end

    def filter_stream(tag, es)
      new_es = MultiEventStream.new
      es.each do |time, record|
        r = record.dup
        record.each_pair do |key, value|
          if @target_keys.include?("*") ||  @target_keys.include?(key)
            r[key] = encrypt(value)
          end
        end
        new_es.add(time, r)
      end
      new_es
    end

    def encrypt(value)
      encrypted = ""
      enc = @enc_generator.call()
      encrypted << enc.update(value)
      encrypted << enc.final
      Base64.encode64(encrypted)
    end


    def decrypt(value)
      decrypted_data = ""
      cipher = OpenSSL::Cipher.new(@algo)
      cipher.decrypt

      cipher.key = @enc_key
      cipher.iv = @enc_iv

      decrypted_data << cipher.update(Base64.decode64(value))
    end
  end
end
