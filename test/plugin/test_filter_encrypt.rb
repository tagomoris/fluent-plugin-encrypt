require 'helper'

class AnonymizerFilterTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup

    @password = "my secret password for test"
    @salt = OpenSSL::Random.random_bytes(8)

    enc = OpenSSL::Cipher.new("AES-256-CBC")
    enc.encrypt
    key_iv_aes256cbc = OpenSSL::PKCS5.pbkdf2_hmac_sha1(@password, @salt, 2000, enc.key_len + enc.iv_len)
    @aes256cbc_key_hex = Base64.encode64(key_iv_aes256cbc[0, enc.key_len])
    @aes256cbc_iv_hex  = Base64.encode64(key_iv_aes256cbc[enc.key_len, enc.iv_len])
  end

  def decrypt(encrypted, name="AES-256-CBC", key=Base64.decode64(@aes256cbc_key_hex), iv=Base64.decode64(@aes256cbc_iv_hex))
    dec = OpenSSL::Cipher.new(name)
    dec.decrypt
    dec.key = key
    dec.iv = iv if iv
    value = ""
    value << dec.update(Base64.decode64(encrypted))
    value << dec.final
    value
  end

  BASE_CONF = %[
    key secret_data
  ].freeze

  def generate_config(base_conf=BASE_CONF, key=@aes256cbc_key_hex, iv=@aes256cbc_iv_hex)
    conf = base_conf + "encrypt_key_hex #{key}\n"
    if iv
      conf += "encrypt_iv_hex #{iv}\n"
    end
    conf
  end

  def create_driver(conf = nil)
    conf ||= generate_config()
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::EncryptFilter).configure(conf)
  end

  test 'configure it successfully' do
    d = create_driver
    assert{ d.instance.is_a? Fluent::Plugin::EncryptFilter }
  end

  test 'configure raises error for missing key/iv' do
    assert_raises(Fluent::ConfigError){
      create_driver(%[
        algorithm aes_256_cbc
        key mykey1
      ])
    }
    assert_raises(Fluent::ConfigError){
      create_driver(%[
        algorithm aes_256_cbc
        encrypt_key_hex #{@aes256cbc_key_hex}
        key mykey2
      ])
    }

    d = create_driver
    assert_equal "secret_data", d.instance.key

    d = create_driver(%[
      algorithm aes_256_cbc
      encrypt_key_hex #{@aes256cbc_key_hex}
      encrypt_iv_hex  #{@aes256cbc_iv_hex}
      key mykey3
    ])
    assert_equal ["mykey3"], d.instance.target_keys
  end

  test 'configure with AES-256-ECB' do
    enc = OpenSSL::Cipher.new("AES-256-ECB")
    enc.encrypt
    key_iv_aes256ecb = OpenSSL::PKCS5.pbkdf2_hmac_sha1(@password, @salt, 2000, enc.key_len)
    key = Base64.encode64(key_iv_aes256ecb[0, enc.key_len])
    base_conf = %[
      key secret_field
      algorithm aes_256_ecb
    ]
    config = generate_config(base_conf, key, nil)
    d = create_driver(config)
    assert{ d.instance.is_a? Fluent::Plugin::EncryptFilter }
  end

  test 'filter records with encryption' do
    d = create_driver
    time = event_time
    d.run(default_tag: "test") do
      d.feed(time, {"data" => "value", "data2" => "value", "secret_data" => "value 2"})
      d.feed(time, {"data" => "value", "data2" => "value", "secret_data" => "value 2"})
      d.feed(time, {"data" => "value", "data2" => "value", "secret_data" => "value 2"})
      d.feed(time, {"data" => "value", "data2" => "value", "secret_data" => "value 2"})
    end
    filtered = d.filtered
    assert_equal 4, filtered.size
    t, r = filtered[0]
    assert_equal time, t
    assert_equal 3, r.size
    assert_equal "value", r["data"]
    assert_equal "value", r["data2"]
    assert{ "value 2" != r["secret_data"] }
    assert_equal "value 2", decrypt(r["secret_data"])
  end
end
