# coding: utf-8

Gem::Specification.new do |spec|
  spec.name          = "fluent-plugin-encrypt-1.0"
  spec.version       = "0.1.7"
  spec.authors       = ["TAGOMORI Satoshi"]
  spec.email         = ["tagomoris@gmail.com"]

  spec.summary       = %q{Fluentd filter plugin to encrypt fields}
  spec.description   = %q{This plugin converts data of specified fields, by encrypting using AES and base64 encoding for encrypted values}
  spec.homepage      = "https://github.com/tagomoris/fluent-plugin-encrypt"
  spec.license       = "Apache-2.0"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "fluentd", ">= 0.12"
  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "test-unit", "~> 3.0"
end
