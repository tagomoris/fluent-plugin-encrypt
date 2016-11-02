require 'bundler/setup'
require 'test/unit'

$LOAD_PATH.unshift(File.join(__dir__, '..', 'lib'))
$LOAD_PATH.unshift(__dir__)
require 'fluent/test'

# $log = Fluent::Log.new(Fluent::Test::DummyLogDevice.new, Fluent::Log::LEVEL_INFO)

require 'fluent/plugin/filter_encrypt'
