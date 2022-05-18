# frozen_string_literal: true

require "test_helper"

class Net::SASLTest < Test::Unit::TestCase

  test "VERSION" do
    assert do
      ::Net::SASL.const_defined?(:VERSION)
    end
  end

  def plain(*args, **kwargs)
    Net::SASL.authenticator("PLAIN", *args, **kwargs)
  end

  test "PLAIN authenticator" do
    assert_equal("\0authc\0passwd",
                 plain("authc", "passwd").process(nil))
    assert_equal("authz\0user\0pass",
                 plain("user", "pass", "authz").process(nil))
  end

  test "PLAIN: no NULL chars" do
    assert_raise(ArgumentError) { plain("bad\0user", "pass") }
    assert_raise(ArgumentError) { plain("user", "bad\0pass") }
    assert_raise(ArgumentError) { plain("u", "p", "bad\0authz") }
  end

  test "SCRAM-SHA-1 authenticator" do
    authenticator = Net::SASL.authenticator("SCRAM-SHA-1", "user", "pencil", "zid", cnonce: "fyko+d2lbbFgONRv9qkxdawL")
    assert_equal "n,a=zid,n=user,r=fyko+d2lbbFgONRv9qkxdawL", authenticator.process(nil)
    refute authenticator.done?
    assert_equal(
      "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
      authenticator.process("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
    )
    refute authenticator.done?
    assert authenticator.process("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=").nil?
    assert authenticator.done?
  end

end
