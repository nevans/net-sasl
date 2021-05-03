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

end
