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

  test "DIGEST-MD5 authenticator" do
    auth = Net::SASL.authenticator("DIGEST-MD5", "cid", "password", "zid")
    assert_match(
      #Regexp.new("nonce=\"OA6MG9tEQGm2hh\",username=\"cid\",realm=\"somerealm\"," \
      #"cnonce=\"[^\"]+\"," \
      #"digest-uri=\"imap/somerealm\",qop=\"auth\",maxbuf=65535,nc=00000001," \
      #"charset=utf-8,authzid=\"zid\",response=
		/\Anonce="OA6MG9tEQGm2hh",username="cid",realm="somerealm",
         cnonce="[a-f0-9]+",digest-uri="imap\/somerealm",qop="auth",maxbuf=65535,
         nc=00000001,charset=utf-8,authzid="zid",
         response=[a-f0-9]+\Z/x,
      auth.process(
        "realm=\"somerealm\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\"," \
        "charset=utf-8,algorithm=md5-sess"))
  end

end
