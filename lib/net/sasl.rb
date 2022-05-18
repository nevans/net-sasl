# frozen_string_literal: true

require_relative "sasl/version"
require_relative "sasl/registry"
require_relative "sasl/authenticator"
require_relative "sasl/cram_md5_authenticator"
require_relative "sasl/digest_md5_authenticator"
require_relative "sasl/login_authenticator"
require_relative "sasl/plain_authenticator"
require_relative "sasl/scram_authenticator"

module Net

  # Pluggable authentication mechanisms for protocols which support SASL (Simple
  # Authentication and Security Layer), such as IMAP4, SMTP, LDAP, and XMPP.
  # SASL is described by RFC4422[https://tools.ietf.org/html/rfc4422]: "SASL is
  # conceptually a framework that provides an abstraction layer between
  # protocols and mechanisms as illustrated in the following diagram."
  #
  #               SMTP    LDAP    XMPP   Other protocols ...
  #                  \       |    |      /
  #                   \      |    |     /
  #                  SASL abstraction layer
  #                   /      |    |     \
  #                  /       |    |      \
  #           EXTERNAL   GSSAPI  PLAIN   Other mechanisms ...
  #
  # This library was originally implemented for Net::IMAP, and has been
  # extracted from there.
  module SASL

    # Superclass of SASL errors.
    class Error < StandardError
    end

    # Error raised when data is in the incorrect format.
    class DataFormatError < Error
    end

    # Error raised when a challnge from the server is non-parseable or the
    # mechanism implementation is unable to respond
    class ChallengeParseError < Error
    end

    # Adds an authenticator to the global registry, for use with
    # Net::SASL.authenticator.  See Net::SASL::Registry#add_authenticator.
    def self.add_authenticator(mechanism, authenticator)
      DEFAULT_REGISTRY.add_authenticator(mechanism, authenticator)
    end

    # Builds an authenticator in its initial state, based on +mechanism+ name.
    # Any additional arguments will be passed directly to the chosen
    # authenticator's +#new+ method.  See Net::SASL::Registry#authenticator.
    def self.authenticator(mechanism, *args, **kwargs)
      DEFAULT_REGISTRY.authenticator(mechanism, *args, **kwargs)
    end

    # The default global registry used by Net::SASL.authenticator
    DEFAULT_REGISTRY = Registry.new

    add_authenticator "PLAIN",         PlainAuthenticator
    add_authenticator "LOGIN",         LoginAuthenticator
    add_authenticator "DIGEST-MD5",    DigestMD5Authenticator
    add_authenticator "CRAM-MD5",      CramMD5Authenticator
    add_authenticator "SCRAM-SHA-1",   ScramAuthenticator.for("SHA1")
    add_authenticator "SCRAM-SHA-224", ScramAuthenticator.for("SHA224")
    add_authenticator "SCRAM-SHA-256", ScramAuthenticator.for("SHA256")
    add_authenticator "SCRAM-SHA-384", ScramAuthenticator.for("SHA384")
    add_authenticator "SCRAM-SHA-512", ScramAuthenticator.for("SHA512")

  end

end
