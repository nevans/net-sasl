# frozen_string_literal: true

module Net

  module SASL

    # Authenticator for the "+PLAIN+" SASL mechanism, specified in
    # RFC4616[https://tools.ietf.org/html/rfc4616].  The authentication
    # credentials are transmitted in cleartext, so this mechanism should only be
    # used over an encrypted link.
    class PlainAuthenticator < Authenticator

      NULL = -"\0".b
      private_constant :NULL

      attr_reader :username, :password, :authzid, :done

      alias done? done
      private :done

      # +username+ is the authentication identity, the identity whose +password+ is
      # used.  +username+ is referred to as +authcid+ by
      # RFC4616[https://tools.ietf.org/html/rfc4616].
      #
      # +authzid+ is the authorization identity (identity to act as).  It can
      # usually be left blank. When +authzid+ is left blank (nil or empty string)
      # the server will derive an identity from the credentials and use that as the
      # authorization identity.
      #
      # Net::SASL.authenticator should be used instead of calling this directly.
      def initialize(username, password, authzid = nil, **_options)
        raise ArgumentError, "username contains NULL" if username&.include?(NULL)
        raise ArgumentError, "password contains NULL" if password&.include?(NULL)
        raise ArgumentError, "authzid  contains NULL" if authzid&.include?(NULL)
        super
        @done = false
      end

      # +PLAIN+ does support SASL-IR
      def supports_initial_response?
        true
      end

      # returns the SASL response for +PLAIN+
      def process(data)
        @done = true
        "#{@authzid}\0#{@username}\0#{@password}"
      end

    end

  end

end
