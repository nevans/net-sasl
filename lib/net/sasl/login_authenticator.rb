# frozen_string_literal: true

module Net

  module SASL

    # Authenticator for the "+LOGIN+" SASL mechanism.  The authentication
    # credentials are transmitted in cleartext so this mechanism should only be
    # used over an encrypted link.
    #
    # === Deprecated
    #
    # The {SASL mechanisms registry}[https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml]
    # marks "LOGIN" as obsoleted by "PLAIN".  It is included here for
    # compatibility with existing servers.  See
    # draft-murchison-sasl-login[https://www.iana.org/go/draft-murchison-sasl-login]
    # for both specification and deprecation.
    class LoginAuthenticator < Authenticator

      attr_reader :username, :password

      # Provide the +username+ and +password+ credentials for authentication.
      #
      # LOGIN doesn't support +authzid+, and an ArgumentError will be raised if
      # a third positional parameter is passed.
      #
      # This should generally be instantiated via Net::SASL.authenticator.
      def initialize(username, password, **_options)
        super
        @state = STATE_USER
      end

      # returns the SASL response for +LOGIN+
      def process(data)
        case @state
        when STATE_USER
          @state = STATE_PASSWORD
          @username
        when STATE_PASSWORD
          @state = STATE_DONE
          @password
        end
      end

      # Returns true after sending the username and password.
      def done?
        @state == STATE_DONE
      end

      STATE_USER = :USER
      STATE_PASSWORD = :PASSWORD
      STATE_DONE = :DONE

      private_constant :STATE_USER, :STATE_PASSWORD

    end
  end
end
