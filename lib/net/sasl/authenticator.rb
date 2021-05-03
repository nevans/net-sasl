# frozen_string_literal: true

module Net

  module SASL

    # A base class to use for SASL authenticators.
    class Authenticator

      # Creates a new authenticator.
      #
      # Each specific mechanism determines how the arguments are interpreted—see
      # each mechanisms' documentation for details.  Whenever it's reasonable,
      # mechanisms should support the standard positional and keyword arguments
      # and ignore any irrelevant or unknown arguments.
      #
      # === Standard arguments
      #
      # * +authcid+: the authentication identity, the identity associated with
      #   the authentication credentials. This is usually a +username+.
      # * +credentials+: the authentication credentials, e.g. a +password+ or a
      #   secret bearer token.  Some mechanisms may not require an explicit
      #   +authcid+ if it is encoded inside the authentication credentials.
      # * +authzid+: the authorization identity, an identity to act as or on
      #   behalf of.  If this is is not given (or is left blank), the server
      #   will derive an authorization identity from the authentication
      #   credentials, usually the same as the authentication identity.
      #
      # The server is responsible for verifying the client's credentials and
      # verifying that the identity it associates with the client's credentials
      # (e.g., the authentication identity) is allowed to act as the
      # authorization identity.  The precise form(s) of identities and
      # credentials may be dictated by the mechanism and by the server.
      #
      # === Standard options
      #
      # * +host+: the server hostname which is being connected to
      # * +port+: the server port being connected to
      # * +realm+: some mechanisms use "realms" or "domains" to segment
      #   authentication identities. This is protocol dependant and it might be
      #   the same as +host+.
      #
      def initialize(authcid = nil, credentials = nil, authzid = nil, **_options)
        @username = authcid
        @password = credentials
        @authzid  = authzid
      end

      # Does this mechanism support sending an initial response via SASL-IR?
      def supports_initial_response?
        false
      end

      # Process a +challenge+ string from the server and return the response.
      # This method should be sent an unencoded challenge and return an
      # unencoded response. The client is responsible for receiving and decoding
      # the challenge, according the the specification of the specific protocol,
      # e.g. IMAP4 base64 encodes challenges and responses.
      #
      # A nil +challenge+ will be sent to get the initial responses, when
      # that is supported by the mechanism (#supports_initial_response? returns
      # true) and by the protocol.
      #
      # Calling #process when #done? returns true has undefined behavior: it may
      # raise an excepion, return the previous response again, or raise an
      # exception.
      def process(challenge)
        raise NotImplementedError, "implemented by SASL mechanism subclasses"
      end

      # Has the authenticator finished?  If so, then clients must not call
      # #process again.  This is so clients can know authentication is supposed
      # to have been completed, without needing to call #process and handle an
      # exception there.
      def done?
        false
      end

    end

  end
end
