# frozen_string_literal: true

module Net

  module SASL

    # A base class to use for all SASL client authenticators.
    class Authenticator

      # :call-seq:
      #   mechanism.new(authcid=nil, credentials=nil, authzid=nil, **properties)
      #   mechanism.new(**properties) {|property, authenticator| ... }
      #
      # Creates a new authenticator for a single SASL authentication exchange.
      #
      # Authenticators can only be used for a single authentication exchange.
      # Create a new authenticator for every connection and every authentication
      # attempt.
      #
      # _n.b. This documents the base API for most mechanisms.  Each specific
      # mechanism determines how the arguments are interpreted—see each
      # mechanisms' documentation for details._
      #
      # Subclasses may raise an exception for unsupported positional arguments,
      # and incompatible or invalid keyword arguments.  Inapplicable or unknown
      # keyword arguments should be ignored.
      #
      # === Standard arguments
      #
      # As a convenience, the property types most common to various mechanisms
      # may be given as positional arguments.  See {@Properties}, below, for
      # more details.
      #
      # * +authcid+: the authentication identity, e.g. a username.
      # * +credentials+: the authentication credentials, e.g. a +password+, a
      #   secret bearer token, a 2FA PIN.  Credentials are mechanism specific.
      # * +authzid+: the authorization identity.
      #
      # Clients should not send the same value by multiple positional or keyword
      # arguments.  Doing so might raise an ArgumentError but that must not be
      # relied upon; it may use the last given argument or some other
      # unspecified behavior.
      #
      # === Keyword arguments
      #
      # Each property described below may be given as a keyword argument.
      # Additionally, +username+ may be used as an alias for +authcid+.  Don't
      # send both +username+ and +authcid+.
      #
      # There is no keyword argument for +credentials+.  Use the property name
      # corresponding to the specific type of credentials that have been
      # provided, e.g. +password+ or +oauthbearer_token+.
      #
      # === Callback block
      #
      # Instead of providing arguments up-front, properties may be requested
      # when they are needed by providing a callback block.  This allows, for
      # example, asking the user for a password interactively, only after
      # securely connecting to the server and choosing a password-based
      # mechanism.  It might also be used to fetch credentials from a KMS.
      #
      # The callback will be passed a symbol +property+ name and the
      # authenticator object.  All keyword options may be provided by the block
      # instead.  If given, the callback will be called for every property, even
      # if a keyword was also provided.  The callback must return +nil+ for
      # properties it doesn't understand or cannot handle, so they can be
      # delegated to the argument, if provided.  This allows e.g. a logging
      # callback to work alongside keyword properties.
      #
      # === Properties
      #
      # All properties may be given as a keyword argument or handled by the
      # callback block.
      #
      # ==== Identities:
      #
      # * +authcid+: the authentication identity, the identity associated with
      #   the credentials, e.g. a +username+.  The form is mechanism specific.
      #   Some mechanisms will derive this from the authentication credentials.
      # * +username+: an alias for +authcid+.
      # * +realm+: some mechanisms use "realms" or "domains" to segment
      #     authentication identities.  How this is used is protocol specific.
      #
      # * +authzid+: the authorization identity, an identity to act as or on
      #   behalf of. The identity form is application protocol specific.  If is
      #   not given (or is left blank), the server will derive an authorization
      #   identity from the authentication credentials.
      #
      #   The server is responsible for verifying the client's credentials and
      #   verifying that the identity it associates with the client's
      #   authentication identity is allowed to act as (or on behalf of) the
      #   authorization identity.
      #
      # There is no single +credentials+ property.  Different mechanisms require
      # different types of credentials, and each credential type has its own
      # property name.
      #
      # ==== Credentials
      #
      # * +password+: password for the authentication identity.  Used by several
      #     different password-based mechanisms.
      #
      # * +pin+: a Personal Identification number, e.g. as used by SecurID 2FA.
      #
      # * +oauth2_token: An OAuth2.0 access token, used by the OAUTHBEARER and
      #     XOAUTH2 mechanisms.
      #
      # ==== Other common properties:
      #
      # * +service+: the service protocol, a {registered GSSAPI service name}[
      #     https://www.iana.org/assignments/gssapi-service-names/gssapi-service-names.xhtml
      #     ], e.g. "imap", "ldap", or "xmpp".
      #     Defaults to "host".
      # * +host+: the DNS hostname for the requested service
      # * +port+: the server port being connected to
      #
      # ==== Mechanism specific properties:
      #
      # Properties that aren't listed here should be prefixed with the mechanism
      # name and described in that mechanism's documentation.
      #
      # * +anonymous_message+: optional message to the server, used by ANONYMOUS
      #
      def initialize(authcid = nil,
                     credentials = nil,
                     authzid = nil,
                     **options,
                     &callback)
        @authcid     = -authcid.to_str if authcid
        @credentials = credentials
        @authzid     = -authzid.to_str if authzid
        @options     = options
        @callback    = callback
      end

      # Does this mechanism support sending an initial client response?
      #
      # Returns +false+ when the mechanism is server-first, or when it is
      # variable and the client has been configured to allow omit the initial
      # response.  In this case, clients must not call #process before the
      # server's initial challenge.
      #
      # Returns +true+ when the mechanism is client-first, or when it is
      # variable and the client has been configured to send an initial response.
      #
      # If the protocol does not support an initial response, clients should
      # behave the same as if this method returns +false+.
      #
      # Clients should call #process with +nil+ only when an initial response is
      # supported by both the mechanism and the protocol.
      #
      # [RFC4422] requires servers send an empty string for their first
      # challenge, but client-first authenticators should ignore the initial
      # response from misbehaving servers.
      def supports_initial_response?
        false
      end

      # :call-seq:
      #   authenticator.process(nil) -> initial_client_response
      #   authenticator.process(server_challenge) -> client_response
      #
      # Process a +challenge+ string from the server and return the response.
      #
      # This method should be sent an unencoded challenge and return an
      # unencoded response. The client is responsible for receiving and decoding
      # the challenge, according the the specification of the specific protocol,
      # e.g. IMAP4 base64 encodes challenges and responses.
      #
      # This method will always be called at least once, excepting only when the
      # server refuses to allow a challenge-first SASL exchange.
      #
      # When a  method should be
      # called with +nil+.
      # will be +nil+ (when the protocol also supports initial response) or an
      # empty string (when it does not).  If a the first challenge to a
      # client-first mechanism is non-empty, that might indicate a misbehaving
      # server.
      #
      # Calling #process when #done? returns +true+ has undefined behavior: e.g.
      # it may raise an excepion or return the previous response again.
      #
      # _n.b. This base implementation will raise a NotImplementedError.
      # Mechanism subclasses must override this method appropriately._
      #
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
