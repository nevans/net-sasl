# frozen_string_literal: true

module Net

  module SASL

    # Authenticator for the "+ANONYMOUS+" SASL mechanism, specified in
    # RFC4616[https://tools.ietf.org/html/rfc4505].
    class AnonymousAuthenticator < Authenticator

      # This should generally be instantiated via Net::SASL.authenticator.
      def initialize(*)
        super
      end

      def supports_initial_response?
        true
      end

      # There are no responses for ANONYMOUS
      def process(_data)
        return if @username == ""

        @authzid || @username
      end

    end

  end

end
