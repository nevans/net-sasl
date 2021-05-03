# frozen_string_literal: true

module Net

  module SASL

    # Registry for SASL mechanisms.  Common usage can use the default global
    # registry, via Net::SASL#authenticator.
    class Registry

      # Creates a new registry, which matches enabled SASL mechanisms with their
      # implementations.
      def initialize
        @authenticators = {}
      end

      # Adds an authenticator class for use with #authenticator.  +mechanism+ is
      # the {SASL mechanism name}[https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml]
      # supported by +authenticator+ (for instance, "+PLAIN+").  The
      # +authenticator+ is an class which defines a +#process+ method to handle
      # authentication with the server.  See e.g. Net::SASL::PlainAuthenticator.
      #
      # If +mechanism+ refers to an existing authenticator, it will be replaced
      # by the new one.
      def add_authenticator(mechanism, authenticator)
        @authenticators[mechanism.upcase] = authenticator
      end

      # Deletes an authenticator from the registry.  This can be useful to
      # implement a policy that prohibits the use of default mechanisms.
      def remove_authenticator(mechanism)
        @authenticators.delete(mechanism.upcase)
      end

      # Builds an authenticator in its initial state.  +mechanism+ is the SASL
      # mechanism name.  All other arguments represent the credentials and other
      # parameters or configuration, which will be passed directly to the chosen
      # authenticator's +#new+ method.  See Authenticator.new.
      def authenticator(mechanism, authcid=nil, credentials=nil, authzid=nil, **kwargs)
        mechanism = mechanism.upcase
        unless @authenticators.key?(mechanism)
          raise ArgumentError, 'unknown SASL mechanism - "%s"' % mechanism
        end
        @authenticators.fetch(mechanism)
          .new(authcid, credentials, authzid, **kwargs)
      end

    end

  end

end
