# frozen_string_literal: true

require "idn"
require "openssl"
require "securerandom"

module Net

  module SASL

    # Authenticator for the "`SCRAM`" family of SASL mechanism types specified
    # in RFC5802(https://tools.ietf.org/html/rfc5802).
    class ScramAuthenticator < Authenticator

      def self.for(hash)
        Class.new(ScramAuthenticator) do
          define_method :initialize do |*args, **options|
            super(*args, hash: hash, **options)
          end
        end
      end

      # Provide the +username+ and +password+ credentials.  An optional
      # +authzid+ is defined as: "The "authorization ID" as per
      # RFC2222[https://tools.ietf.org/html/rfc2222],
      # encoded in UTF-8. optional. If present, and the
      # authenticating user has sufficient privilege, and the server supports
      # it, then after authentication the server will use this identity for
      # making all accesses and access checks.  If the client specifies it, and
      # the server does not support it, then the response-value will be
      # incorrect, and authentication will fail."
      #
      # This should generally be instantiated via Net::SASL.authenticator.
      def initialize(username, password, authzid = nil, hash:, **options)
        super
        @hash = OpenSSL::Digest.new(hash)
        @cnonce = options[:cnonce] || SecureRandom.hex(32)
        @done = false
      end

      def supports_initial_response?
        true
      end

      def done?
        @done
      end

      # responds to the server's challenges
      def process(challenge)
        return "n,#{'a=' + @authzid if @authzid},#{initial_message}" if challenge.nil?

        sparams = challenge.split(/,/).each_with_object({}) do |pair, h|
          k, v = pair.split(/=/)
          h[k] = v
        end

        if @server_signature
          @done = sparams["v"].unpack("m").first == @server_signature
          return if @done

          raise ChallengeParseError, "Bad server signature"
        end

        bare = "c=biws,r=#{sparams['r']}"
        salted_password = OpenSSL::KDF.pbkdf2_hmac(
          IDN::Stringprep.with_profile(@password.encode("utf-8"), "SASLprep"),
          salt: sparams["s"].unpack("m").first,
          iterations: sparams["i"].to_i,
          length: @hash.digest_length,
          hash: @hash
        )
        client_key = OpenSSL::HMAC.digest(@hash, salted_password, "Client Key")
        stored_key = @hash.digest(client_key)
        auth_message = "#{initial_message},#{challenge},#{bare}"
        client_signature = OpenSSL::HMAC.digest(@hash, stored_key, auth_message)
        client_proof = client_key.bytes.zip(client_signature.bytes).map { |x,y| (x ^ y).chr }.join
        server_key = OpenSSL::HMAC.digest(@hash, salted_password, "Server Key")
        @server_signature = OpenSSL::HMAC.digest(@hash, server_key, auth_message)
        "#{bare},p=#{[client_proof].pack('m').chomp}"
      end

    protected

      def initial_message
        "n=#{@username},r=#{@cnonce}"
      end

    end
  end
end
