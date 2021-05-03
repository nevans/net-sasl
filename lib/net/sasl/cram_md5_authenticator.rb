# frozen_string_literal: true

require "digest/md5"

module Net

  module SASL

    # Authenticator for the "+CRAM-MD5+" SASL mechanism, specified in
    # RFC2195[https://tools.ietf.org/html/rfc2195].
    #
    # == Deprecated
    #
    # +CRAM-MD5+ is obsolete. It is included for compatibility with existing
    # servers.
    # {draft-ietf-sasl-crammd5-to-historic}[https://tools.ietf.org/html/draft-ietf-sasl-crammd5-to-historic-00.html]
    # recommends using +SCRAM-*+ or +PLAIN+ protected by TLS instead.
    class CramMD5Authenticator < Authenticator

      attr_reader :username, :password, :done

      alias done? done
      private :done

      # Provide the +username+ and +password+ credentials for authentication.
      #
      # CRAM-MD5 doesn't support +authzid+, and an ArgumentError will be raised
      # if a third positional parameter is passed.
      #
      # This should generally be instantiated via Net::SASL.authenticator.
      def initialize(username, password, **_options)
        super
        @username = username
        @password = password
        @done = false
      end

      # responds to the server's challenge using the HMAC-MD5 algorithm.
      def process(challenge)
        digest = hmac_md5(challenge, password)
        "#{username} #{digest}"
      end

      private

      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength

      def hmac_md5(text, key)
        if key.length > 64
          key = Digest::MD5.digest(key)
        end

        k_ipad = key + "\0" * (64 - key.length)
        k_opad = key + "\0" * (64 - key.length)
        (0..63).each do |i|
          k_ipad[i] = (k_ipad[i].ord ^ 0x36).chr
          k_opad[i] = (k_opad[i].ord ^ 0x5c).chr
        end

        digest = Digest::MD5.digest(k_ipad + text)

        Digest::MD5.hexdigest(k_opad + digest)
      end

      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

    end
  end
end
