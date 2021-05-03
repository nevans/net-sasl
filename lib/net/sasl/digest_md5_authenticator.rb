# frozen_string_literal: true

require "digest/md5"
require "strscan"

module Net

  module SASL

    # Authenticator for the "`DIGEST-MD5`" SASL mechanism type, specified
    # in RFC2831(https://tools.ietf.org/html/rfc2831).
    #
    # == Deprecated
    #
    # "+DIGEST-MD5+" has been deprecated by
    # {RFC6331}[https://tools.ietf.org/html/rfc6331] and should not be relied on
    # for security.  It is included for compatibility with existing servers.
    class DigestMD5Authenticator < Authenticator

      STAGE_ONE = :stage_one
      STAGE_TWO = :stage_two
      private_constant :STAGE_ONE, :STAGE_TWO

      attr_reader :username, :password, :authzid

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
      def initialize(username, password, authzid = nil, **_options)
        super
        @username, @password, @authzid = username, password, authzid
        @nc, @stage = {}, STAGE_ONE
      end

      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength, Metrics/BlockNesting

      # responds to the server's DIGEST-MD5 challenges
      def process(challenge)
        case @stage
        when STAGE_ONE
          @stage = STAGE_TWO
          sparams = {}
          c = StringScanner.new(challenge)
          while c.scan(/(?:\s*,)?\s*(\w+)=("(?:[^\\"]+|\\.)*"|[^,]+)\s*/)
            k, v = c[1], c[2]
            if v =~ /^"(.*)"$/
              v = $1
              if v =~ /,/
                v = v.split(",")
              end
            end
            sparams[k] = v
          end

          raise DataFormatError, "Bad Challenge: '#{challenge}'" unless c.rest.empty?
          unless sparams["qop"].include?("auth")
            raise Error,
                  "Server does not support auth (qop = #{sparams["qop"].join(",")})"
          end

          response = {
            nonce: sparams["nonce"],
            username: @username,
            realm: sparams["realm"],
            cnonce: Digest::MD5.hexdigest("%.15f:%.15f:%d" % [Time.now.to_f, rand,
                                                              Process.pid.to_s,]),
            'digest-uri': "imap/#{sparams["realm"]}",
            qop: "auth",
            maxbuf: 65_535,
            nc: "%08d" % nc(sparams["nonce"]),
            charset: sparams["charset"],
          }

          response[:authzid] = @authzid unless @authzid.nil?

          # now, the real thing
          a0 = Digest::MD5.digest([ response.values_at(:username, :realm),
                                    @password, ].join(":"))

          a1 = [ a0, response.values_at(:nonce, :cnonce) ].join(":")
          a1 << ":#{response[:authzid]}" unless response[:authzid].nil?

          a2 = "AUTHENTICATE:#{response[:'digest-uri']}"
          if response[:qop] && response[:qop] =~ (/^auth-(?:conf|int)$/)
            a2 << ":00000000000000000000000000000000"
          end

          response[:response] = Digest::MD5.hexdigest(
            [
              Digest::MD5.hexdigest(a1),
              response.values_at(:nonce, :nc, :cnonce, :qop),
              Digest::MD5.hexdigest(a2),
            ].join(":")
          )

          response.keys.map {|key| qdval(key.to_s, response[key]) }.join(",")
        when STAGE_TWO
          @stage = nil
          # if at the second stage, return an empty string
          if challenge =~ /rspauth=/
            ""
          else
            raise ChallengeParseError, challenge
          end
        else
          raise ChallengeParseError, challenge
        end
      end

      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength, Metrics/BlockNesting

      # returns true after two challenge/response stages
      def done?
        @stage.nil?
      end

      private

      def nc(nonce)
        @nc[nonce] = if @nc.key? nonce
                       @nc[nonce] + 1
                     else
                       1
                     end
        @nc[nonce]
      end

      # some responses need quoting
      def qdval(k, v) # rubocop:disable Naming/MethodParameterName
        return if k.nil? || v.nil?
        if %w[username authzid realm nonce cnonce digest-uri qop].include? k
          v.gsub!(/([\\"])/, "\\\1")
          '%s="%s"' % [k, v]
        else
          "%s=%s" % [k, v]
        end
      end

    end
  end
end
