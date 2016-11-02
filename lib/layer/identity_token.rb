module Layer
  class IdentityToken
    attr_reader :user_id,
                :nonce,
                :expires_at,
                :optional_attributes

    def initialize(options = {})
      @user_id = options[:user_id]
      @nonce = options[:nonce]
      @expires_at = (options[:expires_at] || Time.now+(1209600))
      @optional_attributes = {
        first_name: options[:first_name],
        last_name: options[:last_name],
        display_name: options[:display_name],
        avatar_url: options[:avatar_url]
      }.delete_if { |_, v| v.nil? }
    end

    def to_s
      get_jwt
    end

    def layer_key_id
      ENV['LAYER_KEY_ID']
    end

    def layer_provider_id
      ENV['LAYER_PROVIDER_ID']
    end

    private

    def get_jwt
      JWT.encode(claim, private_key, 'RS256', headers)
    end

    def headers
      {
        typ: 'JWT',
        cty: 'layer-eit;v=1',
        kid: layer_key_id
      }
    end

    def claim
      {
        iss: layer_provider_id,
        prn: user_id.to_s,
        iat: Time.now.to_i,
        exp: expires_at.to_i,
        nce: nonce
      }.merge!(optional_attributes)
    end

    def private_key
      # Cloud66 stores newlines as \n instead of \\n
      key = ENV['LAYER_PRIVATE_KEY'].dup
      OpenSSL::PKey::RSA.new(key.gsub("\\n","\n"))
    end
  end
end
