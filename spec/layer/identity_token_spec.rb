require 'spec_helper'

describe Layer::IdentityToken do
  describe ".new" do
    let(:user_id) { '1234' }
    let(:nonce) { 'your_random_nonce' }
    let(:expires_at) { '12345678' }
    let(:optional_attributes) { {} }

    subject(:token) do
      Layer::IdentityToken.new(
        user_id: user_id,
        nonce: nonce,
        expires_at: expires_at,
        **optional_attributes
      )
    end

    it "should allow you to set the user_id, nonce and expires_at variables" do
      expect(token.user_id).to eq(user_id)
      expect(token.nonce).to eq(nonce)
      expect(token.expires_at).to eq(expires_at)
    end

    context 'optional attributes' do
      let(:optional_attributes) do
        {
          first_name: 'John',
          last_name: 'Doe',
          display_name: 'John D.',
          avatar_url: 'http://test.org/test.jpeg'
        }
      end

      it "should allow you to pass optional attributes" do
        expect(token.optional_attributes).to eq(optional_attributes)
      end

      context 'with unknown attributes' do
        before { optional_attributes[:unknown] = 'test' }

        it "should not include the unknown attributes" do
          expect(token.optional_attributes).not_to include(:unknown)
        end
      end

      context 'with nil attributes' do
        before { optional_attributes[:first_name] = nil }

        it "should not include the nil attributes" do
          expect(token.optional_attributes).not_to include(:first_name)
        end
      end
    end
  end

  describe ".layer_key_id" do
    it "should return your ENV['LAYER_KEY_ID']" do
      layer_key_id = Layer::IdentityToken.new.layer_key_id
      expect(layer_key_id).to eq(ENV['LAYER_KEY_ID'])
    end
  end

  describe ".layer_provider_id" do
    it "should return your ENV['LAYER_PROVIDER_ID']" do
      provider_id = Layer::IdentityToken.new.layer_provider_id
      expect(provider_id).to eq(ENV['LAYER_PROVIDER_ID'])
    end
  end

  describe ".headers" do
    it "should return necessary headers" do
      token = Layer::IdentityToken.new

      headers = token.send(:headers)

      expect(headers[:kid]).to eq(ENV['LAYER_KEY_ID'])
      expect(headers[:cty]).to eq('layer-eit;v=1')
      expect(headers[:typ]).to eq('JWT')
    end
  end

  describe ".claim" do
    let(:optional_attributes) { {} }
    let(:token) do
      Layer::IdentityToken.new(
        user_id: "user_id",
        nonce: "nonce",
        expires_at: 1234567,
        **optional_attributes
      )
    end

    subject(:claim) do
      token.send(:claim)
    end

    it "should return necessary payload" do
      expect(claim[:iss]).to eq(token.layer_provider_id)
      expect(claim[:prn]).to eq(token.user_id)
      expect(claim[:exp]).to eq(token.expires_at)
      expect(claim[:nce]).to eq(token.nonce)
    end

    context "with optional attributes present" do
      before { optional_attributes[:first_name] = 'Bob' }

      it "should include the optional attribute" do
        expect(claim[:first_name]).to eq(token.optional_attributes[:first_name])
      end
    end
  end

  describe ".private_key" do
    it "should return valid rsa private key" do
      key = Layer::IdentityToken.new.send(:private_key)
      expect(key).to be_instance_of(OpenSSL::PKey::RSA)
    end
  end

  describe ".to_s" do
    it "should return a string representation of the identity token" do
      token = Layer::IdentityToken.new.to_s
      expect(token).to be_instance_of(String)
    end
  end

  describe ".generate_identity_token" do
    it "should instantiate a new IdentityToken object" do
      options = {}
      options[:user_id] = "user_id"
      options[:nonce] = "user_id"
      layer = Layer::Platform::Client.new

      expected_token = Layer::IdentityToken.new(options)
      actual_token = layer.generate_identity_token(options)

      expect(actual_token).to be_instance_of(Layer::IdentityToken)
      expect(expected_token.to_s).to eq(actual_token.to_s)
    end
  end
end
