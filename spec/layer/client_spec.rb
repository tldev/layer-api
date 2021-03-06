require 'spec_helper'

describe Layer::Platform::Client do
  describe "#new" do
    it 'should allow you to set the api_token and app_id' do
      app_id = "app_id"
      api_token = "api_token"

      layer = Layer::Platform::Client.new(app_id: app_id, api_token: api_token)

      expect(layer.app_id).to eq(app_id)
      expect(layer.api_token).to eq(api_token)
    end

    it 'should default to environment variables for api_token and app_id' do
      layer = Layer::Platform::Client.new

      expect(layer.app_id).to eq(ENV['LAYER_APP_ID'])
      expect(layer.api_token).to eq(ENV['LAYER_API_TOKEN'])
    end

    it "should strip layer prefix from app_id if present" do
      app_id = "12345"
      layer = Layer::Platform::Client.new(app_id: "layer:///apps/production/#{app_id}")
      expect(layer.app_id).to eq(app_id)
    end
  end

  describe "#strip_layer_prefix" do
    it "should remove layer prefixes from a string" do
      layer = Layer::Platform::Client.new
      app_id = "app_id"

      layer_prefixed_string = "layer:///apps/staging/#{app_id}"
      stripped_id = layer.strip_layer_prefix(layer_prefixed_string)

      expect(stripped_id).to eq(app_id)
    end

    it "should return original string if there's no layer prefix" do
      layer = Layer::Platform::Client.new
      app_id = "app_id"
      stripped_id = layer.strip_layer_prefix(app_id)
      expect(stripped_id).to eq(app_id)
    end
  end

  describe "#client" do
    it "should return HttpClient instance" do
      layer = Layer::Platform::Client.new

      expect(layer.client).to be_instance_of(Layer::HttpClient)
    end

    it "should assign the same base_url and default_headers as the current instance" do
      layer = Layer::Platform::Client.new
      client = layer.client

      expect(layer.base_url).to eq(client.base_url)
      expect(layer.default_headers).to eq(client.default_headers)
    end
  end

  describe "#default_headers" do
    it "should pass api_token into Authorization header" do
      api_token = "1234"
      layer = Layer::Platform::Client.new(api_token: api_token)

      expect(layer.client.default_headers['Authorization']).to include(api_token)
    end
  end

  describe "#base_url" do
    it "should contain app_id" do
      app_id = "1234"
      layer = Layer::Platform::Client.new(app_id: app_id)
      expect(layer.client.base_url).to include(app_id)
    end
  end
end
