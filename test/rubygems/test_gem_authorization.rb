# frozen_string_literal: true
require 'rubygems/test_case'
require 'rubygems'
require 'rubygems/command'
require 'rubygems/authorization'
require 'net/http'

class TestGemAuthorization < Gem::TestCase

  def setup
    super

    ENV['RUBYGEMS_HOST'] = nil
    Gem.configuration.rubygems_api_key = nil

    @cmd = Gem::Command.new '', 'summary'
    @authorization = Authorization.new
    @authorization.command = @cmd
  end

  def teardown
    ENV['RUBYGEMS_HOST'] = nil
    Gem.configuration.rubygems_api_key = nil
    Gem.configuration.disable_default_gem_server = false

    super
  end

  def test_alternate_key_alternate_host
    keys = {
      :rubygems_api_key => 'KEY',
      "http://rubygems.engineyard.com" => "EYKEY"
    }

    FileUtils.mkdir_p File.dirname Gem.configuration.credentials_path

    open Gem.configuration.credentials_path, 'w' do |f|
      f.write keys.to_yaml
    end

    ENV["RUBYGEMS_HOST"] = "http://rubygems.engineyard.com"

    Gem.configuration.load_api_keys

    assert_equal 'EYKEY', @authorization.api_key
  end

  def test_api_key
    keys = { :rubygems_api_key => 'KEY' }
    FileUtils.mkdir_p File.dirname Gem.configuration.credentials_path

    open Gem.configuration.credentials_path, 'w' do |f|
      f.write keys.to_yaml
    end

    Gem.configuration.load_api_keys

    assert_equal 'KEY', @authorization.api_key
  end

  def test_api_key_override
    keys = { :rubygems_api_key => 'KEY', :other => 'OTHER' }
    FileUtils.mkdir_p File.dirname Gem.configuration.credentials_path

    open Gem.configuration.credentials_path, 'w' do |f|
      f.write keys.to_yaml
    end

    Gem.configuration.load_api_keys

    @authorization.add_key_option
    @cmd.handle_options %w[--key other]

    assert_equal 'OTHER', @authorization.api_key
  end

  def test_host
    assert_equal 'https://rubygems.org', @authorization.host
  end

  def test_host_RUBYGEMS_HOST
    ENV['RUBYGEMS_HOST'] = 'https://other.example'

    assert_equal 'https://other.example', @authorization.host
  end

  def test_host_RUBYGEMS_HOST_empty
    ENV['RUBYGEMS_HOST'] = ''

    assert_equal 'https://rubygems.org', @authorization.host
  end

  def test_rubygems_api_request_when_no_host
    Gem.configuration.disable_default_gem_server = true
    @authorization.host = nil
    response = "You must specify a gem server"

    assert_raises Gem::MockGemUi::TermError do
      use_ui @ui do
        @authorization.rubygems_api_request(Net::HTTP::Post, 'foobar')
      end
    end

    assert_match response, @ui.error
  end

  def test_api_request_with_disallowed_push_host
    host = "https://anotherprivategemserver.example"
    push_host = "https://privategemserver.example"

    @spec, @path = util_gem "freebird", "1.0.1" do |spec|
      spec.metadata['allowed_push_host'] = push_host
    end

    response = "ERROR:  \"#{host}\" is not allowed by the gemspec, which only allows \"#{push_host}\""

    assert_raises Gem::MockGemUi::TermError do
      use_ui @ui do
        @authorization.rubygems_api_request(Net::HTTP::Post, 'foobar', host, push_host)
      end
    end

    assert_match response, @ui.error
  end


  def test_sign_in
    api_key     = 'a5fdbb6ba150cbb83aad2bb2fede64cf040453903'
    util_sign_in [api_key, 200, 'OK']

    assert_match %r{Enter your RubyGems.org credentials.}, @sign_in_ui.output
    assert @fetcher.last_request["authorization"]
    assert_match %r{Signed in.}, @sign_in_ui.output

    credentials = YAML.load_file Gem.configuration.credentials_path
    assert_equal api_key, credentials[:rubygems_api_key]
  end

  def test_sign_in_with_host
    api_key     = 'a5fdbb6ba150cbb83aad2bb2fede64cf040453903'

    util_sign_in [api_key, 200, 'OK'], 'http://example.com', ['http://example.com']

    assert_match "Enter your http://example.com credentials.",
                 @sign_in_ui.output
    assert @fetcher.last_request["authorization"]
    assert_match %r{Signed in.}, @sign_in_ui.output

    credentials = YAML.load_file Gem.configuration.credentials_path
    assert_equal api_key, credentials['http://example.com']
  end

  def test_sign_in_with_host_nil
    api_key     = 'a5fdbb6ba150cbb83aad2bb2fede64cf040453903'

    util_sign_in [api_key, 200, 'OK'], nil, [nil]

    assert_match "Enter your RubyGems.org credentials.",
                 @sign_in_ui.output
    assert @fetcher.last_request["authorization"]
    assert_match %r{Signed in.}, @sign_in_ui.output

    credentials = YAML.load_file Gem.configuration.credentials_path
    assert_equal api_key, credentials[:rubygems_api_key]
  end

  def test_sign_in_with_host_ENV
    api_key     = 'a5fdbb6ba150cbb83aad2bb2fede64cf040453903'
    util_sign_in [api_key, 200, 'OK'], 'http://example.com'

    assert_match "Enter your http://example.com credentials.",
                 @sign_in_ui.output
    assert @fetcher.last_request["authorization"]
    assert_match %r{Signed in.}, @sign_in_ui.output

    credentials = YAML.load_file Gem.configuration.credentials_path
    assert_equal api_key, credentials['http://example.com']
  end

  def test_sign_in_skips_with_existing_credentials
    api_key     = 'a5fdbb6ba150cbb83aad2bb2fede64cf040453903'
    Gem.configuration.rubygems_api_key = api_key

    util_sign_in [api_key, 200, 'OK']

    assert_equal "", @sign_in_ui.output
  end

  def test_sign_in_skips_with_key_override
    api_key     = 'a5fdbb6ba150cbb83aad2bb2fede64cf040453903'
    Gem.configuration.api_keys[:KEY]  = 'other'
    @cmd.options[:key] = :KEY
    util_sign_in [api_key, 200, 'OK']

    assert_equal "", @sign_in_ui.output
  end

  def test_sign_in_with_other_credentials_doesnt_overwrite_other_keys
    api_key       = 'a5fdbb6ba150cbb83aad2bb2fede64cf040453903'
    other_api_key = 'f46dbb18bb6a9c97cdc61b5b85c186a17403cdcbf'

    FileUtils.mkdir_p File.dirname(Gem.configuration.credentials_path)
    open Gem.configuration.credentials_path, 'w' do |f|
      f.write Hash[:other_api_key, other_api_key].to_yaml
    end
    util_sign_in [api_key, 200, 'OK']

    assert_match %r{Enter your RubyGems.org credentials.}, @sign_in_ui.output
    assert_match %r{Signed in.}, @sign_in_ui.output

    credentials   = YAML.load_file Gem.configuration.credentials_path
    assert_equal api_key, credentials[:rubygems_api_key]
    assert_equal other_api_key, credentials[:other_api_key]
  end

  def test_sign_in_with_bad_credentials
    skip 'Always uses $stdin on windows' if Gem.win_platform?

    assert_raises Gem::MockGemUi::TermError do
      util_sign_in ['Access Denied.', 403, 'Forbidden']
    end

    assert_match %r{Enter your RubyGems.org credentials.}, @sign_in_ui.output
    assert_match %r{Access Denied.}, @sign_in_ui.output
  end

  def util_sign_in response, host = nil, args = []
    skip 'Always uses $stdin on windows' if Gem.win_platform?

    email    = 'you@example.com'
    password = 'secret'

    if host
      ENV['RUBYGEMS_HOST'] = host
    else
      host = Gem.host
    end

    @fetcher = Gem::FakeFetcher.new
    @fetcher.data["#{host}/api/v1/api_key"] = response
    Gem::RemoteFetcher.fetcher = @fetcher

    @sign_in_ui = Gem::MockGemUi.new "#{email}\n#{password}\n"

    use_ui @sign_in_ui do
      if args.length > 0 then
        @authorization.sign_in(*args)
      else
        @authorization.sign_in
      end
    end
  end

  def test_verify_api_key
    keys = {:other => 'a5fdbb6ba150cbb83aad2bb2fede64cf040453903'}
    FileUtils.mkdir_p File.dirname(Gem.configuration.credentials_path)
    File.open Gem.configuration.credentials_path, 'w' do |f|
      f.write keys.to_yaml
    end
    Gem.configuration.load_api_keys

    assert_equal 'a5fdbb6ba150cbb83aad2bb2fede64cf040453903',
                 @authorization.verify_api_key(:other)
  end

  def test_verify_missing_api_key
    assert_raises Gem::MockGemUi::TermError do
      @authorization.verify_api_key :missing
    end
  end

end
