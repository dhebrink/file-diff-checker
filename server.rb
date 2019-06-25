require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements
require 'httparty'    # Sending additional API requests
require 'base64'

set :port, 3000
set :bind, '0.0.0.0'

CONFIG_FILE = '.file-checker.json'
CONFIG_KEY = 'filename'
GITHUB_API = 'https://api.github.com/'


class MyRequest
  include HTTParty
  # TODO: This isn't authenticating correctly...
  headers('Authorization' => '60fd0f91763f2f240be028bb2cc4058a6b379d44',
          'User-Agent' => 'Hebrink First Test App')
end


# This is template code to create a GitHub App server.
# You can read more about GitHub Apps here: # https://developer.github.com/apps/
#
# On its own, this app does absolutely nothing, except that it can be installed.
# It's up to you to add functionality!
# You can check out one example in advanced_server.rb.
#
# This code is a Sinatra app, for two reasons:
#   1. Because the app will require a landing page for installation.
#   2. To easily handle webhook events.
#
# Of course, not all apps need to receive and process events!
# Feel free to rip out the event handling code if you don't need it.
#
# Have fun!
#

class GHAapp < Sinatra::Application

  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end


  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    # Authenticate the app installation in order to run API operations
    authenticate_installation(@payload)
  end


  post '/event_handler' do

    # # # # # # # # # # # #
    # ADD YOUR CODE HERE  #
    # # # # # # # # # # # #

    the_event = request.env['HTTP_X_GITHUB_EVENT']
    the_action = @payload['action']
    unknown_message = 'Unknown %s action: %s' % [the_event, the_action]
    case the_event
    when 'pull_request'
      if the_action === 'opened' || the_action === 'reopened'
        handle_opened_pr(@payload)
      else
        logger.debug(unknown_message)
      end
    else
        logger.debug(unknown_message)
    end
  end


  helpers do

    # # # # # # # # # # # # # # # # #
    # ADD YOUR HELPER METHODS HERE  #
    # # # # # # # # # # # # # # # # #
  
    def handle_opened_pr(the_payload)
      pr_number = the_payload['pull_request']['number']
      repo_name = the_payload['repository']['full_name']

      # TODO: Get the config file from the repo's MASTER branch that tells us which file to check for.
      file_of_interest = 'required_file_to_change.py'
      #file_of_interest = read_from_repo_config(repo_name)

      # Grab the files changed in the PR and see if one of them is our target file.
      found = false
      diff_files = @installation_client.pull_request_files(repo_name, pr_number)
      for f in diff_files do
        logger.debug('%s found as changed' % [f['filename']])
        if f['filename'] == file_of_interest
            found = true
            break
        end
      end

      if !found
        comment = 'Review your changes that have been submitted. The following file is required to be updated: `%s`' % [file_of_interest]
        api_options = {'body' => comment, 'event' => 'COMMENT'}
        @installation_client.create_pull_request_review(repo_name, pr_number, api_options)
      end
    end

    def read_from_repo_config(repo_name)
      target_file = nil
      repo_details = @installation_client.repository(repo_name)
      short_name = repo_details['name']
      owner_user = repo_details['owner']['login']
      content_path = 'repos/%{owner}/%{repo}/%{config_file}' % { :owner => owner_user, :repo => short_name, :config_file => CONFIG_FILE }
      # TODO: This is failing with 404 due to lack of authorization... Not sure what to do here at this time.
      response = MyRequest.get(GITHUB_API + content_path)
      if response.code == 200
        file_content = JSON.parse(response.body)
        file_json = Base64.decode64(file_content['content'])
        file_json = JSON.parse(file_json)
        target_file = file_json[CONFIG_KEY]
      else
        logger.debug('Content Request Response: ' + response.code)
        logger.debug(response.body)
      end
      return target_file
    end

    ############## BEGIN - template helper functions

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app an not altererd by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: "sha1=123456".
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
