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
GITHUB_API = 'https://api.github.com/'


class MyRequest
  include HTTParty
  headers('Authorization' => 'token ' + ENV['GITHUB_API_TOKEN'],
          'User-Agent' => ENV['GITHUB_USER_AGENT'],
          'Accept' => 'application/json')
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

      diff_files = @installation_client.pull_request_files(repo_name, pr_number)
      repo_json_config = read_from_repo_config(repo_name)
      if repo_json_config == nil
        logger.error('Repo Config Read Error!')
        return
      end

      review_comment = perform_file_checking_from_repo_json(repo_json_config, diff_files)

      if review_comment
        api_options = {'body' => review_comment, 'event' => 'COMMENT'}
        @installation_client.create_pull_request_review(repo_name, pr_number, api_options)
      else
        logger.debug('No files needed reporting. All clear!')
      end
    end

    def read_from_repo_config(repo_name)
      file_json = nil
      repo_details = @installation_client.repository(repo_name)
      short_name = repo_details['name']
      owner_user = repo_details['owner']['login']
      content_path = 'repos/%{owner}/%{repo}/contents/%{config_file}' % { :owner => owner_user, :repo => short_name, :config_file => CONFIG_FILE }
      api_path = GITHUB_API + content_path
      logger.debug('Hitting GitHub API: ' + api_path)
      response = MyRequest.get(api_path)
      if response.code == 200
        logger.debug('Content request success!')
        file_content = JSON.parse(response.body)
        file_json = Base64.decode64(file_content['content'])
        file_json = JSON.parse(file_json)
      else
        logger.debug('Content Request Response: %s' % [response.code])
        logger.debug(response.body)
        logger.debug response
      end
      return file_json
    end

    def perform_file_checking_from_repo_json(repo_json, pr_diff_files)
      review_comment = ''
      spacer = '<br/>----<br/><br/>'
      required_filenames = repo_json.fetch('required', [])
      if !required_filenames.empty?
        warning = warn_against_required_files(required_filenames, pr_diff_files)
        if !warning.empty?
          review_comment += spacer + warning
        end
      else
        logger.debug('Required file config was empty')
      end

      caution_file_hash = repo_json.fetch('cautionary', {})
      if !caution_file_hash.empty?
        caution_msg = build_custom_caution_statements(caution_file_hash, pr_diff_files)
        if !caution_msg.empty?
          review_comment += spacer + caution_msg
        end
      else
        logger.debug('Cautionary file config was empty')
      end

      dependent_file_hash = repo_json.fetch('dependent', {})
      if !dependent_file_hash.empty?
        dependency_msg = check_file_diff_dependencies(dependent_file_hash, pr_diff_files)
        if !dependency_msg.empty?
          review_comment += spacer + dependency_msg
        end
      else
        logger.debug('Dependent file config was empty')
      end

      return review_comment
    end

    def warn_against_required_files(required_files, changed_files)
      logger.debug('REQUIRED FILES FOUND')
      logger.debug(required_files)
      comment_msg = 'The following files are required to be altered in all Pull Requests but were not found in this diff:<br/>'
      any_found = false
      for file_ in changed_files do
        this_filename = file_['filename']
        if required_files.include? this_filename
          comment_msg += '\t * ' + this_filename
          any_found = true
        end
      end

      if any_found
        return comment_msg
      else
        return ''
      end
    end

    def build_custom_caution_statements(cautionary_file_hash, changed_files)
      logger.debug('CAUTION FILES FOUND')
      logger.debug(cautionary_file_hash)
      comment = ''
      for file_ in changed_files do
        this_filename = file_['filename']
        file_message = cautionary_file_hash.fetch(this_filename, '')
        if !file_message.empty?
          comment += '* ' + file_message + '<br/>'
        end
      end

      return comment
    end

    def check_file_diff_dependencies(dependent_file_hash, changed_files)
      logger.debug('DEPENDENT FILES FOUND')
      logger.debug(dependent_file_hash)
      changed_filenames = []
      # Collect just the filenames so that we can make simpler comparisons
      # when looping through our dependency hash.
      for file_ in changed_files do
        changed_filenames.push(file_['filename'])
      end

      comment = ''
      dependent_file_hash.each { | file_changed, file_to_search_for |
        if changed_filenames.include? file_changed and !changed_filenames.include? file_to_search_for
          comment += '* `%s` was modified and requires corresponding modification to `%s`<br/>' % [file_changed, file_to_search_for]
        end
      }
      return comment
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
