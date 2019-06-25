# Overview
Do you have a project that always requires a specific file to be updated with each PR?
Perhaps a file containing the version info that must be incremented in order for new installations
to install the updates?

This project will listen for any opened PRs on a given repo and check the diff for a given file.
If that file is not included in the PR's list of files changed, a review comment will be added
as a reminder to the Author and any other peers.

## Install

To run the code, make sure you have [Bundler](http://gembundler.com/) installed; then enter `bundle install` on the command line.

## Set environment variables

1. Create a copy of the `.env-example` file called `.env`.
2. Add your GitHub App's private key, app ID, and webhook secret to the `.env` file.

## Run the server

1. Run `ruby server.rb` on the command line.
1. View the Sinatra app at `localhost:3000`.

## TODO

* [ ] Read the target file from the target repo's config file (`.file-checker.json`)
  * [ ] Authenticate with API from app
  * [ ] Send API request to pull repo file content
* [ ] Check for multiple files required per PR?
* [ ] Host the app
* [ ] Add tests
* [ ] Configure CI builds
