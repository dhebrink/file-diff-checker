# Overview
Do you have a project that always requires a specific file to be updated with each PR?
Perhaps a file containing the version info that must be incremented in order for new installations
to install the updates?

This project will listen for any opened PRs on a given repo and check the diff for a given file.
If that file is not included in the PR's list of files changed, a review comment will be added
as a reminder to the Author and any other peers.

## Install

To run the code, make sure you have [Bundler](http://gembundler.com/) installed; then enter `bundle install` on the command line.

* Install this app on your GitHub account and give it access to a given repository.
* Add a `.file-checker.json` file in the root directory of your repo's `master` branch

```json
{
  "filename": "the_file_requiring_changes.py"
}
```

## Set environment variables

1. Create a copy of the `.env-example` file called `.env`.
1. Add the following to your `.env` file:
    1. GitHub App private key
    2. App ID
    3. App webhook secret
    4. GitHub API access key

## Local Testing

1. Go to `smee.io/new` to get a new proxy redirect URL
1. Run `smee --url <SMEE_URL> --port 3000 --path /event_handler`
1. Run `ruby server.rb` on the command line.

## TODO

* [ ] Check for multiple files required per PR?
* [ ] Investigate best practice for API authentication. `.env` key? Other programmatic options?
* [ ] Host the app
* [ ] Add tests
* [ ] Configure CI builds


*This was forked from the [`github-app-template`](https://github.com/github-developer/github-app-template) starter repo*
