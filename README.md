# Overview
Do you have a project that always requires a specific file to be updated with each PR?
Perhaps a file containing the version info that must be incremented in order for new installations
to install the updates?

This app will read PR events and leave comments based on a set of specified files.

* `required` - any files listed in this section will be expected in all PR diffs
* `cautionary` - customized warning messages if certain files are changed
* `dependent` - note any files that typically result in corresponding changes to other files in the repo

## Install

To run the code, make sure you have [Bundler](http://gembundler.com/) installed; then enter `bundle install` on the command line.

* Install this app on your GitHub account and give it read-access to a given repository.
* Add a `.file-checker.json` file in the root directory of your repo's `master` branch

```json
{
	"required": [
		"filename_1",
		"filename_2"
	],
	"cautionary": {
		"path/to/some/file": "You have modified a scary file. Here is a custom warning!"
	},
	"dependent": {
		"some/changed/file": "another/file/expected/to/be/changed"
	}
}
```

## Set environment variables

1. Create a copy of the `.env-example` file called `.env`.
1. Add the following to your `.env` file:
    1. GitHub App private key
    2. App ID
    3. App webhook secret
    4. GitHub API access key
    5. GitHub User Agent (used for API request header, pairs with API key?)

## Local Testing

1. Go to `smee.io/new` to get a new proxy redirect URL
1. Run `smee --url <SMEE_URL> --port 3000 --path /event_handler`
1. Run `ruby server.rb` on the command line.

## TODO

* [ ] Investigate best practice for API authentication. `.env` key? Other programmatic options?
* [ ] Host the app
* [ ] Add tests
* [ ] Configure CI builds


*This was forked from the [`github-app-template`](https://github.com/github-developer/github-app-template) starter repo*
