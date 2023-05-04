# mitmproxy

This is my custom fork of [mitmproxy](https://github.com/mitmproxy/mitmproxy). It contains a few extra modifications and changes that can't exactly be added to mitmproxy but are extremely helpful for me and what I do.

Specifically, this adds tools to mitmproxy to make automatic changes to particular requests & responses, which would normally require its own script to manage each change. It adds commands and a web interface to manage changes, along with the ability to import and export rules.

## Changes

### Replace response commands

Several commands and options were added to allow quickly making changes to update future responses to a particular URL without having to write your own script each time directly inside mitmproxy. To use it, you can use the following commands:

- `replace.body.file [file] [flow]`: replaces all future requests to a url with the content of a file (for example, `: replace.body.file ./test.txt @focus` will replace all future requests to the current url with whatever is in the file)
- `replace.body.content [content] [flow]`: same as `replace.body.file` but instead uses the content provided instead of the file
- `replace.body.edit [flow]`: this will open vim and allow you to edit the response body and persist the edited response for all future requests to that url (it can be invoked with `: replace.body.edit @focus`)
- `replace.body.remove [flow]`: removes any active replacements for a current url (example: `: replace.body.remove @focus`)
- `replace.body.clearall`: clears all active replacements

Replacements work through an option named `replace_response_body` that contains a series of JSON inputs that control body replacements. If you would like to persist certain replacements across sessions, you can do so by setting the `replace_response_body` option in your configuration.

### Interact

The interact tool allows you to easily create "rules" that automatically change information about requests and responses without having to create a script for each change you'd like. It works through based off of **conditions** that when met will result in **actions** as defined by the rule. They are easily managed through a locally hosted web panel, and rules can be easily exported and imported through mitmproxy itself.

Commands:
- `interact.open`: opens the Interact tool with a valid auth token in your default browser
- `interact.export [file]`: exports all active rules to a file
- `interact.import [file]`: imports rules from a file (note: you'll likely need to refresh your active web session to see them)

Options:
- `interact_server_host`: defines the host that the interact web server runs on, must be set before mitmproxy runs (default: `localhost`)
- `interact_server_port`: defines the port that the interact web server runs on, must be set before mitmproxy runs (default: `3032`)
- `interact_auth_token`: defines the authentication token used for the current session. if you set this to a specific value in your default options, you won't have to use `interact.open` each time you want to use it, but you will still have to remember to refresh. (default: randomly generated)
- `interact_debug`: boolean that defines whether or not stack traces should be included in 500 responses from the interact server. (default: `false`)
- `interact_rules`: an internal option that stores interact rules in an array (default: `[]`)

## Installation

To install, you will need to clone this repository and run the following while having Python 3.11 installed:

```sh
# make sure you are inside the repository when you run this
python3 -m venv venv
venv/bin/pip install -e ".[dev]"
```

If run successfully, this sets up the mitmproxy python venv to be able to run mitmproxy. If you would like to check to make sure it's working, you can use `venv/bin/mitmproxy` to see if it runs successfully.

While you could just use `venv/bin/mitmproxy` every time you want to use this version of mitmproxy, you can also add it to the path to make it your default version of mitmproxy (so that when you run `mitmproxy` anywhere, it will load this version).

Adding it to your path can be a bit tricky since mitmproxy is running in a venv. To make a directory that doesn't override other versions of python, you can run the following:

```sh
mkdir .bin
cd .bin
ln -s ../venv/bin/mitmproxy mitmproxy
ln -s ../venv/bin/mitmweb mitmweb
ln -s ../venv/bin/mitmdump mitmdump
cd ..
```

This will create a `.bin` directory that can be added to your path. You will then need to edit your `~/.bashrc` or `~/.zshrc` to include this file in the path. You can do this by adding `export PATH=$PATH:[absolute path for the .bin folder]` to those files and then using `source ~/.bashrc` or `source ~/.zshrc` respectively. You should then be able to launch this custom version of mitmproxy in your current terminal session and all future sessions by using `mitmproxy`.