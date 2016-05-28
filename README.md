# mysteryshack [![Build Status](https://travis-ci.org/untitaker/mysteryshack.svg?branch=master)](https://travis-ci.org/untitaker/mysteryshack)

<img src="https://shack.unterwaditzer.net/static/logo.svg" width=120 height=120 />

Mysteryshack is a lightweight, yet self-contained
[remoteStorage](http://remotestorage.io/)-server.

***This project is still in active development. Do not use with sensitive data, or without backup.***

Use username `demo` and password `demo` on [my
server](https://shack.unterwaditzer.net) to try it out. Don't use that account
for actual data though: It is reset daily.

## Installation

You need [OpenSSL](https://openssl.org/),
[Autoconf](https://www.gnu.org/software/autoconf/autoconf.html) and
[libtool](https://www.gnu.org/software/libtool/) installed.

* Install [Rust](https://www.rust-lang.org/) and [Cargo](https://crates.io/install).
* Clone this repository.
* Run `make`.
* Stick `./target/release/mysteryshack` into your PATH.

## Usage

* Edit `config.example` and save it as `config`.
* `mysteryshack user foo create` to create a new user. 
* `mysteryshack serve` to run the server as configured in `./config`.

For advanced usage, see `mysteryshack --help` and `mysteryshack user --help`.

## Updating

Just `git pull` and `make` again.

----

## Troubleshooting

### OS X and OpenSSL

As of OS X 10.11, OpenSSL isn't installed anymore. You'll need to install it manually:

    brew install openssl
    brew link --force openssl

## Implementation notes

* Mysteryshack mostly implements `draft-dejong-remotestorage-05.txt`, however:

  - it sends two kinds of webfinger responses to stay compatible with
    `remotestorage.js`.

  - The app-provided `client_id` is ignored, Origin of `redirect_uri` is used
    for app identification.

* Mysteryshack is set up to be tested against the official [api test
  suite](https://github.com/remotestorage/api-test-suite/) automatically (in
  Travis).

* Mysteryshack's approach to concurrency is very simplistic. Only storage
  operations are safe to perform concurrently. User creation and deletion, app
  authorization and de-authorization are not, because it is assumed that the
  user performing those operations is a single human with only two hands and
  one keyboard.

* Web admin sessions are stored inside signed cookies. The key is generated at
  server startup. To log everybody out, restart the server.

* OAuth tokens are JSON signed with a per-user key. The server stores a list
  of `client_id`s the user has authorized, and checks if the token's
  `client_id` claim is found in that list.

* Mysteryshack violates the WebFinger RFC by returning bogus information for
  nonexistent accounts. This is done to prevent account enumeration.


## License

* Logo is licensed under
  [CC-BY-SA](https://creativecommons.org/licenses/by-sa/3.0/), based on:

  * [Rust logo, CC-BY](https://www.rust-lang.org/legal.html)

  * [remoteStorage logo, CC-BY-SA](https://github.com/remotestorage/design)

* Source code is licensed under the MIT, see `LICENSE`.
