# mysteryshack [![Build Status](https://travis-ci.org/untitaker/mysteryshack.svg?branch=master)](https://travis-ci.org/untitaker/mysteryshack)

Mysteryshack is a lightweight, yet self-contained
[remoteStorage](http://remotestorage.io/)-server.

***This project is still in active development. Do not use with sensitive data, or without backup.***

## Usage

* Install [Rust](https://www.rust-lang.org/).
* Clone this repository.
* Edit `config.example` and save it as `config`.
* Run `cargo build --release`.
* `./target/release/mysteryshack` is your binary.
* `mysteryshack user create foo` to create a new user. See also `mysteryshack
  --help` and `mysteryshack user --help`.
* `mysteryshack serve` to run the server as configured in `./config`.

## Troubleshooting

### OS X and OpenSSL

As of OS X 10.11, OpenSSL isn't installed anymore. You'll need to install it manually:

    brew install openssl
    brew link --force openssl

## Implementation notes

* Mysteryshack implements `draft-dejong-remotestorage-05.txt`, however, it
  sends two kinds of webfinger responses to stay compatible with
  `remotestorage.js`.

* Mysteryshack is set up to be tested against the official [api test
  suite](https://github.com/remotestorage/api-test-suite/) automatically (in
  Travis).

* Mysteryshack's approach to concurrency is very simplistic, but is certainly
  enough for smaller to medium-sized servers.

* Mysteryshack stores OAuth tokens on the harddrive, but web admin sessions are
  stored inside signed cookies. The key is generated at server startup. To log
  everybody out, restart the server.

## License

Licensed under the MIT, see `LICENSE`.
