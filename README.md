# mysteryshack [![Build Status](https://travis-ci.org/untitaker/mysteryshack.svg?branch=master)](https://travis-ci.org/untitaker/mysteryshack)

Mysteryshack is a lightweight, yet self-contained
[remoteStorage](http://remotestorage.io/)-server.

***This project is still in active development. Do not use with sensitive data, or without backup.***

Use username `demo` and password `demo` on [my
server](https://shack.unterwaditzer.net) to try it out.

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

## License

Licensed under the MIT, see `LICENSE`.
