#![cfg_attr(feature = "clippy", allow(unstable_features))]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", deny(warnings))]

extern crate rustc_serialize;
#[macro_use] extern crate iron;
extern crate router;
extern crate hyper;
extern crate toml;
extern crate unicase;
extern crate atomicwrites;
extern crate url;
extern crate urlencoded;
extern crate clap;
extern crate sodiumoxide;
extern crate rand;
extern crate persistent;
extern crate iron_login;
extern crate handlebars;
extern crate handlebars_iron;
extern crate mount;
extern crate regex;
#[macro_use] extern crate quick_error;
extern crate time;
extern crate filetime;
extern crate chrono;
extern crate nix;
extern crate itertools;
extern crate uuid;
extern crate jsonwebtoken;
extern crate webicon;

#[cfg(test)]
extern crate tempdir;

pub mod cli;
mod web;
mod models;
mod utils;
mod config;
