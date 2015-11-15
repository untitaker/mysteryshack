use std::error::Error;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::io;
use std::path;

use atomicwrites;
use regex;
use config;

use rustc_serialize::json;
use rustc_serialize::Decodable;
use rustc_serialize::Encodable;


quick_error! {
    // FIXME: https://github.com/tailhook/quick-error/issues/3
    #[derive(Debug)]
    pub enum ServerError {
        Io(error: io::Error) {
            display("{}", error)
            description(error.description())
            cause(error)
            from()
        }
        JsonDecode(error: json::DecoderError) {
            display("{}", error)
            description(error.description())
            cause(error)
            from()
        }
        JsonEncode(error: json::EncoderError) {
            display("{}", error)
            description(error.description())
            cause(error)
            from()
        }
        ConfigError(error: config::Error) {
            display("{}", error)
            description(error.description())
            cause(error)
            from()
        }
    }
}

pub fn safe_join<P: AsRef<path::Path>, Q: AsRef<path::Path>>(base: P,
                                                             user_input: Q)
                                                             -> Option<path::PathBuf> {
    let a = base.as_ref();
    let b = user_input.as_ref();

    let rv = a.join(b);
    if rv.starts_with(a) && rv.is_absolute() {
        Some(rv)
    } else {
        None
    }
}

pub fn prompt<T: AsRef<str>>(text: T) -> String {
    let mut stdout = io::stdout();
    stdout.write(text.as_ref().as_bytes()).unwrap();
    stdout.flush().unwrap();

    let stdin = io::stdin();
    let mut response = String::new();
    stdin.read_line(&mut response).unwrap();
    if response.ends_with("\n") {
        response.pop();
    }
    response
}

pub fn double_prompt<T: AsRef<str>>(text: T) -> String {
    let again_text = {
        let mut x = "(confirm) ".to_string();
        x.push_str(text.as_ref());
        x
    };

    loop {
        let first = prompt(text.as_ref());
        let second = prompt(&again_text[..]);
        if first == second {
            return first;
        } else {
            println!("Inputs don't match. Try again.");
        }
    }
}

pub fn prompt_confirm<T: AsRef<str>>(question: T, default: bool) -> bool {
    let mut question = question.as_ref().to_owned();
    question.push_str(" ");
    question.push_str(if default {
        "[Y/n]"
    } else {
        "[y/N]"
    });
    question.push_str(" ");
    loop {
        let response = prompt(&question[..]);
        return match response.trim() {
            "y" | "Y" => true,
            "n" | "N" => false,
            "" => default,
            _ => {
                println!("Invalid answer.");
                continue;
            }
        };
    }
}

pub fn read_json_file<T: Decodable, P: AsRef<path::Path>>(p: P) -> Result<T, ServerError> {
    let mut f = try!(fs::File::open(p.as_ref()));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    let rv = try!(json::decode(&s));
    Ok(rv)
}

pub fn write_json_file<T: Encodable, P: AsRef<path::Path>>(t: T, p: P) -> Result<(), ServerError> {
    let data = try!(json::encode(&t)).into_bytes();
    let f = atomicwrites::AtomicFile::new(p, atomicwrites::AllowOverwrite);
    try!(f.write(|f| f.write(&data)));
    Ok(())
}

pub fn is_safe_identifier(string: &str) -> bool {
    regex::Regex::new(r"^[A-Za-z0-9_-]+$").unwrap().is_match(string)
}
