use std::error::Error;
use std::fmt;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::io;
use std::path;
use std::net::SocketAddr;
use std::str::FromStr;

use regex;

use hyper::header;
use hyper::method::Method;

use rustc_serialize::json;
use rustc_serialize::Decodable;
use rustc_serialize::Encodable;

use url::Host;

use iron;
use iron::prelude::*;

use unicase::UniCase;


// FIXME: replace with quick_error?
#[derive(Debug)]
pub struct ServerError {
    pub error: Box<Error + Send>
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(f)
    }
}

impl Error for ServerError {
    fn description(&self) -> &str { self.error.description() }
    fn cause(&self) -> Option<&Error> { Some(&*self.error) }
}

impl From<io::Error> for ServerError {
    fn from(e: io::Error) -> ServerError {
        ServerError { error: Box::new(e) }
    }
}

impl From<json::DecoderError> for ServerError {
    fn from(e: json::DecoderError) -> ServerError {
        ServerError { error: Box::new(e) }
    }
}

impl From<json::EncoderError> for ServerError {
    fn from(e: json::EncoderError) -> ServerError {
        ServerError { error: Box::new(e) }
    }
}


pub fn safe_join<P: AsRef<path::Path>, Q: AsRef<path::Path>>(base: P, user_input: Q) -> Option<path::PathBuf> {
    let a = base.as_ref();
    let b = user_input.as_ref();

    let rv = a.join(b);
    if rv.starts_with(a) && rv.is_absolute() {
        Some(rv)
    } else {
        None
    }
}

pub trait EtagMatcher {
    fn matches_etag(&self, given: Option<&str>) -> bool;
}

impl EtagMatcher for header::IfNoneMatch {
    fn matches_etag(&self, given: Option<&str>) -> bool {
        match *self {
            header::IfNoneMatch::Any => given.is_some(),
            header::IfNoneMatch::Items(ref values) => {
                match given {
                    Some(given_value) => values.iter().any(|val| val.tag() == &given_value[..]),
                    None => false
                }
            }
        }
    }
}

impl EtagMatcher for header::IfMatch {
    fn matches_etag(&self, given: Option<&str>) -> bool {
        match *self {
            header::IfMatch::Any => given.is_some(),
            header::IfMatch::Items(ref values) => {
                match given {
                    Some(given_value) => values.iter().any(|val| val.tag() == &given_value[..]),
                    None => false
                }
            }
        }
    }
}

pub fn preconditions_ok(request: &Request, etag: Option<&str>) -> bool {
    match request.headers.get::<header::IfNoneMatch>() {
        Some(header) => if header.matches_etag(etag) { return false; },
        None => ()
    };

    match request.headers.get::<header::IfMatch>() {
        Some(header) => if !header.matches_etag(etag) { return false; },
        None => ()
    };
    true
}

fn set_cors_headers(rq: &Request, r: &mut Response) {
    match &rq.url.path[0][..] {
        ".well-known" | "storage" => (),
        _ => return
    };

    let origin = match rq.headers.get_raw("Origin") {
        Some(x) => if x.len() == 1 {
            match String::from_utf8(x.to_owned().into_iter().next().unwrap()) {
                Ok(x) => x,
                Err(_) => return
            }
        } else {
            return;
        },
        None => return
    };

    r.headers.set(header::AccessControlAllowOrigin::Value(origin));
    // FIXME: https://github.com/hyperium/hyper/issues/673
    r.headers.set_raw("Access-Control-Expose-Headers", vec![b"ETag".to_vec()]);
    r.headers.set(header::AccessControlAllowMethods(vec![Method::Get, Method::Put, Method::Delete]));
    r.headers.set(header::AccessControlAllowHeaders(vec![
        UniCase("Authorization".to_owned()),
        UniCase("Content-Type".to_owned()),
        UniCase("Origin".to_owned()),
        UniCase("If-Match".to_owned()),
        UniCase("If-None-Match".to_owned()),
    ]));
}

pub struct CorsMiddleware;

impl iron::middleware::AfterMiddleware for CorsMiddleware {
    fn after(&self, request: &mut Request, mut response: Response) -> IronResult<Response> {
        set_cors_headers(&request, &mut response);
        Ok(response)
    }

    fn catch(&self, request: &mut Request, mut error: IronError) -> IronResult<Response> {
        set_cors_headers(&request, &mut error.response);
        Err(error)
    }
}

pub fn prompt<T: AsRef<str>>(text: T) -> String {
    let mut stdout = io::stdout();
    stdout.write(text.as_ref().as_bytes()).unwrap();
    stdout.flush().unwrap();

    let stdin = io::stdin();
    let mut response = String::new();
    stdin.read_line(&mut response).unwrap();
    if response.ends_with("\n") { response.pop(); }
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
    question.push_str(if default { "[Y/n]" } else { "[y/N]" });
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
    };
}

pub fn read_json_file<T: Decodable, P: AsRef<path::Path>>(p: P) -> Result<T, ServerError> {
    let mut f = try!(fs::File::open(p.as_ref()));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    let rv = try!(json::decode(&s));
    Ok(rv)
}

pub fn write_json_file<T: Encodable, P: AsRef<path::Path>>(t: T, p: P) -> Result<(), ServerError> {
    let mut f = try!(fs::File::create(p.as_ref()));
    let data = try!(json::encode(&t));
    try!(f.write(&data.into_bytes()));
    Ok(())
}

pub fn is_safe_identifier(string: &str) -> bool {
    regex::Regex::new(r"^[A-Za-z0-9_-]+$").unwrap().is_match(string)
}

pub struct XForwardedMiddleware;

fn get_one_raw(r: &mut Request, key: &str) -> Option<String> {
    r.headers
        .get_raw(key)
        .and_then(|vals| if vals.len() > 0 { vals.to_owned().pop() } else { None })
        .and_then(|x| String::from_utf8(x).ok())
}

impl iron::middleware::BeforeMiddleware for XForwardedMiddleware {
    fn before(&self, r: &mut Request) -> IronResult<()> {
        get_one_raw(r, "X-Forwarded-Host")
            .and_then(|host| Host::parse(&host[..]).ok())
            .map(|x| r.url.host = x);

        get_one_raw(r, "X-Forwarded-For")
            .and_then(parse_remote_addrs)
            .map(|ip| r.remote_addr = ip);

        get_one_raw(r, "X-Forwarded-Proto")
            .map(|scheme| r.url.scheme = scheme.to_lowercase());

        Ok(())
    }
}

fn parse_remote_addrs(s: String) -> Option<SocketAddr> {
    let split = s.split(',');
    let mut iter_ips = split.map(|x| x.trim()).filter(|x| x.len() > 0);
    iter_ips.next().and_then(|ip| SocketAddr::from_str(ip).ok())
}
