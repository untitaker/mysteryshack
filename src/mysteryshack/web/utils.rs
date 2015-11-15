use std::net::SocketAddr;
use std::str::FromStr;

use hyper::header;
use hyper::method::Method;

use url::Host;
use url::SchemeData;

use urlencoded;

use unicase::UniCase;

use iron;
use iron::prelude::*;

use models;

pub struct XForwardedMiddleware;

fn get_one_raw(r: &mut Request, key: &str) -> Option<String> {
    r.headers
     .get_raw(key)
     .and_then(|vals| {
         if vals.len() > 0 {
             vals.to_owned().pop()
         } else {
             None
         }
     })
     .and_then(|x| String::from_utf8(x).ok())
}

impl iron::middleware::BeforeMiddleware for XForwardedMiddleware {
    fn before(&self, r: &mut Request) -> IronResult<()> {
        get_one_raw(r, "X-Forwarded-Host")
            .and_then(|host| Host::parse(&host[..]).ok())
            .map(|x| r.url.host = x);

        get_one_raw(r, "X-Forwarded-Port")
            .and_then(|s| u16::from_str(&s[..]).ok())
            .map(|port| r.url.port = port);

        get_one_raw(r, "X-Forwarded-For")
            .and_then(parse_remote_addrs)
            .map(|ip| r.remote_addr = ip);

        get_one_raw(r, "X-Forwarded-Proto").map(|scheme| r.url.scheme = scheme.to_lowercase());

        Ok(())
    }
}

fn parse_remote_addrs(s: String) -> Option<SocketAddr> {
    let split = s.split(',');
    let mut iter_ips = split.map(|x| x.trim()).filter(|x| x.len() > 0);
    iter_ips.next().and_then(|ip| SocketAddr::from_str(ip).ok())
}


pub struct SecurityHeaderMiddleware;

impl iron::middleware::AfterMiddleware for SecurityHeaderMiddleware {
    fn after(&self, request: &mut Request, mut response: Response) -> IronResult<Response> {
        set_cors_headers(&request, &mut response);
        set_frame_options(&request, &mut response);
        Ok(response)
    }

    fn catch(&self, request: &mut Request, mut error: IronError) -> IronResult<Response> {
        set_cors_headers(&request, &mut error.response);
        set_frame_options(&request, &mut error.response);
        Err(error)
    }
}

/// Required by remoteStorage spec
fn set_cors_headers(rq: &Request, r: &mut Response) {
    match &rq.url.path[0][..] {
        ".well-known" | "storage" => (),
        _ => return,
    };

    let origin = match rq.headers.get_raw("Origin") {
        Some(x) => if x.len() == 1 {
            match String::from_utf8(x.to_owned().into_iter().next().unwrap()) {
                Ok(x) => x,
                Err(_) => return,
            }
        } else {
            return;
        },
        None => return,
    };

    r.headers.set(header::AccessControlAllowOrigin::Value(origin));
    r.headers.set_raw("Access-Control-Expose-Headers", vec![b"ETag".to_vec()]);
    r.headers
     .set(header::AccessControlAllowMethods(vec![Method::Get, Method::Put, Method::Delete]));
    r.headers.set(header::AccessControlAllowHeaders(vec![
        UniCase("Authorization".to_owned()),
        UniCase("Content-Type".to_owned()),
        UniCase("Origin".to_owned()),
        UniCase("If-Match".to_owned()),
        UniCase("If-None-Match".to_owned()),
    ]));
}

/// Prevent clickjacking attacks like described in OAuth RFC
/// https://tools.ietf.org/html/rfc6749#section-10.13
fn set_frame_options(rq: &Request, r: &mut Response) {
    match &rq.url.path[0][..] {
        // It's probably fine to embed user storage data into other documents
        "storage" => return,
        _ => (),
    };

    r.headers.set_raw("X-Frame-Options", vec![b"DENY".to_vec()]);
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
                    None => false,
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
                    None => false,
                }
            }
        }
    }
}

pub fn preconditions_ok(request: &Request, etag: Option<&str>) -> bool {
    match request.headers.get::<header::IfNoneMatch>() {
        Some(header) => if header.matches_etag(etag) {
            return false;
        },
        None => (),
    };

    match request.headers.get::<header::IfMatch>() {
        Some(header) => if !header.matches_etag(etag) {
            return false;
        },
        None => (),
    };
    true
}

pub trait FormDataHelper<K: ?Sized, V> {
    fn get_only<Q: AsRef<K>>(&self, k: Q) -> Option<&String>;
}

impl FormDataHelper<str, String> for urlencoded::QueryMap {
    fn get_only<Q: AsRef<str>>(&self, k: Q) -> Option<&String> {
        match self.get(&k.as_ref().to_owned()) {
            Some(x) if x.len() == 1 => Some(&x[0]),
            _ => None,
        }
    }
}

pub fn get_account_id(user: &models::User, request: &Request) -> String {
    let url = request.url.clone().into_generic_url();
    let scheme_data = match url.scheme_data {
        SchemeData::Relative(ref x) => x,
        _ => panic!("Expected relative scheme data."),
    };

    let mut rv = format!("{}@{}", user.userid, scheme_data.host);
    if let Some(port) = scheme_data.port {
        if Some(port) != scheme_data.default_port {
            rv.push_str(&format!(":{}", port)[..]);
        }
    };

    rv
}
