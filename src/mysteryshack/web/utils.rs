use std::net::SocketAddr;
use std::str::FromStr;

use hyper::header;
use hyper::method::Method;

use url::Host;

use unicase::UniCase;

use iron;
use iron::prelude::*;

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

        get_one_raw(r, "X-Forwarded-Port")
            .and_then(|s| u16::from_str(&s[..]).ok())
            .map(|port| r.url.port = port);

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

