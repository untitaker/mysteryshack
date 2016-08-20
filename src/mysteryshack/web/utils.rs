use std::net::SocketAddr;

use hyper::header;
use hyper::method::Method;

use url::Position;

use urlencoded;

use unicase::UniCase;

use iron;
use iron::prelude::*;

use models;

header! { (XForwardedHost, "X-Forwarded-Host") => [String] }
header! { (XForwardedPort, "X-Forwarded-Port") => [u16] }
header! { (XForwardedProto, "X-Forwarded-Proto") => [String] }
header! { (XForwardedFor, "X-Forwarded-For") => [SocketAddr] }

pub struct XForwardedMiddleware;

impl iron::middleware::BeforeMiddleware for XForwardedMiddleware {
    fn before(&self, request: &mut Request) -> IronResult<()> {
        macro_rules! h {
            ($x:path, $n:expr) => {{
                // FIXME: https://github.com/hyperium/hyper/issues/891
                let rv = match request.headers.get::<$x>() {
                    Some(x) => x.0.clone(),
                    None => {
                        panic!("Missing header: {:?}. Turn off use_proxy_headers or set proxy headers.", $n);
                    }
                };
                assert!(request.headers.remove::<$x>());
                rv
            }}
        }
        let host = h!(XForwardedHost, "X-Forwarded-Host");
        let port = h!(XForwardedPort, "X-Forwarded-Port");
        let scheme = h!(XForwardedProto, "X-Forwarded-Proto");
        let remote_addr = h!(XForwardedFor, "X-Forwarded-For");

        // FIXME: https://github.com/iron/iron/pull/475
        let mut url = request.url.clone().into_generic_url();
        url.set_host(Some(&host)).unwrap();
        url.set_port(Some(port)).unwrap();
        url.set_scheme(&scheme).unwrap();

        request.url = iron::Url::from_generic_url(url).unwrap();
        request.remote_addr = remote_addr;
        Ok(())
    }
}

pub struct SecurityHeaderMiddleware;

impl iron::middleware::AfterMiddleware for SecurityHeaderMiddleware {
    fn after(&self, request: &mut Request, mut response: Response) -> IronResult<Response> {
        Self::set_security_headers(&request, &mut response);
        Ok(response)
    }

    fn catch(&self, request: &mut Request, mut error: IronError) -> IronResult<Response> {
        Self::set_security_headers(&request, &mut error.response);
        Err(error)
    }
}

impl SecurityHeaderMiddleware {
    fn set_security_headers(rq: &Request, r: &mut Response) {
        Self::set_cors_headers(rq, r);
        r.headers.set_raw("X-Content-Type-Options", vec![b"nosniff".to_vec()]);
        r.headers.set_raw("X-XSS-Protection", vec![b"1; mode=block".to_vec()]);

        let mut csp = vec!["default-src 'self'"];

        if rq.url.path()[0] != "storage" {
            // It's probably fine to embed user storage data into other documents

            // Prevent clickjacking attacks like described in OAuth RFC
            // https://tools.ietf.org/html/rfc6749#section-10.13
            r.headers.set_raw("X-Frame-Options", vec![b"DENY".to_vec()]);

            // This is a newer way to do what X-Frame-Options does
            // http://www.w3.org/TR/CSP11/#frame-ancestors-and-frame-options
            csp.push("frame-ancestors 'none'");
        };
        r.headers.set_raw("Content-Security-Policy", vec![csp.join(";").as_bytes().to_vec()]);
    }

    /// Required by remoteStorage spec
    fn set_cors_headers(rq: &Request, r: &mut Response) {
        match &rq.url.path()[0][..] {
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
        r.headers.set(header::AccessControlExposeHeaders(vec![
            UniCase("ETag".to_owned()),
            UniCase("Content-Length".to_owned())
        ]));
        r.headers.set(header::AccessControlAllowMethods(vec![Method::Get, Method::Put, Method::Delete]));
        r.headers.set(header::AccessControlAllowHeaders(vec![
            UniCase("Authorization".to_owned()),
            UniCase("Content-Type".to_owned()),
            UniCase("Origin".to_owned()),
            UniCase("If-Match".to_owned()),
            UniCase("If-None-Match".to_owned()),
        ]));
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
    if let Some(header) = request.headers.get::<header::IfNoneMatch>() {
        if header.matches_etag(etag) {
            return false
        }
    };

    if let Some(header) = request.headers.get::<header::IfMatch>() {
        if !header.matches_etag(etag) {
            return false
        }
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
            _ => None
        }
    }
}

pub fn get_account_id(user: &models::User, request: &Request) -> String {
    // FIXME: https://github.com/iron/iron/pull/475
    let url = request.url.clone().into_generic_url();
    let netloc = &url[Position::BeforeHost..Position::AfterPort];
    format!("{}@{}", user.userid, netloc)
}
