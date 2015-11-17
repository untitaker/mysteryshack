use std::collections;
use std::fmt;
use std::error::Error as ErrorTrait;

use rustc_serialize::json;
use rustc_serialize::json::ToJson;

use hyper::header;

use url;

use iron::prelude::*;
use iron::modifiers::Header;
use iron::status;

use urlencoded;

// FIXME: oauth module should not be concerned with serialization
#[derive(RustcDecodable, RustcEncodable, Debug, Clone)]
pub struct OauthRequest {
    pub session: Session,
    pub state: Option<String>,
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone)]
pub struct Session {
    pub client_id: String,
    pub uri: url::Url,
    pub permissions: collections::HashMap<String, CategoryPermissions>
}

impl Session {
    pub fn permissions_for_category(&self, category: &str) -> Option<&CategoryPermissions> {
        match self.permissions.get(category) {
            Some(x) => Some(x),
            None => self.permissions.get("")
        }
    }
}

impl ToJson for Session {
    fn to_json(&self) -> json::Json {
        json::Json::Object({
            let mut rv = collections::BTreeMap::new();
            rv.insert("client_id".to_owned(), self.client_id.to_json());
            rv.insert("uri".to_owned(), self.uri.serialize().to_json());
            rv.insert("permissions".to_owned(), self.permissions.to_json());
            rv
        })
    }
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone, Copy)]
pub struct CategoryPermissions {
    pub can_read: bool,
    pub can_write: bool
}

impl ToJson for CategoryPermissions {
    // ToJson for passing to template
    fn to_json(&self) -> json::Json {
        json::Json::Object({
            let mut rv = collections::BTreeMap::new();
            rv.insert("can_read".to_owned(), self.can_read.to_json());
            rv.insert("can_write".to_owned(), self.can_write.to_json());
            rv
        })
    }
}

impl ToJson for OauthRequest {
    // ToJson for passing to template
    fn to_json(&self) -> json::Json {
        self.session.to_json()
    }
}

fn expect_param(query: &urlencoded::QueryMap, key: &str) -> Result<String, Error> {
    match query.get(key) {
        Some(x) if x.len() == 1 => Ok(x[0].clone()),
        _ => Err({
            let mut rv = Error::new(ErrorKind::InvalidRequest);
            rv.msg = Some(format!("Missing query parameter: {:?}", key));
            rv
        })
    }
}


impl OauthRequest {
    pub fn from_http(request: &mut Request) -> Result<Self, Error> {
        let query = match request.get_ref::<urlencoded::UrlEncodedQuery>().ok() {
            Some(x) => x,
            None => return Err({
                let mut e = Error::new(ErrorKind::InvalidRequest);
                e.msg = Some("No query parameters.".to_owned());
                e
            })
        };

        let mut rv = OauthRequest {
            session: Session {
                client_id: "".to_owned(),
                uri: match url::Url::parse(&try!(expect_param(query, "redirect_uri"))[..]) {
                    Ok(x) => x,
                    Err(e) => return Err({
                        let mut ne = Error::new(ErrorKind::InvalidRequest);
                        ne.msg = Some(format!("{}", e));
                        ne
                    })
                },
                permissions: collections::HashMap::new()
            },
            state: expect_param(query, "state").ok() 
        };

        rv.session.client_id = match expect_param(query, "client_id") {
            Ok(x) => x,
            Err(mut e) => {
                e.request = Some(rv);
                return Err(e);
            }
        };

        let scope = match expect_param(query, "scope") {
            Ok(x) => x,
            Err(mut e) => {
                e.request = Some(rv);
                return Err(e);
            }
        };

        let scope_err = |x| { Err({
            let mut e = Error::new(ErrorKind::InvalidScope);
            e.msg = Some("Invalid scope.".to_owned());
            e.request = Some(x);
            e
        }) };

        for category_permission in scope.split(' ') {
            let parts = category_permission.split(':').collect::<Vec<_>>();
            if parts.len() != 2 { return scope_err(rv); }

            let (category, permission) = (parts[0], parts[1]);
            if category.len() == 0 || permission.len() == 0 { return scope_err(rv); }

            let key = (if category == "*" { "" } else { category }).to_owned();
            if rv.session.permissions.get(&key).is_some() { return scope_err(rv); }

            rv.session.permissions.insert(key, CategoryPermissions {
                can_read: permission.contains("r"),
                can_write: permission.contains("w")
            });
        }

        Ok(rv)
    }

    pub fn grant(self, token: String) -> Grant {
        Grant { request: self, token: token }
    }

    pub fn reject(self) -> Error {
        let mut e = Error::new(ErrorKind::AccessDenied);
        e.request = Some(self);
        e
    }
}

pub struct Grant {
    pub request: OauthRequest,
    pub token: String
}

impl HttpResponder for Grant {
    fn get_redirect_uri(&self) -> Option<url::Url> {
        Some(self.request.session.uri.clone())
    }

    fn get_redirect_uri_params(&self) -> collections::BTreeMap<String, String> {
        let mut rv = collections::BTreeMap::new();
        rv.insert("access_token".to_owned(), self.token.clone());
        self.request.state.as_ref().map(|x| rv.insert("state".to_owned(), x.clone()));
        rv
    }
}

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub request: Option<OauthRequest>,
    pub error_uri: Option<url::Url>,
    pub msg: Option<String>
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Error {
            kind: kind,
            request: None,
            error_uri: None,
            msg: None
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ErrorKind {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable
}

impl ErrorKind {
    fn as_snake_case(&self) -> &str {
        match *self {
            ErrorKind::InvalidRequest => "invalid_request",
            ErrorKind::UnauthorizedClient => "unauthorized_client",
            ErrorKind::AccessDenied => "access_denied",
            ErrorKind::UnsupportedResponseType => "unsupported_response_type",
            ErrorKind::InvalidScope => "invalid_scope",
            ErrorKind::ServerError => "server_error",
            ErrorKind::TemporarilyUnavailable => "temporarily_unavailable"
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.description().fmt(f) }
}

impl ErrorTrait for Error {
    fn description(&self) -> &str {
        match self.msg {
            Some(ref x) => x,
            None => self.kind.as_snake_case()
        }
    }
    fn cause(&self) -> Option<&ErrorTrait> { None }
}

pub trait HttpResponder {
    fn get_redirect_uri(&self) -> Option<url::Url>;
    fn get_redirect_uri_params(&self) -> collections::BTreeMap<String, String>;

    fn get_response(&self) -> Option<Response> {
        self.get_redirect_uri()
            .map(|mut uri| {
                uri.fragment = Some(url::form_urlencoded::serialize(self.get_redirect_uri_params()));
                Response::with(status::Found)
                 // Do not use Redirect modifier here, we need to handle custom URI schemes as well
                 .set(Header(header::Location(uri.serialize())))
            })
    }
}

impl HttpResponder for Error {
    fn get_redirect_uri(&self) -> Option<url::Url> {
        self.request.as_ref().map(|req| req.session.uri.clone())
    }

    fn get_redirect_uri_params(&self) -> collections::BTreeMap<String, String> {
        let mut rv = collections::BTreeMap::new();
        rv.insert("error".to_owned(), self.kind.as_snake_case().to_owned());
        self.msg.as_ref().map(|x| rv.insert("error_description".to_owned(), x.clone()));
        self.request.as_ref().map(|req| req.state.as_ref().map(|state| rv.insert("state".to_owned(), state.clone())));
        rv
    }
}
