use std::collections;
use std::io;
use std::fs;
use std::ops::Deref;

use hyper::header;

use iron;

use iron::prelude::*;
use iron::modifiers::{Header,Redirect};
use iron::status;
use iron::method::Method;
use iron::typemap::Key;
use router::Router;

use rand::{Rng,StdRng};

use persistent;

use handlebars_iron::{Template,HandlebarsEngine};

use urlencoded;

use iron_login::{User,LoginManager};

use url;

use rustc_serialize::json;
use rustc_serialize::json::ToJson;

use models;
use models::UserNode;
use models::SessionManager;
use config;
use utils;
use utils::EtagMatcher;

#[derive(Copy, Clone)]
pub struct AppConfig;
impl Key for AppConfig { type Value = config::Config; }

macro_rules! itry {
    ($expr:expr) => (match $expr {
        ::std::result::Result::Ok(val) => val,
        ::std::result::Result::Err(err) => {
            return ::std::result::Result::Err(
                ::iron::IronError::new(err, ::iron::status::InternalServerError))
        }
    })
}

macro_rules! some_or {
    ($expr:expr, $modifier:expr) => (match $expr {
        Some(x) => x,
        None => return Ok(Response::new().set($modifier))
    })
}

macro_rules! require_login_as {
    ($req:expr, $expect_user:expr) => ({
        let login_redirect = Ok(Response::with((status::Found, Redirect({
            let mut url = $req.url.clone();
            url.path = vec!["login".to_owned(), "".to_owned()];
            url.fragment = None;
            let mut url = url.into_generic_url();
            let redirect_to = $req.url.clone().into_generic_url().serialize();
            let mut query = vec![("redirect_to", &redirect_to[..])];
            if $expect_user.len() > 0 { query.push(("prefill_user", $expect_user)); }
            url.set_query_from_pairs(query.into_iter());
            iron::Url::from_generic_url(url).unwrap()
        }))));

        match models::User::from_request($req) {
            Some(x) => if $expect_user.len() == 0 || &x.userid[..] == $expect_user { x }
                       else { return login_redirect },
            _ => return login_redirect
        }
    })
}

macro_rules! require_login { ($req:expr) => (require_login_as!($req, "")) }

macro_rules! check_csrf {
    ($req:expr) => (match
        $req.headers.get::<header::Referer>()
        .and_then(|s| url::Url::parse(s).ok())
        .and_then(|u| if u == $req.url.clone().into_generic_url() { Some(()) } else { None }) {
            Some(_)  => (),
            _ => return Ok(Response::with((status::BadRequest, "CSRF detected.")))
        }
    )
}

struct ErrorPrinter;
impl iron::middleware::AfterMiddleware for ErrorPrinter {
    fn catch(&self, _: &mut Request, err: IronError) -> IronResult<Response> {
        println!("Server error: {:?}", err);
        Err(err)
    }
}

pub fn run_server(config: config::Config) {
    let mut router = Router::new();


    router.options("*", |_: &mut Request| Ok(Response::with(status::Ok)));

    for route in ["/storage/:userid/*path", "/storage/:userid/"].iter() {
        for method in [Method::Get, Method::Put, Method::Delete].into_iter() {
            router.route(method.clone(), route, user_node_response);
        }
    }

    router.get("/.well-known/webfinger", webfinger_response);
    router.get("/dashboard/", user_dashboard);
    router.get("/login/", user_login_get);
    router.post("/login/", user_login_post);
    router.get("/oauth/:userid/", oauth_entry);
    router.post("/oauth/:userid/", oauth_entry);

    let mut chain = Chain::new(router);
    if config.use_proxy_headers { chain.link_before(utils::XForwardedMiddleware); }
    chain.link(persistent::Read::<AppConfig>::both(config.clone()));
    chain.around(LoginManager::new({
        println!("Generating session keys...");
        let mut rv = [0u8; 24];
        let mut rng = StdRng::new().unwrap();
        rng.fill_bytes(&mut rv);
        rv.to_vec()
    }));

    // FIXME: Inline templates into bin
    chain.link_after(HandlebarsEngine::new("./src/templates/", ".hbs"));
    chain.link_after(utils::CorsMiddleware);
    chain.link_after(ErrorPrinter);

    let listen = &config.listen[..];
    println!("Listening on: http://{}", listen);
    Iron::new(chain).listen_with(listen, 1, iron::Protocol::Http).unwrap();
}

fn user_node_response(req: &mut Request) -> IronResult<Response> {
    let write_operation = match req.method {
        Method::Get | Method::Head => false,
        _ => true
    };
    let config = req.get::<persistent::Read<AppConfig>>().unwrap();
    let data_path = &config.data_path;

    let (userid, path_str) = {
        let parts = req.extensions.get::<Router>().unwrap();
        let userid = parts.find("userid").unwrap().to_owned();
        // FIXME: https://github.com/iron/router/issues/97
        let path_str = String::from_utf8(
            url::percent_encoding::percent_decode(
                parts.find("path").unwrap_or("").as_bytes())).unwrap();
        (userid, path_str)
    };

    let user = match models::User::get(data_path, &userid[..]) {
        Some(x) => x,
        None => return Ok(Response::with(status::Forbidden))
    };

    let access_token = match req.headers.get::<header::Authorization<header::Bearer>>() {
        Some(x) => Some(x.token.clone()),
        None => None
    };

    let permissions = user.get_permissions(
        access_token.as_ref().map(Deref::deref),
        &path_str[..]
    );

    if !permissions.can_read || (write_operation && !permissions.can_write) {
        return Ok(Response::with(status::Forbidden))
    }

    if path_str.len() == 0 || path_str.ends_with("/") {
        match models::UserFolder::from_path(&user, &path_str[..]) {
            Some(x) => x.respond(req),
            None => Ok(Response::with(status::BadRequest))
        }
    } else {
        match models::UserFile::from_path(&user, &path_str[..]) {
            Some(x) => x.respond(req),
            None => Ok(Response::with(status::BadRequest))
        }
    }
}

fn user_login_get(request: &mut Request) -> IronResult<Response> {
    let mut r = Response::with(status::Ok);
    r.headers.set(header::ContentType("text/html".parse().unwrap()));
    r.set_mut(Template::new("login", {
        let mut rv = collections::BTreeMap::new();
        request.get_ref::<urlencoded::UrlEncodedQuery>().ok()
            .and_then(|query| query.get("prefill_user"))
            .and_then(|params| if params.len() == 1 { Some(params) } else { None })
            .and_then(|x| rv.insert("prefill_user".to_owned(), x[0].to_json()));
        rv
    }));
    Ok(r)
}

fn user_login_post(request: &mut Request) -> IronResult<Response> {
    check_csrf!(request);
    let config = request.get::<persistent::Read<AppConfig>>().unwrap();
    let data_path = &config.data_path;

    let (ref username, ref password) = {
        let formdata = itry!(request.get_ref::<urlencoded::UrlEncodedBody>());
        (
            &formdata.get("user").unwrap()[0].clone(),
            &formdata.get("pass").unwrap()[0].clone()
        )
    };

    let bad_creds = Ok(Response::with((status::Ok, "Wrong credentials.")));

    let user = match models::User::get(data_path, &username[..]) {
        Some(user) => if (&user).get_password_hash().unwrap().equals_password(password) {
            user
        } else {
            return bad_creds;
        },
        None => return bad_creds
    };

    let url = request.get_ref::<urlencoded::UrlEncodedQuery>().ok()
        .and_then(|query| query.get("redirect_to"))
        .and_then(|params| if params.len() == 1 { Some(params) } else { None })
        .and_then(|x| iron::Url::parse(&x[0].clone()).ok())
        .unwrap_or_else(|| {
            let mut rv = request.url.clone();
            rv.path = vec!["dashboard".to_string(), "".to_string()];
            rv.query = None;
            rv.fragment = None;
            rv
        });

    if &url.scheme != &request.url.scheme || &url.host != &request.url.host || &url.port != &request.url.port {
        return Ok(Response::with(status::BadRequest));
    }

    return Ok(Response::with(status::Ok)
              .set(user.log_in())
              .set(status::Found)
              .set(Redirect(url)));
}

fn user_dashboard(request: &mut Request) -> IronResult<Response> {
    let user = require_login!(request);
    Ok(Response::with(status::Ok).set(format!("Hello, {}!", user.userid)))
}

fn oauth_entry(request: &mut Request) -> IronResult<Response> {
    let oauth_userid = {
        let parts = request.extensions.get::<Router>().unwrap();
        parts.find("userid").unwrap().to_owned()
    };
    let user = require_login_as!(request, &oauth_userid[..]);
    let oauth_request = some_or!(OauthRequest::from_http(request), status::BadRequest);

    match request.method {
        Method::Get => Ok(Response::with(status::Ok).set(Template::new("oauth_entry", oauth_request.to_json()))),
        Method::Post => {
            check_csrf!(request);
            let allow = some_or!({
                let formdata = itry!(request.get_ref::<urlencoded::UrlEncodedBody>());
                match &formdata.get("decision").unwrap()[0][..] {
                    "allow" => Some(true),
                    "deny" => Some(false),
                    _ => None
                }
            }, status::BadRequest);

            let mut redirect_uri = itry!(url::Url::parse(&oauth_request.session.uri[..]));
            if allow {
                redirect_uri.fragment = Some(url::form_urlencoded::serialize({
                    let mut rv = collections::BTreeMap::new();
                    oauth_request.state.map(|x| rv.insert("state", x));
                    rv.insert("access_token", itry!(user.create_session(oauth_request.session)));
                    rv
                }));
            }
            Ok(Response::with(status::Found)
               // Do not use Redirect modifier here, we need to handle custom URI schemes as well
               .set(Header(header::Location(redirect_uri.serialize()))))
        },
        _ => Ok(Response::with(status::BadRequest))
    }
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone)]
struct OauthRequest {
    pub session: models::Session,
    pub state: Option<String>,
}

impl ToJson for OauthRequest {
    // ToJson for passing to template
    fn to_json(&self) -> json::Json {
        json::Json::Object({
            let mut rv = collections::BTreeMap::new();
            rv.insert("redirect_uri".to_owned(), self.session.uri.to_json());
            rv.insert("scope".to_owned(), self.session.permissions.to_json());
            rv.insert("client_id".to_owned(), self.session.client_id.to_json());
            rv
        })
    }
}

impl OauthRequest {
    pub fn from_http(request: &mut Request) -> Option<Self> {
        // FIXME: validate client_id
        let query = match request.get_ref::<urlencoded::UrlEncodedQuery>().ok() {
            Some(x) => x,
            None => return None
        };

        let mut session = models::Session {
            client_id: query.get("client_id").unwrap()[0].clone(),
            uri: query.get("redirect_uri").unwrap()[0].clone(),
            permissions: collections::HashMap::new()
        };

        for category_permission in query.get("scope").unwrap()[0].clone().split(' ') {
            let parts = category_permission.split(':').collect::<Vec<_>>();
            if parts.len() != 2 { return None; }
            let (category, permission) = (parts[0], parts[1]);
            if category.len() == 0 || permission.len() == 0 { return None; }

            let key = (if category == "*" { "" } else { category }).to_owned();
            if session.permissions.get(&key).is_some() { return None; }

            session.permissions.insert(key, models::CategoryPermissions {
                can_read: permission.contains("r"),
                can_write: permission.contains("w")
            });
        }

        Some(OauthRequest {
            session: session,
            state: query.get("state").map(|x| x[0].clone())
        })
    }
}

fn webfinger_response(request: &mut Request) -> IronResult<Response> {
    let bad_request = Ok(Response::with(status::BadRequest));
    let mut query = collections::BTreeMap::new();
    for (k, v) in request.url.clone().into_generic_url().query_pairs().unwrap().into_iter() {
        query.insert(k, v);
    }
    let userid = match query.get("resource") {
        Some(x) => if x.starts_with("acct:") {
            &x[5..x.find('@').unwrap_or(x.len())]
        } else {
            return bad_request;
        },
        None => return bad_request
    };

    let storage_url = {
        let mut url = request.url.clone();
        url.query = None;
        url.fragment = None;
        url.path = vec!["storage".to_string(), userid.to_string()];
        url.into_generic_url()
    };

    let oauth_url = {
        let mut url = request.url.clone();
        url.query = None;
        url.fragment = None;
        url.path = vec!["oauth".to_string(), userid.to_string(), "".to_string()];
        url.into_generic_url()
    };

    let mut r = Response::with(status::Ok);
    r.headers.set(header::ContentType("application/jrd+json".parse().unwrap()));

    r.set_mut(json::encode(&json::Json::Object({
        let mut d = collections::BTreeMap::new();
        d.insert("links".to_string(), json::Json::Array(vec![
            json::Json::Object({
                let mut d = collections::BTreeMap::new();
                d.insert("href".to_string(), storage_url.serialize().to_json());
                d.insert("rel".to_string(), "http://tools.ietf.org/id/draft-dejong-remotestorage".to_json());
                d.insert("properties".to_string(), json::Json::Object({
                    let mut d = collections::BTreeMap::new();
                    d.insert("http://remotestorage.io/spec/version".to_string(),
                        "draft-dejong-remotestorage-05".to_json());
                    d.insert("http://tools.ietf.org/html/rfc6749#section-4.2".to_string(),
                        oauth_url.serialize().to_json());
                    d.insert("http://tools.ietf.org/html/rfc6750#section-2.3".to_string(),
                        false.to_json());
                    d.insert("http://tools.ietf.org/html/rfc7233".to_string(),
                        false.to_json());
                    d.insert("http://remotestorage.io/spec/web-authoring".to_string(),
                        false.to_json());
                    d
                }));
                d
            }),
            // We need to provide an older webfinger response because remoteStorage.js doesn't
            // support newer ones.
            // https://github.com/remotestorage/remotestorage.js/pull/899
            // https://github.com/silverbucket/webfinger.js/pull/11
            json::Json::Object({
                let mut d = collections::BTreeMap::new();
                d.insert("href".to_string(), storage_url.serialize().to_json());
                d.insert("rel".to_string(), "remotestorage".to_json());
                d.insert("properties".to_string(), json::Json::Object({
                    let mut d = collections::BTreeMap::new();
                    d.insert("http://remotestorage.io/spec/version".to_string(),
                        "draft-dejong-remotestorage-02".to_json());
                    d.insert("http://tools.ietf.org/html/rfc6749#section-4.2".to_string(),
                        oauth_url.serialize().to_json());
                    d.insert("http://tools.ietf.org/html/rfc6750#section-2.3".to_string(),
                        false.to_json());
                    d.insert("http://tools.ietf.org/html/rfc2616#section-14.16".to_string(),
                        false.to_json());
                    d.insert("http://remotestorage.io/spec/web-authoring".to_string(),
                        false.to_json());
                    d
                }));
                d
            })
        ]));
        d
    })).unwrap());
    Ok(r)
}

trait UserNodeResponder where Self: Sized {
    fn respond(self, request: &mut Request) -> IronResult<Response> {
        match request.method {
            Method::Get => self.respond_get(request),
            Method::Put => self.respond_put(request),
            Method::Delete => self.respond_delete(request),
            _ => Ok(Response::with(status::BadRequest))
        }
    }

    fn respond_get(self, request: &Request) -> IronResult<Response>;
    fn respond_put(self, _: &mut Request) -> IronResult<Response> {
        Ok(Response::with(status::BadRequest))
    }
    fn respond_delete(self, _: &Request) -> IronResult<Response> {
        Ok(Response::with(status::BadRequest))
    }
}

impl<'a> UserNodeResponder for models::UserFolder<'a> {
    fn respond_get(self, request: &Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();
        // https://github.com/remotestorage/spec/issues/93
        let shown_etag = etag.unwrap_or("empty".to_string());

        match request.headers.get::<header::IfNoneMatch>() {
            Some(header) => if header.matches_etag(Some(&shown_etag[..])) {
                return Ok(Response::with(status::NotModified));
            },
            None => ()
        };
        let mut r = Response::with(status::Ok);

        r.headers.set(header::ContentType("application/ld+json".parse().unwrap()));
        // FIXME: https://github.com/hyperium/hyper/issues/666
        r.headers.set_raw("Expires", vec!["0".as_bytes().to_owned()]);
        r.headers.set(header::ETag(header::EntityTag::new(false, shown_etag)));

        r.set_mut(json::encode(&json::Json::Object({
            let mut d = collections::BTreeMap::new();
            d.insert("@context".to_string(),
            "http://remotestorage.io/spec/folder-description".to_json());
            d.insert("items".to_string(), json::Json::Object({
                let mut d = collections::BTreeMap::new();
                match self.read_children() {
                    Ok(children) => {
                        for child in children.iter() {
                            match child.json_repr() {
                                Ok(json) => {
                                    d.insert(child.get_basename(), json);
                                },
                                Err(e) => {
                                    println!("Failed to show item {:?}: {:?}", child.get_path(), e);
                                    continue;
                                }
                            };
                        };
                    }
                    Err(_) => ()
                };
                d
            }));
            d
        })).unwrap());
        Ok(r)
    }
}

impl<'a> UserNodeResponder for models::UserFile<'a> {
    fn respond_get(self, request: &Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();

        match request.headers.get::<header::IfNoneMatch>() {
            Some(header) => if header.matches_etag(etag.as_ref().map(Deref::deref)) {
                return Ok(Response::with(status::NotModified));
            },
            None => ()
        };

        let meta = match self.read_meta() {
            Ok(meta) => meta,
            Err(_) => return Ok(Response::with(status::NotFound))
        };

        let mut r = Response::with(status::Ok);

        r.headers.set(header::ContentType(meta.content_type.parse().unwrap()));
        r.headers.set(header::ETag(header::EntityTag::new(false, self.read_etag().unwrap())));
        // FIXME: https://github.com/hyperium/hyper/issues/666
        r.headers.set_raw("Expires", vec!["0".as_bytes().to_owned()]);
        r.set_mut(self.open().unwrap());
        Ok(r)
    }

    fn respond_delete(self, request: &Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();
        
        if !utils::preconditions_ok(&request, etag.as_ref().map(Deref::deref)) {
            return Ok(Response::with(status::PreconditionFailed));
        };

        if etag.is_none() {
            return Ok(Response::with(status::NotFound));
        }

        self.delete().unwrap();
        Ok(Response::with(status::Ok))
    }

    fn respond_put(self, request: &mut Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();

        if !utils::preconditions_ok(&request, etag.as_ref().map(Deref::deref)) {
            return Ok(Response::with(status::PreconditionFailed));
        };

        {
            let content_type = match request.headers.get_raw("content-type") {
                Some(x) if x.len() == 1 => x.to_owned().pop().unwrap(),
                Some(_) => return Ok(Response::with((status::BadRequest, "ONE content type header required."))),
                None => return Ok(Response::with((status::BadRequest, "Missing content type.")))
            };
            let local_file = match self.create() {
                Ok(x) => x,
                Err(_) => return Ok(Response::with(status::Conflict))
            };
            let content_length = match local_file.write(|mut f| {
                io::copy(&mut request.body, &mut f)
            }) {
                Ok(x) => x,
                Err(e) => {
                    match fs::metadata(self.get_fs_path()) {
                        Ok(metadata) => if metadata.is_dir() {
                            return Ok(Response::with(status::Conflict));
                        },
                        Err(_) => ()
                    };

                    itry!(Err(e))
                }
            };
            self.write_meta(models::UserFileMeta {
                content_type: String::from_utf8(content_type).unwrap(),
                content_length: content_length as usize
            }).unwrap()
        }

        let mut r = Response::with(status::Created);
        r.headers.set(header::ETag(header::EntityTag::new(false, self.read_etag().unwrap())));
        Ok(r)
    }
}

impl User for models::User {
    fn get_username(&self) -> &str { &self.userid[..] }
    fn from_username(request: &mut Request, username: &str) -> Option<Self> {
        let config = request.get::<persistent::Read<AppConfig>>().unwrap();
        let data_path = &config.data_path;

        Self::get(data_path, username)
    }
}

