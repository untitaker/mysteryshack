use std::collections;
use std::io;
use std::fs;
use std::ops::Deref;
use std::error::Error;
use std::path::Path;

use hyper::header;

use iron;

use iron::prelude::*;
use iron::modifiers::Redirect;
use iron::status;
use iron::method::Method;
use iron::typemap::Key;


use persistent;
use handlebars_iron::{HandlebarsEngine,Template};
use mount;
use iron_login::{User,LoginManager};
use urlencoded;
use router::Router;
use staticfile;

use url;
use rand::{Rng,StdRng};

use rustc_serialize::json;
use rustc_serialize::json::ToJson;

use models;
use models::UserNode;
use config;
use super::utils::{preconditions_ok,EtagMatcher,SecurityHeaderMiddleware,XForwardedMiddleware,FormDataHelper,get_account_id};
use super::oauth;
use super::oauth::HttpResponder;

static REPO_ROOT: &'static str = env!("CARGO_MANIFEST_DIR");

#[derive(Copy, Clone)]
pub struct AppConfig;
impl Key for AppConfig { type Value = config::Config; }

#[derive(Copy, Clone)]
pub struct AppLock;
impl Key for AppLock { type Value = (); }

macro_rules! itry {
    ($expr:expr) => (itry!($expr, ::iron::status::InternalServerError));

    ($expr:expr, $modifier:expr) => (match $expr {
        ::std::result::Result::Ok(val) => val,
        ::std::result::Result::Err(err) => return Err(::iron::IronError::new(err, $modifier))
    })
}

macro_rules! some_or {
    ($expr:expr, $modifier:expr) => (match $expr {
        Some(x) => x,
        None => return Ok(Response::with($modifier))
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
    ($req:expr) => (some_or!(
        $req.headers.get::<header::Referer>()
            .and_then(|s| url::Url::parse(s).ok())
            .and_then(|u| if u == $req.url.clone().into_generic_url() { Some(()) } else { None }),
        (status::BadRequest, "CSRF detected.")
    ))
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
    router.post("/dashboard/", user_dashboard);
    router.get("/login/", user_login_get);
    router.post("/login/", user_login_post);
    router.get("/oauth/:userid/", oauth_entry);
    router.post("/oauth/:userid/", oauth_entry);

    router.get("/", |_: &mut Request| Ok(Response::with((status::Ok, Template::new("index", "".to_json())))));

    let mut chain = Chain::new(router);
    if config.use_proxy_headers { chain.link_before(XForwardedMiddleware); }
    chain.link(persistent::Read::<AppConfig>::both(config.clone()));
    chain.link(persistent::State::<AppLock>::both(()));
    chain.around(LoginManager::new({
        println!("Generating session keys...");
        let mut rv = [0u8; 24];
        let mut rng = StdRng::new().unwrap();
        rng.fill_bytes(&mut rv);
        rv.to_vec()
    }));


    chain.link_after(HandlebarsEngine::new(
        Path::new(REPO_ROOT).join("src/templates/").to_str().unwrap(),
        ".hbs"
    ));
    chain.link_after(SecurityHeaderMiddleware);
    chain.link_after(ErrorPrinter);

    let mut mount = mount::Mount::new();
    mount.mount("/", chain);
    mount.mount("/static/", staticfile::Static::new(Path::new(REPO_ROOT).join("src/static/")));

    let listen = &config.listen[..];
    println!("Listening on: http://{}", listen);
    Iron::new(mount).http(listen).unwrap();
}

fn user_node_response(req: &mut Request) -> IronResult<Response> {
    let write_operation = match req.method {
        Method::Get | Method::Head => false,
        _ => true
    };

    let lock = req.get::<persistent::State<AppLock>>().unwrap().clone();
    let _guard = if write_operation {
        (None, Some(lock.write().unwrap()))
    } else {
        (Some(lock.read().unwrap()), None)
    };

    let config = req.get::<persistent::Read<AppConfig>>().unwrap();
    let data_path = &config.data_path;

    let (userid, path_str) = {
        let parts = req.extensions.get::<Router>().unwrap();
        let userid = parts.find("userid").unwrap().to_owned();
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

    let permissions = user.permissions(&path_str[..], access_token.as_ref().map(Deref::deref));

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
            &some_or!(formdata.get("user"), status::BadRequest)[0].clone(),
            &some_or!(formdata.get("pass"), status::BadRequest)[0].clone()
        )
    };

    let bad_creds = Ok(Response::with((status::Ok, "Wrong credentials.")));

    let user = match models::User::get(data_path, &username[..]) {
        Some(user) => if itry!((&user).get_password_hash()).equals_password(password) {
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

    match request.method {
        Method::Get => Ok(Response::with(status::Ok)
                          .set(Template::new("dashboard", {
                              let mut rv = collections::BTreeMap::new();
                              rv.insert("account_id".to_owned(), get_account_id(&user, &request).to_json());
                              let sessions = user.walk_sessions().unwrap_or_else(|_| vec![]);
                              rv.insert("sessions".to_owned(), sessions.to_json());
                              rv
                          }))),
        Method::Post => {
            check_csrf!(request);
            let back_to = request.url.clone();
            let (action, token) = some_or!(
                request.get_ref::<urlencoded::UrlEncodedBody>().ok()
                    .map(|query| (query.get_only("action").clone(), query.get_only("token").clone())),
                status::BadRequest);

            match (action.map(Deref::deref), token) {
                (Some("delete_token"), Some(token)) => {
                    let session = some_or!(models::Session::get(&user, token), status::NotFound);
                    itry!(session.delete());
                    Ok(Response::with((status::Found, Redirect(back_to))))
                },
                _ => Ok(Response::with(status::BadRequest))
            }
        },
        _ => Ok(Response::with(status::BadRequest))
    }
}

fn oauth_entry(request: &mut Request) -> IronResult<Response> {
    let oauth_userid = {
        let parts = request.extensions.get::<Router>().unwrap();
        parts.find("userid").unwrap().to_owned()
    };
    let user = require_login_as!(request, &oauth_userid[..]);
    let oauth_request = match oauth::OauthRequest::from_http(request) {
        Ok(x) => x,
        Err(e) => return Ok(
            e.get_response().unwrap_or_else(|| {
                Response::with(status::BadRequest)
                .set(Template::new("oauth_error", json::Json::Object({
                    let mut rv = collections::BTreeMap::new();
                    rv.insert("e_msg".to_owned(), e.description().to_json());
                    rv
                })))
            })
        )
    };

    match request.method {
        Method::Get => Ok(Response::with(status::Ok).set(Template::new("oauth_entry", oauth_request.to_json()))),
        Method::Post => {
            check_csrf!(request);
            let allow = some_or!({
                let formdata = itry!(request.get_ref::<urlencoded::UrlEncodedBody>());
                match &some_or!(formdata.get("decision"), status::BadRequest)[0][..] {
                    "allow" => Some(true),
                    "deny" => Some(false),
                    _ => None
                }
            }, status::BadRequest);

            if allow {
                let session = itry!(models::Session::create(&user, &oauth_request.session));
                Ok(oauth_request.grant(session.token).get_response().unwrap())
            } else {
                Ok(oauth_request.reject().get_response().unwrap())
            }
        },
        _ => Ok(Response::with(status::BadRequest))
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
        r.headers.set(header::ETag(header::EntityTag::new(false, itry!(self.read_etag()))));
        // FIXME: https://github.com/hyperium/hyper/issues/666
        r.headers.set_raw("Expires", vec!["0".as_bytes().to_owned()]);
        r.set_mut(itry!(self.open()));
        Ok(r)
    }

    fn respond_delete(self, request: &Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();
        
        if !preconditions_ok(&request, etag.as_ref().map(Deref::deref)) {
            return Ok(Response::with(status::PreconditionFailed));
        };

        if etag.is_none() {
            return Ok(Response::with(status::NotFound));
        }

        itry!(self.delete());
        Ok(Response::with(status::Ok))
    }

    fn respond_put(self, request: &mut Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();

        if !preconditions_ok(&request, etag.as_ref().map(Deref::deref)) {
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
            itry!(self.write_meta(models::UserFileMeta {
                content_type: String::from_utf8(content_type).unwrap(),
                content_length: content_length as usize
            }));
        }

        let mut r = Response::with(status::Created);
        r.headers.set(header::ETag(header::EntityTag::new(false, itry!(self.read_etag()))));
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

