use std::collections;
use std::io;
use std::fs;
use std::ops::Deref;
use std::error::Error;

use hyper::header;

use iron;

use iron::prelude::*;
use iron::modifiers::{Header,Redirect};
use iron::status;
use iron::method::Method;
use iron::typemap::Key;


use persistent;
use handlebars_iron::Template;
use mount;
use iron_login::{User,LoginManager};
use urlencoded;
use router::Router;
use iron_error_router as error_router;

use url;
use rand;
use rand::Rng;
use webicon;

use rustc_serialize::json;
use rustc_serialize::json::ToJson;

use models;
use models::UserNode;
use config;
use super::utils::{preconditions_ok,EtagMatcher,SecurityHeaderMiddleware,XForwardedMiddleware,FormDataHelper,get_account_id};
use super::oauth;
use super::oauth::HttpResponder;
use super::templates::get_template_engine;
use super::staticfiles::get_static_handler;

#[derive(Copy, Clone)]
pub struct AppConfig;
impl Key for AppConfig { type Value = config::Config; }

#[derive(Copy, Clone)]
pub struct AppLock;
impl Key for AppLock { type Value = (); }

macro_rules! require_login_as {
    ($req:expr, $expect_user:expr) => ({
        let login_redirect = Ok(Response::with((status::Found, Redirect({
            let mut url = $req.url.clone();
            url.path = vec!["dashboard".to_owned(), "login".to_owned(), "".to_owned()];
            url.fragment = None;
            let mut url = url.into_generic_url();
            let redirect_to = $req.url.clone().into_generic_url().serialize();
            let mut query = vec![("redirect_to", &redirect_to[..])];
            if $expect_user.len() > 0 { query.push(("prefill_user", $expect_user)); }
            url.set_query_from_pairs(query.into_iter());
            iron::Url::from_generic_url(url).unwrap()
        }))));

        match models::User::get_login($req).get_user() {
            Some(x) => if $expect_user.len() == 0 || &x.userid[..] == $expect_user { x }
                       else { return login_redirect },
            _ => return login_redirect
        }
    })
}

macro_rules! require_login { ($req:expr) => (require_login_as!($req, "")) }

macro_rules! check_csrf {
    ($req:expr) => ({
        let req = &$req;

        iexpect!(
            req.headers.get::<header::Referer>()
                .and_then(|s| url::Url::parse(s).ok())
                .and_then(|referer_u| {
                    let req_u = req.url.clone().into_generic_url();

                    if referer_u.origin() == req_u.origin() { Some(()) }
                    else { None }
                }),
            (status::BadRequest, "CSRF detected.")
        )
    })
}

macro_rules! alert_tmpl {
    ($msg:expr, $back_to:expr) => ({
        Template::new("alert", json!{
            "msg" => $msg,
            "back_to" => $back_to
        })
    })
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

    for route in &["/storage/:userid/*path", "/storage/:userid/"] {
        for method in [Method::Get, Method::Put, Method::Delete].into_iter() {
            router.route(method.clone(), route, user_node_response);
        }
    }

    router.get("/.well-known/webfinger", webfinger_response);
    router.get("/dashboard/icon", icon_proxy);
    router.get("/dashboard/", user_dashboard);
    router.post("/dashboard/delete-app", user_dashboard_delete_app);
    router.post("/dashboard/change-password", user_dashboard_change_password);
    router.get("/dashboard/login/", user_login);
    router.post("/dashboard/login/", user_login);
    router.post("/dashboard/logout/", user_logout);
    router.get("/dashboard/oauth/:userid/", oauth_entry);
    router.post("/dashboard/oauth/:userid/", oauth_entry);

    router.get("/", |_: &mut Request| Ok(Response::with((status::Ok, Template::new("index", "".to_json())))));

    let mut mount = mount::Mount::new();
    mount.mount("/", router);
    mount.mount("/static/", get_static_handler());

    let mut chain = Chain::new(mount);
    if config.use_proxy_headers { chain.link_before(XForwardedMiddleware); }
    chain.link(persistent::Read::<AppConfig>::both(config.clone()));
    chain.link(persistent::State::<AppLock>::both(()));
    chain.around({
        let mut rv = LoginManager::new({
            println!("Generating session keys...");
            let mut rng = rand::OsRng::new().unwrap();
            rng.gen_iter::<u8>().take(64).collect()
        });
        rv.config.cookie_base.path = Some("/dashboard/".to_owned());
        rv
    });


    let mut error_router = error_router::ErrorRouter::new();
    error_router.modifier_for_status(status::NotFound, (
        status::NotFound,
        alert_tmpl!("Error 404, content not found.", "/"),
    ));
    error_router.modifier_for_status(status::InternalServerError, (
        status::InternalServerError,
        alert_tmpl!("Error 500, internal server error.", "/"),
    ));

    chain.link_after(error_router);
    chain.link_after(get_template_engine());
    chain.link_after(SecurityHeaderMiddleware);
    chain.link_after(ErrorPrinter);

    let listen = &config.listen[..];
    println!("Listening on: http://{}", listen);
    Iron::new(chain).http(listen).unwrap();
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

    let lock = req.get::<persistent::State<AppLock>>().unwrap().clone();
    let _guard = if write_operation {
        (None, Some(lock.write().unwrap()))
    } else {
        (Some(lock.read().unwrap()), None)
    };

    if path_str.is_empty() || path_str.ends_with('/') {
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

fn user_login(request: &mut Request) -> IronResult<Response> {
    let url = request.get_ref::<urlencoded::UrlEncodedQuery>().ok()
        .and_then(|query| query.get("redirect_to"))
        .and_then(|params| params.get(0))
        .and_then(|x| iron::Url::parse(x).ok())
        .unwrap_or_else(|| {
            let mut rv = request.url.clone();
            rv.path = vec!["dashboard".to_owned(), "".to_owned()];
            rv.query = None;
            rv.fragment = None;
            rv
        });

    match request.method {
        Method::Get => {
            if models::User::get_login(request).get_user().is_some() {
                Ok(Response::with((status::Found, Redirect(url))))
            } else {
                user_login_get(request)
            }
        },
        Method::Post => user_login_post(request, url),
        _ => Ok(Response::with(status::BadRequest))
    }
}

fn user_login_get(request: &mut Request) -> IronResult<Response> {
    let mut r = Response::with(status::Ok);
    r.headers.set(header::ContentType("text/html".parse().unwrap()));
    r.set_mut(Template::new("login", {
        let mut rv = collections::BTreeMap::new();
        request.get_ref::<urlencoded::UrlEncodedQuery>().ok()
            .and_then(|query| query.get("prefill_user"))
            .and_then(|params| params.get(0))
            .and_then(|x| rv.insert("prefill_user".to_owned(), x.to_json()));
        rv
    }));
    Ok(r)
}

fn user_login_post(request: &mut Request, url: iron::Url) -> IronResult<Response> {
    check_csrf!(request);
    let config = request.get::<persistent::Read<AppConfig>>().unwrap();
    let data_path = &config.data_path;

    let (ref username, ref password) = {
        let formdata = itry!(request.get_ref::<urlencoded::UrlEncodedBody>());
        (
            &iexpect!(formdata.get("user"))[0].clone(),
            &iexpect!(formdata.get("pass"))[0].clone()
        )
    };

    let user = iexpect!(
        models::User::get(data_path, &username[..])
            .and_then(|user| user.get_password_hash().ok()
                      .and_then(|h| if h.equals_password(password) { Some(user) } else { None })),
        (status::Ok, "Wrong credentials.")
    );


    if &url.scheme != &request.url.scheme || &url.host != &request.url.host || &url.port != &request.url.port {
        return Ok(Response::with(status::BadRequest));
    }

    Ok(Response::with(status::Ok)
       .set(models::User::get_login(request).log_in(user))
       .set(status::Found)
       .set(Redirect(url)))
}

fn user_logout(request: &mut Request) -> IronResult<Response> {
    check_csrf!(request);
    Ok(Response::with(status::Found)
       .set(models::User::get_login(request).log_out())
       .set(Redirect({
           let mut rv = request.url.clone();
           rv.path = vec!["".to_owned()];
           rv.query = None;
           rv.fragment = None;
           rv
       })))
}

fn user_dashboard(request: &mut Request) -> IronResult<Response> {
    let user = require_login!(request);

    let apps = user.walk_apps().unwrap_or_else(|_| vec![]);
    Ok(Response::with((
        status::Ok,
        Template::new("dashboard", json!{
            "account_id" => get_account_id(&user, &request).to_json(),
            "apps" => apps
        })
    )))
}

fn user_dashboard_delete_app(request: &mut Request) -> IronResult<Response> {
    let user = require_login!(request);
    check_csrf!(request);

    let client_id = iexpect!(request.get_ref::<urlencoded::UrlEncodedBody>().ok()
                             .and_then(|q| q.get_only("client_id"))).clone();
    let app = iexpect!(models::App::get(&user, &client_id), status::NotFound);
    itry!(app.delete());
    Ok(Response::with((
        status::Found,
        Redirect({
            let mut u = request.url.clone();
            u.path = vec!["dashboard".to_owned(), "".to_owned()];
            u
        })
    )))
}

fn user_dashboard_change_password(request: &mut Request) -> IronResult<Response> {
    static BACK_TO: &'static str = "/dashboard/#change-password";

    let user = require_login!(request);
    check_csrf!(request);
    
    let (current_pass, new_pass1, new_pass2, regen_key) = {
        let formdata = iexpect!(request.get_ref::<urlencoded::UrlEncodedBody>().ok());
        (
            iexpect!(formdata.get_only("current_pass")).clone(),
            iexpect!(formdata.get_only("new_pass1")).clone(),
            iexpect!(formdata.get_only("new_pass2")).clone(),
            formdata.get_only("regen_key").cloned()
        )
    };

    if new_pass1 != new_pass2 {
        return Ok(Response::with((
            status::Ok,
            alert_tmpl!("Typo in new password: Repeated new password doesn't match new password.
                         Do you have a typo somewhere?", BACK_TO)
        )));
    }

    if !itry!(user.get_password_hash()).equals_password(current_pass) {
        return Ok(Response::with((
            status::Ok,
            alert_tmpl!("Wrong current password.", BACK_TO)
        )));
    }

    let new_hash = models::PasswordHash::from_password(new_pass1);
    itry!(user.set_password_hash(new_hash));

    if let Some(x) = regen_key {
        assert_eq!(x, "yes");
        itry!(user.new_key());
    }

    Ok(Response::with((
        status::Ok,
        alert_tmpl!("Password successfully changed.", BACK_TO)
    )))
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
                .set(Template::new("oauth_error", json!(
                    "e_msg" => (e.description())
                )))
            })
        )
    };

    match request.method {
        Method::Get => Ok(Response::with(status::Ok).set(Template::new("oauth_entry", oauth_request.to_json()))),
        Method::Post => {
            check_csrf!(request);
            let allow = iexpect!({
                let formdata = itry!(request.get_ref::<urlencoded::UrlEncodedBody>());
                match &iexpect!(formdata.get("decision"))[0][..] {
                    "allow" => Some(true),
                    "deny" => Some(false),
                    _ => None
                }
            });

            if allow {
                let (_, session) = itry!(models::Token::create(
                    &user,
                    oauth_request.session.clone().unwrap()
                ));
                Ok(oauth_request.grant(session.token(&user)).get_response().unwrap())
            } else {
                Ok(oauth_request.reject().get_response().unwrap())
            }
        },
        _ => Ok(Response::with(status::BadRequest))
    }
}


fn webfinger_response(request: &mut Request) -> IronResult<Response> {
    let query = request.url
        .clone()
        .into_generic_url()
        .query_pairs()
        .unwrap()
        .into_iter()
        .collect::<collections::BTreeMap<_, _>>();

    let userid = iexpect!(
        query.get("resource")
        .and_then(|x| if x.starts_with("acct:") {
            Some(&x[5..x.find('@').unwrap_or(x.len())])
        } else {
            None
        })
    );

    let storage_url = {
        let mut url = request.url.clone();
        url.query = None;
        url.fragment = None;
        url.path = vec!["storage".to_owned(), userid.to_owned()];
        url.into_generic_url()
    };

    let oauth_url = {
        let mut url = request.url.clone();
        url.query = None;
        url.fragment = None;
        url.path = vec!["dashboard".to_owned(), "oauth".to_owned(), userid.to_owned(), "".to_owned()];
        url.into_generic_url()
    };

    let mut r = Response::with(status::Ok);
    r.headers.set(header::ContentType("application/jrd+json".parse().unwrap()));

    r.set_mut(json::encode(&json!{
        "links" => (&json::Json::Array({
            let mut rv = vec![];
            // We need to provide an older webfinger response because remoteStorage.js doesn't
            // support newer ones.
            // https://github.com/remotestorage/remotestorage.js/pull/899
            // https://github.com/silverbucket/webfinger.js/pull/11
            for &(rel, version) in &[
                ("http://tools.ietf.org/id/draft-dejong-remotestorage", "draft-dejong-remotestorage-05"),
                ("remotestorage", "draft-dejong-remotestorage-02")
            ] {
                rv.push(json!{
                    "href" => storage_url.serialize(),
                    "rel" => rel,
                    "properties" => json!{
                        // Spec version
                        "http://remotestorage.io/spec/version" => version,

                        // OAuth as in draft-06
                        "http://tools.ietf.org/html/rfc6749#section-4.2" => oauth_url.serialize(),

                        // No support for providing the access token via URL query param as in
                        // draft-06
                        "http://tools.ietf.org/html/rfc6750#section-2.3" => (),

                        // No Content-Range as in draft-02
                        "http://tools.ietf.org/html/rfc2616#section-14.16" => (),

                        // No Content-Range as in draft-06
                        "http://tools.ietf.org/html/rfc7233" => (),

                        // No web authoring as in draft-06
                        "http://remotestorage.io/spec/web-authoring" => ()
                    }
                });
            }
            rv
        }))
    }).unwrap());
    Ok(r)
}

trait UserNodeResponder where Self: Sized {
    fn respond(self, request: &mut Request) -> IronResult<Response> {
        match request.method {
            Method::Get => self.respond_get(request),
            Method::Put => {
                if request.headers.get::<header::ContentRange>().is_some() {
                    Ok(Response::with((
                        status::BadRequest,
                        "Content-Range is invalid on PUT, as per RFC 7231. See https://github.com/remotestorage/spec/issues/124"
                    )))
                } else {
                    self.respond_put(request)
                }
            },
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
        let shown_etag = etag.unwrap_or("empty".to_owned());

        if let Some(header) = request.headers.get::<header::IfNoneMatch>() {
            if header.matches_etag(Some(&shown_etag[..])) {
                return Ok(Response::with(status::NotModified));
            }
        };
        let mut r = Response::with(status::Ok);

        r.headers.set(header::ContentType("application/ld+json".parse().unwrap()));
        r.headers.set(header::CacheControl(vec![header::CacheDirective::NoCache]));
        r.headers.set(header::AcceptRanges(vec![header::RangeUnit::None]));
        r.headers.set(header::ETag(header::EntityTag::new(false, shown_etag)));

        r.set_mut(json::encode(&json!{
            "@context" => "http://remotestorage.io/spec/folder-description",
            "items" => json::Json::Object({
                let mut d = collections::BTreeMap::new();
                if let Ok(children) = self.read_children() {
                    for child in &children {
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
                };
                d
            })
        }).unwrap());
        Ok(r)
    }
}

impl<'a> UserNodeResponder for models::UserFile<'a> {
    fn respond_get(self, request: &Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();

        if let Some(header) = request.headers.get::<header::IfNoneMatch>() {
            if header.matches_etag(etag.as_ref().map(Deref::deref)) {
                return Ok(Response::with(status::NotModified));
            }
        };

        let meta = match self.read_meta() {
            Ok(meta) => meta,
            Err(_) => return Ok(Response::with(status::NotFound))
        };

        let mut r = Response::with(status::Ok);

        r.headers.set(header::ContentType(meta.content_type.parse().unwrap()));
        r.headers.set(header::ETag(header::EntityTag::new(false, itry!(self.read_etag()))));
        r.headers.set(header::CacheControl(vec![header::CacheDirective::NoCache]));
        r.headers.set(header::AcceptRanges(vec![header::RangeUnit::None]));
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
            let content_type = match request.headers.get::<header::ContentType>() {
                Some(x) => format!("{}", x),
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
                    if let Ok(metadata) = fs::metadata(self.get_fs_path()) {
                        if metadata.is_dir() {
                            return Ok(Response::with(status::Conflict))
                        }
                    };

                    itry!(Err(e))
                }
            };
            itry!(self.write_meta(models::UserFileMeta {
                content_type: content_type,
                content_length: content_length
            }));
        }

        Ok(Response::with((
            status::Created,
            Header(header::ETag(header::EntityTag::new(false, itry!(self.read_etag()))))
        )))
    }
}

impl User for models::User {
    fn get_user_id(&self) -> String { self.userid.to_owned() }
    fn from_user_id(request: &mut Request, user_id: &str) -> Option<Self> {
        let config = request.get::<persistent::Read<AppConfig>>().unwrap();
        let data_path = &config.data_path;

        Self::get(data_path, user_id)
    }
}

fn icon_proxy(request: &mut Request) -> IronResult<Response> {
    require_login!(request);
    let url = iexpect!(request.get_ref::<urlencoded::UrlEncodedQuery>().ok()
        .and_then(|query| query.get("url"))
        .and_then(|params| params.get(0))
        .and_then(|x| url::Url::parse(x).ok())
        .and_then(|url| url.join("/").ok()));

    let mut parser = webicon::IconScraper::from_http(url);
    let mut icon = iexpect!(
        parser.fetch_icons().at_least(128, 128),
        (
            status::Ok,
            Header(header::ContentType("image/svg+xml".parse().unwrap())),
            &include_bytes!("../../static/app.svg")[..],
        )
    );
    itry!(icon.fetch());
    Ok(Response::with((status::Ok, icon.mime_type.unwrap(), icon.raw.unwrap())))
}
