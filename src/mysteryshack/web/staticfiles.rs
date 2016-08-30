// Generated using scripts/make_static.py. Do NOT edit directly!

use router::Router;
use hyper::header;
use iron::prelude::*;
use iron::modifiers::Header;
use iron::status;

pub fn get_static_handler() -> Router {
    let mut r = Router::new();
    r.get("/app.css", (|_: &mut Request|
        Ok(Response::with((
            status::Ok,
            Header(header::ContentType("text/css".parse().unwrap())),
            &include_bytes!("../../static/app.css")[..]
        )))), "app.css"
    );
    r.get("/app.svg", (|_: &mut Request|
        Ok(Response::with((
            status::Ok,
            Header(header::ContentType("image/svg+xml".parse().unwrap())),
            &include_bytes!("../../static/app.svg")[..]
        )))), "app.svg"
    );
    r.get("/logo.svg", (|_: &mut Request|
        Ok(Response::with((
            status::Ok,
            Header(header::ContentType("image/svg+xml".parse().unwrap())),
            &include_bytes!("../../static/logo.svg")[..]
        )))), "logo.svg"
    );
    r.get("/pure-min.css", (|_: &mut Request|
        Ok(Response::with((
            status::Ok,
            Header(header::ContentType("text/css".parse().unwrap())),
            &include_bytes!("../../static/pure-min.css")[..]
        )))), "pure-min.css"
    );
    r
}
