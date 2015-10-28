use std::collections;

use rustc_serialize::json;
use rustc_serialize::json::ToJson;

use iron::prelude::*;

use urlencoded;

use models;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        ClientError(s: String) {
            description(s)
        }
    }
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone)]
pub struct OauthRequest {
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

fn expect_param(query: &urlencoded::QueryMap, key: &str) -> Result<String, Error> {
    match query.get(key) {
        Some(x) if x.len() == 1 => Ok(x[0].clone()),
        _ => Err(Error::ClientError(format!("Missing query parameter: {:?}", key)))
    }
}


impl OauthRequest {
    pub fn from_http(request: &mut Request) -> Result<Self, Error> {
        // FIXME: validate client_id
        let query = match request.get_ref::<urlencoded::UrlEncodedQuery>().ok() {
            Some(x) => x,
            None => return Err(Error::ClientError("Missing all URL query parameters.".to_string()))
        };

        let mut session = models::Session {
            client_id: try!(expect_param(query, "client_id")),
            uri: try!(expect_param(query, "redirect_uri")),
            permissions: collections::HashMap::new()
        };

        for category_permission in try!(expect_param(query, "scope")).split(' ') {
            let parts = category_permission.split(':').collect::<Vec<_>>();
            let scope_err = Err(Error::ClientError(format!("Invalid scope: {:?}", category_permission)));
            if parts.len() != 2 { return scope_err; }

            let (category, permission) = (parts[0], parts[1]);
            if category.len() == 0 || permission.len() == 0 { return scope_err; }

            let key = (if category == "*" { "" } else { category }).to_owned();
            if session.permissions.get(&key).is_some() { return scope_err; }

            session.permissions.insert(key, models::CategoryPermissions {
                can_read: permission.contains("r"),
                can_write: permission.contains("w")
            });
        }

        Ok(OauthRequest {
            session: session,
            state: query.get("state").map(|x| x[0].clone())
        })
    }
}

