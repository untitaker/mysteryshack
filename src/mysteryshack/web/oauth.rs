use std::collections;

use rustc_serialize::json;
use rustc_serialize::json::ToJson;

use iron::prelude::*;

use urlencoded;

use models;


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

