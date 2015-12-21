use std::path;
use std::io;
use std::io::Read;
use std::io::Write;
use std::fs;
use std::collections;
use std::os::unix::fs::MetadataExt;

use chrono;

use rustc_serialize::json;
use rustc_serialize::json::ToJson;

use jsonwebtoken as jwt;
use uuid;

use itertools::Itertools;
use regex;

use crypto::bcrypt;
use rand::{Rng, StdRng};

use atomicwrites;
use time;
use filetime;
use nix::errno;

use url;
use utils;
use utils::ServerError;
use web::oauth::{permissions_for_category, PermissionsMap, Session as OauthSession, CategoryPermissions};

pub fn is_safe_identifier(string: &str) -> bool {
    regex::Regex::new(r"^[A-Za-z0-9_-]+$").unwrap().is_match(string)
}

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        InvalidUserName {
            description("Invalid chars in username. Allowed are numbers (0-9), letters (a-zA-Z), \
                        `_` and `-`.")
        }
    }
}

pub struct User {
    pub user_path: path::PathBuf,
    pub userid: String
}

impl User {
    fn new_unchecked(basepath: &path::Path, userid: &str) -> Result<User, Error> {
        assert!(basepath.is_absolute());
        if !is_safe_identifier(userid) {
            Err(Error::InvalidUserName)
        } else {
            Ok(User {
                user_path: basepath.join(userid.to_owned()),
                userid: userid.to_owned()
            })
        }
    }

    pub fn get(basepath: &path::Path, userid: &str) -> Option<User> {
        User::new_unchecked(basepath, userid)
            .ok()
            .and_then(|user| match fs::metadata(user.user_info_path()) {
                Ok(ref x) if x.is_file() => Some(user),
                _ => None
            })
    }

    pub fn create(basepath: &path::Path, userid: &str) -> Result<User, ServerError> {
        let user = try!(User::new_unchecked(basepath, userid));
        try!(fs::create_dir_all(user.data_path()));
        try!(fs::create_dir_all(user.meta_path()));
        try!(fs::create_dir_all(user.tmp_path()));
        try!(fs::create_dir_all(user.apps_path()));
        try!(fs::File::create(user.user_info_path()));
        try!(user.new_key());
        Ok(user)
    }

    pub fn delete(self) -> io::Result<()> {
        try!(fs::remove_dir_all(self.user_path));
        Ok(())
    }

    pub fn get_password_hash(&self) -> Result<PasswordHash, ServerError> {
        utils::read_json_file(self.password_path())
    }

    pub fn set_password_hash(&self, hash: PasswordHash) -> Result<(), ServerError> {
        utils::write_json_file(hash, self.password_path())
    }

    fn user_info_path(&self) -> path::PathBuf { self.user_path.join("user.json") }
    fn password_path(&self) -> path::PathBuf { self.user_path.join("password") }
    pub fn data_path(&self) -> path::PathBuf { self.user_path.join("data/") }
    pub fn meta_path(&self) -> path::PathBuf { self.user_path.join("meta/") }
    pub fn tmp_path(&self) -> path::PathBuf { self.user_path.join("tmp/") }
    pub fn apps_path(&self) -> path::PathBuf { self.user_path.join("apps/") }

    pub fn key_path(&self) -> path::PathBuf { self.user_path.join("user.key") }

    pub fn walk_apps(&self) -> io::Result<Vec<App>> {
        let mut rv = vec![];
        for entry in try!(fs::read_dir(self.apps_path())) {
            let entry = try!(entry);
            if try!(entry.metadata()).is_dir() {
                rv.push(
                    App::get(
                        &self,
                        &entry.file_name().into_string().unwrap()[..]
                    ).unwrap()
                );
            };
        };
        Ok(rv)
    }

    pub fn permissions(&self, path: &str, token: Option<&str>) -> CategoryPermissions {
        let anonymous = CategoryPermissions {
            can_read: path.starts_with("public/") && !path.ends_with("/"),
            can_write: false
        };

        let token = match token { Some(x) => x, None => return anonymous };
        let (_, session) = match Token::get(&self, token) { Some(x) => x, None => return anonymous };

        let category = {
            let mut rv = path.splitn(2, '/').nth(0).unwrap();
            if rv == "public" {
                rv = path.splitn(3, '/').nth(1).unwrap();
            }
            rv
        };

        permissions_for_category(&session.permissions, category)
            .map_or(anonymous, |x| x.clone())
    }

    pub fn get_key(&self) -> Vec<u8> {
        let mut f = fs::File::open(self.key_path()).unwrap();
        let mut s = vec![];
        f.read_to_end(&mut s).unwrap();
        s
    }

    pub fn new_key(&self) -> io::Result<()> {
        let mut key = [0u8; 4096];
        {
            let mut rng = try!(StdRng::new());
            rng.fill_bytes(&mut key);
        };

        let f = atomicwrites::AtomicFile::new(self.key_path(), atomicwrites::AllowOverwrite);
        try!(f.write(|f| f.write(&key)));
        Ok(())
    }
}

pub struct App<'a> {
    pub client_id: String,
    pub app_id: String,
    pub user: &'a User
}

impl<'a> ToJson for App<'a> {
    // for passing to template
    fn to_json(&self) -> json::Json {
        let mut rv = collections::BTreeMap::new();
        rv.insert("client_id".to_owned(), self.client_id.to_json());
        rv.insert("app_id".to_owned(), self.app_id.to_json());
        json::Json::Object(rv)
    }
}

impl<'a> App<'a> {
    fn get_path(u: &User, client_id: &str) -> path::PathBuf {
        u.apps_path().join(client_id.replace("/", ""))
    }

    fn normalize_client_id(client_id: &str) -> String {
        let u = url::Url::parse(client_id).unwrap();
        utils::format_origin(&u)
    }

    pub fn get(u: &'a User, client_id: &str) -> Option<App<'a>> {
        let p = App::get_path(u, client_id).join("app_id");
        let mut f = match fs::File::open(p) { Ok(x) => x, Err(_) => return None };

        let app_id = {
            let mut rv = String::new();
            match f.read_to_string(&mut rv) {
                Ok(_) => (),
                Err(_) => return None
            };
            rv
        };

        Some(App {
            user: u,
            client_id: App::normalize_client_id(client_id),
            app_id: app_id
        })
    }

    pub fn delete(&self) -> io::Result<()> {
        fs::remove_dir_all(App::get_path(&self.user, &self.client_id))
    }

    pub fn create(u: &'a User, client_id: &str) -> Result<App<'a>, io::Error> {
        let app_id = uuid::Uuid::new_v4().to_simple_string();

        let p = App::get_path(u, client_id);
        try!(fs::create_dir_all(&p));

        let f = atomicwrites::AtomicFile::new(
            p.join("app_id"),
            atomicwrites::DisallowOverwrite
        );

        let app_id_bytes = app_id.to_owned().into_bytes();
        try!(f.write(|f| f.write(&app_id_bytes)));

        Ok(App {
            user: u,
            client_id: client_id.to_owned(),
            app_id: app_id.to_owned()
        })
    }
}

#[derive(RustcEncodable, RustcDecodable, Debug)]
pub struct Token {
    pub exp: i64,
    pub app_id: String,
    pub client_id: String,
    pub permissions: PermissionsMap
}

const SESSION_HASH_ALGORITHM: jwt::Algorithm = jwt::Algorithm::HS256;

impl Token {
    pub fn get<'a>(u: &'a User, token: &str) -> Option<(App<'a>, Self)> {
        let key = u.get_key();

        let session = match jwt::decode::<Token>(&token, &key, SESSION_HASH_ALGORITHM) {
            Ok(x) => x,
            Err(_) => return None
        };

        let now = chrono::UTC::now().timestamp();

        if session.exp < now {
            return None;
        }

        let app = match App::get(u, &session.client_id[..]) {
            Some(app) => {
                if app.app_id == session.app_id { app }
                else { return None }
            },
            _ => return None
        };

        Some((app, session))
    }

    pub fn create<'a>(u: &'a User, sess: OauthSession) -> Result<(App<'a>, Self), ServerError> {
        let app = match App::get(u, &sess.client_id) {
            Some(x) => x,
            None => try!(App::create(u, &sess.client_id))
        };

        let app_id_cp = app.app_id.clone();

        Ok((app, Token {
            app_id: app_id_cp,
            client_id: sess.client_id,
            permissions: sess.permissions,
            exp: (chrono::UTC::now() + chrono::Duration::days(30)).timestamp()
        }))
    }

    pub fn token(&self, u: &User) -> String {
        let key = u.get_key();
        jwt::encode(self, &key, SESSION_HASH_ALGORITHM).unwrap()
    }
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
pub struct PasswordHash {
    cost: u32,
    salt: Vec<u8>,
    hash: Vec<u8>
}

impl PasswordHash {
    pub fn from_password(pwd: String) -> io::Result<PasswordHash> {
        const DEFAULT_COST: u32 = 10;
        const MAX_SALT_SIZE: usize = 16;
        const OUTPUT_SIZE: usize = 24;

        let salt = {
            let mut rv = [0u8; MAX_SALT_SIZE];
            let mut rng = try!(StdRng::new());
            rng.fill_bytes(&mut rv);
            rv
        };

        let mut hash = [0u8; OUTPUT_SIZE];
        bcrypt::bcrypt(DEFAULT_COST, &salt, pwd.as_bytes(), &mut hash);
        Ok(PasswordHash {
            cost: DEFAULT_COST,
            salt: salt.to_vec(),
            hash: hash.to_vec()
        })
    }

    pub fn equals_password<T: AsRef<str>>(&self, pwd: T) -> bool {
        let mut hash = Vec::with_capacity(self.hash.len());
        for _ in 0..self.hash.len() { hash.push(0u8); }

        bcrypt::bcrypt(self.cost, &self.salt, pwd.as_ref().as_bytes(), &mut hash);
        hash == self.hash
    }
}



pub trait UserNode<'a> {
    fn from_path(user: &'a User, path: &str) -> Option<Self> where Self: Sized;
    
    // Get frontent-facing path relative to root
    fn get_path(&self) -> &str;
    fn get_basename(&self) -> String;
    fn get_user(&self) -> &User;

    // Get absolute path on filesystem
    fn get_fs_path(&self) -> &path::Path;

    // Get json repr for folder listing
    fn json_repr(&self) -> Result<json::Json, ServerError>;

    // Get etag
    fn read_etag(&self) -> Result<String, ServerError> {
        let metadata = match fs::metadata(&self.get_fs_path()) {
            Ok(x) => x,
            Err(e) => return Err(e.into())
        };

        Ok(format!("{}", metadata.mtime_nsec()))
    }
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct UserFileMeta {
    pub content_type: String,
    pub content_length: usize
}

pub struct UserFile<'a> {
    pub user: &'a User,
    pub path: String,
    data_path: path::PathBuf,
    meta_path: path::PathBuf
}

impl<'a> UserFile<'a> { 
    pub fn read_meta(&self) -> Result<UserFileMeta, ServerError> {
        let mut meta_f = try!(fs::File::open(&self.meta_path));
        let meta_str = {
            let mut rv = String::new();
            try!(meta_f.read_to_string(&mut rv));
            rv
        };

        let rv = try!(json::decode(&meta_str));
        Ok(rv)
    }

    pub fn open(&self) -> io::Result<fs::File> {
        fs::File::open(&self.data_path)
    }

    pub fn create(&self) -> io::Result<atomicwrites::AtomicFile> {
        try!(fs::create_dir_all(self.data_path.parent().unwrap()));
        try!(fs::create_dir_all(self.meta_path.parent().unwrap()));

        Ok(atomicwrites::AtomicFile::new_with_tmpdir(
            &self.data_path,
            atomicwrites::AllowOverwrite,
            &self.user.tmp_path()
        ))
    }

    pub fn write_meta(&self, meta: UserFileMeta) -> Result<(), ServerError> {
        try!(utils::write_json_file(meta, &self.meta_path));
        match self.touch_parents() {
            Ok(_) => (),
            Err(e) => println!("Failed to touch parent directories: {:?}", e)
        };
        Ok(())
    }

    fn touch_parents(&self) -> io::Result<()> {
        let timestamp = {
            // Stolen from https://github.com/uutils/coreutils/blob/master/src/touch/touch.rs
            let t = time::now().to_timespec();
            filetime::FileTime::from_seconds_since_1970(
                t.sec as u64,
                t.nsec as u32
            )
        };

        utils::map_parent_dirs(&self.data_path, self.user.data_path(), |p| {
            filetime::set_file_times(p, timestamp, timestamp).map(|_| true)
        }).map(|_| ())
    }

    pub fn delete(self) -> io::Result<()> {
        fn f(p: &path::Path) -> io::Result<bool> {
            match fs::remove_dir(p) {
                Err(e) => {
                    if let Some(errno) = e.raw_os_error() {
                        if errno::Errno::from_i32(errno) == errno::Errno::ENOTEMPTY {
                            return Ok(false);
                        }
                    }
                    println!("Failed to remove directory during cleanup: {:?}", e);
                    Err(e)
                },
                Ok(_) => Ok(true)
            }
        }

        try!(fs::remove_file(&self.data_path));
        try!(fs::remove_file(&self.meta_path));
        try!(utils::map_parent_dirs(&self.data_path, self.user.data_path(), f));
        try!(utils::map_parent_dirs(&self.meta_path, self.user.meta_path(), f));
        Ok(())
    }
}

impl<'a> UserNode<'a> for UserFile<'a> {
    fn from_path(user: &'a User, path: &str) -> Option<UserFile<'a>> {
        if path.ends_with("/") { return None; };

        let data_path = match utils::safe_join(user.data_path(), path) {
            Some(x) => x,
            None => return None
        };
        let meta_path = match utils::safe_join(user.meta_path(), path) {
            Some(x) => x,
            None => return None
        };

        Some(UserFile {
            path: path.to_owned(),
            data_path: data_path,
            meta_path: meta_path,
            user: user,
        })
    }
    fn get_user(&self) -> &User { self.user }
    
    fn get_path(&self) -> &str { &self.path }
    fn get_basename(&self) -> String {
        self.path.rsplitn(2, '/').nth(0).unwrap().to_owned()
    }
    fn get_fs_path(&self) -> &path::Path { self.data_path.as_path() }
    
    fn json_repr(&self) -> Result<json::Json, ServerError> {
        let meta = try!(self.read_meta());
        let mut d = collections::BTreeMap::new();
        d.insert("Content-Type".to_owned(), meta.content_type.to_json());
        d.insert("Content-Length".to_owned(), meta.content_length.to_json());
        d.insert("ETag".to_owned(), try!(self.read_etag()).to_json());

        Ok(json::Json::Object(d))
    }
}

pub struct UserFolder<'a> {
    pub user: &'a User,
    data_path: path::PathBuf,
    path: String
}

impl<'a> UserFolder<'a> {
    pub fn read_children<'b>(&'b self) -> Result<Vec<Box<UserNode + 'b>>, ServerError> {
        let mut rv: Vec<Box<UserNode>> = vec![];
        for entry in try!(fs::read_dir(&self.data_path)) {
            let entry = try!(entry);
            let path = entry.path();
            let meta = try!(fs::metadata(&path));
            let fname_string = entry.file_name();
            let fname_str = fname_string.to_str().unwrap();

            if meta.is_dir() {
                rv.push(Box::new(UserFolder::from_path(
                    &self.user,
                    &(self.path.clone() + fname_str + "/")
                ).unwrap()));
            } else if !fname_str.starts_with(".~") {
                rv.push(Box::new(UserFile::from_path(
                    &self.user,
                    &(self.path.clone() + fname_str)
                ).unwrap()));
            }
        }
        Ok(rv)
    }
}

impl<'a> UserNode<'a> for UserFolder<'a> {
    fn from_path(user: &'a User, path: &str) -> Option<UserFolder<'a>> {
        Some(UserFolder {
            path: if path.ends_with("/") || path.len() == 0 {
                path.to_owned()
            } else {
                return None
            },
            data_path: match utils::safe_join(user.data_path(), path) {
                Some(x) => x,
                None => return None
            },
            user: user
        })
    }

    fn get_path(&self) -> &str { &self.path }
    fn get_user(&self) -> &User { self.user }
    fn get_basename(&self) -> String {
        self.path.rsplitn(3, '/').nth(1).unwrap().to_owned() + "/"
    }

    fn get_fs_path(&self) -> &path::Path { self.data_path.as_path() }

    fn json_repr(&self) -> Result<json::Json, ServerError> {
        let mut d = collections::BTreeMap::new();
        d.insert("ETag".to_owned(), try!(self.read_etag()).to_json());
        Ok(json::Json::Object(d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use web::oauth::Session as OauthSession;
    use web::oauth::CategoryPermissions;
    use tempdir::TempDir;
    use std::collections;

    fn get_tmp() -> TempDir {
        TempDir::new("mysteryshack").unwrap()
    }

    #[test]
    fn test_sessions() {
        let t = get_tmp();
        let u = User::create(t.path(), "foo").unwrap();

        assert!(Token::get(&u, "aint a jwt").is_none());
        let (app, session) = Token::create(&u, OauthSession {
            client_id: "http://example.com".to_owned(),
            permissions: {
                let mut rv = collections::HashMap::new();
                rv.insert("".to_owned(), CategoryPermissions {
                    can_read: true,
                    can_write: true
                });
                rv
            }
        }).unwrap();
        assert!(Token::get(&u, &session.token(&u)).is_some());

        app.delete().unwrap();
        assert!(Token::get(&u, &session.token(&u)).is_none());
    }
}
