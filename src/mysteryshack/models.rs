use std::path;
use std::io;
use std::io::Read;
use std::io::Write;
use std::fs;
use std::collections;
use std::os::unix::fs::MetadataExt;
use std::error::Error;

use rustc_serialize::json;
use rustc_serialize::json::ToJson;

use itertools::Itertools;

use crypto::bcrypt;
use rand::{Rng, StdRng};

use atomicwrites;
use chrono::*;
use time;
use filetime;
use nix::errno;

use utils;
use utils::ServerError;
use web::oauth::{Session as OauthSession, CategoryPermissions};


pub struct User {
    pub user_path: path::PathBuf,
    pub userid: String
}

impl User {
    fn new_unchecked(basepath: &path::Path, userid: &str) -> User {
        assert!(basepath.is_absolute());
        assert!(utils::is_safe_identifier(userid), "Invalid chars in username.");

        let user_path = basepath.join(userid.to_string() + "/");
        User {
            user_path: user_path,
            userid: userid.to_owned()
        }
    }

    pub fn get(basepath: &path::Path, userid: &str) -> Option<User> {
        let user = User::new_unchecked(basepath, userid);
        match fs::metadata(user.user_info_path()) {
            Ok(ref x) if x.is_file() => Some(user),
            _ => None
        }
    }

    pub fn create(basepath: &path::Path, userid: &str) -> io::Result<User> {
        let user = User::new_unchecked(basepath, userid);
        try!(fs::create_dir_all(user.data_path()));
        try!(fs::create_dir_all(user.meta_path()));
        try!(fs::create_dir_all(user.tmp_path()));
        try!(fs::File::create(user.user_info_path()));
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
    fn sessions_path(&self) -> path::PathBuf { self.user_path.join("sessions/") }
    pub fn data_path(&self) -> path::PathBuf { self.user_path.join("data/") }
    pub fn meta_path(&self) -> path::PathBuf { self.user_path.join("meta/") }
    pub fn tmp_path(&self) -> path::PathBuf { self.user_path.join("tmp/") }

    fn walk_sessions(&self) -> io::Result<Vec<Session>> {
        let mut rv = vec![];
        for entry in try!(fs::read_dir(self.sessions_path())) {
            let entry = try!(entry);
            if try!(entry.metadata()).is_dir() {
                rv.push(
                    Session::get(
                        &self,
                        &entry.file_name().into_string().unwrap()[..]
                    ).unwrap()
                );
            };
        };
        Ok(rv)
    }

    pub fn walk_apps(&self) -> io::Result<Vec<App>> {
        self.walk_sessions()
            .map(|s| s
                .into_iter()
                .group_by(|s| s.read_oauth().unwrap().identifier())
                .map(|(k, s)| App { client_id: k, sessions: s })
                .collect())
    }

    pub fn permissions(&self, path: &str, token: Option<&str>) -> CategoryPermissions {
        let anonymous = CategoryPermissions {
            can_read: path.starts_with("public/") && !path.ends_with("/"),
            can_write: false
        };

        let token = match token { Some(x) => x, None => return anonymous };
        let session = match Session::get(&self, token) { Some(x) => x, None => return anonymous };
        match session.bump_last_used() {
            Ok(_) => (),
            Err(e) => println!("WARNING: Failed to update last-used timestamp: {:?}", e)
        };

        let category = {
            let mut rv = path.splitn(2, '/').nth(0).unwrap();
            if rv == "public" {
                rv = path.splitn(3, '/').nth(1).unwrap();
            }
            rv
        };

        let oauth = session.read_oauth().unwrap();
        oauth.permissions_for_category(category)
            .map(|x| x.clone())
            .unwrap_or(anonymous)
    }
}

pub struct App<'a> {
    pub client_id: String,
    pub sessions: Vec<Session<'a>>,
}

impl<'a> ToJson for App<'a> {
    // for passing to template
    fn to_json(&self) -> json::Json {
        let mut rv = collections::BTreeMap::new();
        rv.insert("client_id".to_owned(), self.client_id.to_json());
        rv.insert("sessions".to_owned(), self.sessions.to_json());
        json::Json::Object(rv)
    }
}

pub struct Session<'a> {
    pub user: &'a User,
    pub token: String
}

impl<'a> Session<'a> {
    fn new_unchecked(user: &'a User, token: String) -> Session<'a> {
        Session {
            user: user,
            token: token
        }
    }

    pub fn get(user: &'a User, token: &str) -> Option<Session<'a>> {
        let rv = Session::new_unchecked(user, token.to_owned());
        rv.read_oauth().map(|_| rv)
    }

    pub fn delete(&self) -> io::Result<()> {
        try!(fs::remove_dir_all(self.path()));
        Ok(())
    }

    pub fn create(user: &'a User, oauth: &OauthSession) -> Result<Session<'a>, ServerError> {
        let mut rng = try!(StdRng::new());
        let rand_iter = rng.gen_ascii_chars();
        let token: String = rand_iter.take(24).collect();
        let rv = Session::new_unchecked(user, token);
        try!(fs::create_dir_all(rv.path()));
        match rv.read_oauth() {
            Some(_) => panic!("Token already issued."),
            None => ()
        };
        try!(rv.write_oauth(oauth));
        Ok(rv)
    }

    fn path(&self) -> path::PathBuf {
        self.user.sessions_path().join(&self.token)
    }

    fn oauth_path(&self) -> path::PathBuf { self.path().join("oauth.json") }
    fn last_used_path(&self) -> path::PathBuf { self.path().join("last_used") }

    pub fn read_oauth(&self) -> Option<OauthSession> {
        match utils::read_json_file(self.oauth_path()) {
            Ok(x) => Some(x),
            Err(e) => { println!("Failed to parse session file: {:?}", e); None }
        }
    }

    pub fn write_oauth(&self, s: &OauthSession) -> Result<(), ServerError> {
        utils::write_json_file(s, self.oauth_path())
    }

    pub fn read_last_used(&self) -> Option<DateTime<UTC>> {
        fs::File::open(self.last_used_path())
            .ok()
            .and_then(|mut f| {
                let mut s = String::new();
                match f.read_to_string(&mut s) {
                    Ok(_) => Some(s),
                    Err(_) => None
                }
            })
            .and_then(|x| UTC.datetime_from_str(&x[..], "%+").ok())
    }

    pub fn write_last_used(&self, d: DateTime<UTC>) -> io::Result<()> {
        let data = d.to_rfc3339().into_bytes();
        let f = atomicwrites::AtomicFile::new(self.last_used_path(), atomicwrites::AllowOverwrite);
        try!(f.write(|f| f.write(&data)));
        Ok(())
    }

    pub fn bump_last_used(&self) -> io::Result<()> {
        self.write_last_used(UTC::now())
    }
}

impl<'a> ToJson for Session<'a> {
    // for passing to template
    fn to_json(&self) -> json::Json {
        match self.read_oauth().unwrap().to_json() {
            json::Json::Object(mut map) => {
                map.insert("token".to_string(), self.token.to_json());
                map.insert("last_used".to_string(),
                    self.read_last_used()
                        .map(|x| format!("{}", x.format("%d. %B %Y %H:%M %Z")))
                        .unwrap_or_else(|| "".to_string())
                        .to_json());
                json::Json::Object(map)
            },
            _ => panic!("Did not expect anything else than Object.")
        }
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
            println!("Touching directory: {:?}", p);
            filetime::set_file_times(p, timestamp, timestamp).map(|_| true)
        }).map(|_| ())
    }

    pub fn delete(self) -> io::Result<()> {
        fn f(p: &path::Path) -> io::Result<bool> {
            println!("Cleaning up directory: {:?}", p);
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
        d.insert("Content-Type".to_string(), meta.content_type.to_json());
        d.insert("Content-Length".to_string(), meta.content_length.to_json());
        d.insert("ETag".to_string(), try!(self.read_etag()).to_json());

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
        d.insert("ETag".to_string(), try!(self.read_etag()).to_json());
        Ok(json::Json::Object(d))
    }
}
