use std::path;
use std::io;
use std::io::Read;
use std::fs;
use std::collections;
use std::os::unix::fs::MetadataExt;
use std::error::Error;

use std::collections::hash_map::Entry;

use rustc_serialize::json;
use rustc_serialize::json::ToJson;

use crypto::bcrypt;
use rand::{Rng, StdRng};

use atomicwrites;

use utils;
use utils::ServerError;
use web::oauth::{Session, CategoryPermissions};


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
    fn session_file_path(&self) -> path::PathBuf { self.user_path.join("sessions.json") }
    pub fn data_path(&self) -> path::PathBuf { self.user_path.join("data/") }
    pub fn meta_path(&self) -> path::PathBuf { self.user_path.join("meta/") }
    pub fn tmp_path(&self) -> path::PathBuf { self.user_path.join("tmp/") }
}

type SessionMap = collections::HashMap<String, Session>;


pub trait SessionManager {
    fn read_sessions(&self) -> Result<SessionMap, ServerError>;
    fn write_sessions(&self, map: &SessionMap) -> Result<(), ServerError>;

    fn get_permissions(&self, token_opt: Option<&str>, path: &str) -> CategoryPermissions {
        let anonymous = CategoryPermissions {
            can_read: path.starts_with("public/") && !path.ends_with("/"),
            can_write: false
        };

        let token = match token_opt { Some(x) => x, None => return anonymous };
        let session = match self.get_session(token) { Some(x) => x, None => return anonymous };

        let category = path.splitn(2, '/').nth(0).unwrap();
        match session.permissions_for_category(category) {
            Some(x) => x.clone(),
            None => {
                if category == "public" {
                    let subcategory = path.splitn(3, '/').nth(1).unwrap();
                    match session.permissions_for_category(subcategory) {
                        Some(x) => x.clone(),
                        None => anonymous
                    }
                } else {
                    anonymous
                }
            }
        }
    }

    fn get_session(&self, token: &str) -> Option<Session> {
        match self.read_sessions() {
            Ok(mut x) => x.remove(token),
            Err(e) => {
                println!("Failed to parse session file: {:?}", e);
                None
            }
        }
    }

    fn create_session(&self, session: &Session) -> Result<String, ServerError> {
        let mut sessions = self.read_sessions().unwrap_or_else(|_| collections::HashMap::new());
        let mut rng = try!(StdRng::new());
        let rand_iter = rng.gen_ascii_chars();
        let token: String = rand_iter.take(24).collect();
        match sessions.entry(token.clone()) {
            Entry::Vacant(x) => x.insert(session.clone()),
            _ => panic!("Access token already given.")
        };

        try!(self.write_sessions(&sessions));
        Ok(token)
    }
}

impl SessionManager for User {
    fn read_sessions(&self) -> Result<SessionMap, ServerError> {
        utils::read_json_file(self.session_file_path())
    }

    fn write_sessions(&self, map: &SessionMap) -> Result<(), ServerError> {
        utils::write_json_file(map, self.session_file_path())
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
        utils::write_json_file(meta, &self.meta_path)
    }

    pub fn delete(self) -> io::Result<()> {
        try!(fs::remove_file(&self.data_path));
        try!(fs::remove_file(&self.meta_path));

        for dir in [&self.data_path, &self.meta_path].iter() {
            let mut cur_dir = dir.as_path();

            loop {
                cur_dir = match cur_dir.parent() {
                    Some(x) => x,
                    None => break
                };
                if !self.user.user_path.starts_with(cur_dir) {
                    break;
                }
                println!("Cleaning up directory: {:?}", cur_dir);
                match fs::remove_dir(cur_dir) {
                    Err(e) => {
                        println!("Failed to remove directory during cleanup: {:?}", e);
                        break;
                    },
                    _ => ()
                }
            }
        }

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
