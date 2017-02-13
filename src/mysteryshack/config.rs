use std::env;
use std::fs;
use std::io::Read;
use std::path;

use toml;

use utils::ServerError;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub listen: String,
    pub data_path: path::PathBuf,
    pub use_proxy_headers: bool
}

impl Config {
    pub fn read_file(path: &path::Path) -> Result<Self, ServerError> {
        let path = &env::current_dir().unwrap().join(path);
        let mut s = String::new();
        let mut f = try!(fs::File::open(path));
        try!(f.read_to_string(&mut s));
        Ok(try!(toml::from_str(&s)))
    }
}
