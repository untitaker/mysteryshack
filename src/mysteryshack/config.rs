use std::error::Error;
use std::fmt;
use std::env;
use std::fs;
use std::io::Read;
use std::path;


use toml;

use utils::ServerError;


#[derive(Clone)]
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

        let mut parser = toml::Parser::new(&s);
        let mut sections = match parser.parse() {
            Some(x) => x,
            None => return Err(ConfigError::new(format!("{:?}", parser.errors)).into())
        };

        let mut main_section = match sections.remove("main") {
            Some(toml::Value::Table(x)) => x,
            _ => panic!("Config file is missing `main` section.")
        };

        let listen = match main_section.remove("listen") {
            Some(toml::Value::String(x)) => x,
            _ => panic!("The `listen` parameter is missing.")
        };
        
        let data_path = match main_section.remove("data_path") {
            Some(toml::Value::String(x)) => path.parent().unwrap().join(&x),
            _ => panic!("The `data_path` parameter is missing.")
        };

        let use_proxy_headers = match main_section.remove("use_proxy_headers") {
            Some(toml::Value::Boolean(x)) => x,
            _ => panic!("The `use_proxy_headers` parameter must be a boolean.")
        };

        Ok(Config {
            listen: listen,
            data_path: data_path,
            use_proxy_headers: use_proxy_headers
        })
    }
}

#[derive(Debug)]
pub struct ConfigError {
    pub msg: String
}

impl ConfigError {
    pub fn new(msg: String) -> Self {
        ConfigError { msg: msg }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(f)
    }
}

impl Error for ConfigError {
    fn description(&self) -> &str { &self.msg[..] }
    fn cause(&self) -> Option<&Error> { None }
}


impl From<toml::ParserError> for ServerError {
    fn from(e: toml::ParserError) -> ServerError {
        ServerError { error: Box::new(e) }
    }
}


impl From<ConfigError> for ServerError {
    fn from(e: ConfigError) -> ServerError {
        ServerError { error: Box::new(e) }
    }
}

