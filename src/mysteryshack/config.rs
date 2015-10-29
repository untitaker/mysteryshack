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
            None => return Err(Error::ParserError(parser.errors).into())
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

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        ParserError(errors: Vec<toml::ParserError>)
    }
}
