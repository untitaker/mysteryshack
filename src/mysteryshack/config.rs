use std::env;
use std::fs;
use std::io::Read;
use std::path;

use toml;

use utils::ServerError;

macro_rules! pop_value {
    ($t:expr, $k:expr, $ty:path, $ty_repr:expr) => (
         try!(match $t.remove($k) {
             Some($ty(x)) => Ok(x),
             Some(_) => Err(Error::ValueError(format!("The {} parameter must be {:?}", $k, $ty_repr))),
             None => Err(Error::ValueError(format!("The {} parameter is missing", $k)))
         })
    )
}

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

        let mut main_section = pop_value!(sections, "main", toml::Value::Table, "a section");
        let listen = pop_value!(main_section, "listen", toml::Value::String, "a string");
        let data_path = path.parent().unwrap().join(pop_value!(main_section, "data_path", toml::Value::String, "a string"));
        let use_proxy_headers = pop_value!(main_section, "use_proxy_headers", toml::Value::Boolean, "a boolean");

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
        ParserError(errors: Vec<toml::ParserError>) {
            display("Multiple errors while parsing configuration: {:?}", errors)
            from()
        }
        ValueError(msg: String) {
            display("{}", msg)
        }
    }
}
