use std::path;
use std::process;

use clap::{App, Arg, SubCommand, AppSettings};

use config;
use models;
use web;
use utils;

macro_rules! clap_dispatch {
    (
        $matches:expr;
        // FIXME: $matches_name absolutely requires a trailing comma, couldn't get it to work under
        // stable rust:
        //
        // foo(_) => ()   // Errors
        // foo(_,) => ()  // Works
        {
            $( $name:ident ($matches_name:pat, $($arg_name:ident as $varname:ident),*) => $callback:expr ),*
        }
    ) => {
        match $matches.subcommand_name() {
            $(
                Some(stringify!($name)) => {
                    let matches = $matches.subcommand_matches(stringify!($name)).unwrap();
                    $(
                        let $varname = matches.value_of(stringify!($arg_name)).unwrap();
                    )*
                    let $matches_name = matches;
                    $callback;
                }
            )*
            Some(x) => {
                panic!("Internal error: Command not covered: {}", x);
            },
            None => {
                println!("Subcommand required. See --help for help.");
                process::exit(1);
            }
        }
    }
}

pub fn main() {
    let matches =
        App::new("mysteryshack")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Markus Unterwaditzer & contributors")
        .about("A remoteStorage server.")
        .args_from_usage("-c, --config=[FILE] 'Use specified config file, defaults to ./config'")
        .setting(AppSettings::SubcommandRequired)
        .subcommand(SubCommand::with_name("serve")
                    .about("Start server"))
        .subcommand(SubCommand::with_name("user")
                    .about("User management")
                    .setting(AppSettings::SubcommandRequired)
                    .subcommand(SubCommand::with_name("create")
                                .about("Create a new user")
                                .arg(Arg::with_name("USERNAME")
                                     .help("The username")
                                     .required(true)
                                     .index(1)))
                    .subcommand(SubCommand::with_name("delete")
                                .about("Delete a user")
                                .arg(Arg::with_name("USERNAME")
                                     .help("The username")
                                     .required(true)
                                     .index(1)))
                    .subcommand(SubCommand::with_name("setpass")
                                .about("Change the password for a user")
                                .arg(Arg::with_name("USERNAME")
                                     .help("The username")
                                     .required(true)
                                     .index(1))))
        .get_matches();

    let config_path = path::Path::new(matches.value_of("config").unwrap_or("./config"));

    let config = match config::Config::read_file(config_path) {
        Ok(x) => x,
        Err(e) => {
            println!("Failed to parse config: {}", e);
            process::exit(1);
        }
    };

    clap_dispatch!(matches; {
        serve(_,) => web::run_server(config),
        user(user_matches,) => clap_dispatch!(user_matches; {
            create(_, USERNAME as username) => {
                let password_hash = models::PasswordHash::from_password(utils::double_prompt("Password for new user: "));

                match models::User::create(&config.data_path, username).map(|user| {
                    user.set_password_hash(password_hash)
                }) {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Failed to create user {}: {}", username, e);
                        process::exit(1);
                    }
                };

                println!("Successfully created user {}", username);
            },
            setpass(_, USERNAME as username) => {
                let user = match models::User::get(&config.data_path, username) {
                    Some(x) => x,
                    None => {
                        println!("User does not exist: {}", username);
                        process::exit(1);
                    }
                };

                let password_hash = models::PasswordHash::from_password(utils::double_prompt("New password: "));
                match user.set_password_hash(password_hash) {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Failed to set password for user {}: {}", username, e);
                        process::exit(1);
                    }
                };

                println!("Changed password for user {}", username);
            },
            delete(_, USERNAME as username) => {
                let user = match models::User::get(&config.data_path, username) {
                    Some(x) => x,
                    None => {
                        println!("User does not exist: {}", username);
                        process::exit(1);
                    }
                };

                println!("You are about to delete the user {} and ALL the user's user data. This
                         process is irreversible.", username);
                if !utils::prompt_confirm(format!("Do you want to delete the user {}?", username), false) {
                    println!("Aborted!");
                    process::exit(1);
                }

                match user.delete() {
                    Ok(_) => println!("Successfully deleted user {}.", username),
                    Err(e) => {
                        println!("Failed to delete user: {:?}", e);
                        process::exit(1);
                    }
                };
            }
        })
    });
}
