use std::path;
use std::process;

use clap::{App, Arg, SubCommand};

use config;
use models;
use web;
use utils;

pub fn main() {
    let matches =
        App::new("mysteryshack")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Markus Unterwaditzer & contributors")
        .about("A remoteStorage server.")
        .args_from_usage("-c --config=[CONFIG] 'Use specified config file, defaults to ./config'")
        .subcommand(SubCommand::with_name("serve")
                    .about("Start server"))
        .subcommand(SubCommand::with_name("user")
                    .about("User management")
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
                    .subcommand_required(true))
        .subcommand_required(true)
        .get_matches();

    let config_path = path::Path::new(matches.value_of("CONFIG").unwrap_or("./config"));

    let config = match config::Config::read_file(config_path) {
        Ok(x) => x,
        Err(e) => {
            println!("Failed to parse config: {}", e);
            process::exit(1);
        }
    };

    if let Some(_) = matches.subcommand_matches("serve") {
        web::run_server(config);
    } else if let Some(user_matches) = matches.subcommand_matches("user") {
        if let Some(user_create_matches) = user_matches.subcommand_matches("create") {
            let username = user_create_matches.value_of("USERNAME").unwrap();

            let password_hash = match models::PasswordHash::from_password(
                utils::double_prompt("Password for new user: ")) {
                Ok(x) => x,
                Err(e) => {
                    println!("Failed to hash password: {}", e);
                    process::exit(1);
                }
            };

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
        } else if let Some(user_delete_matches) = user_matches.subcommand_matches("delete") {
            let username = user_delete_matches.value_of("USERNAME").unwrap();
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
    }
}
