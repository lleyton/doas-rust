use anyhow::{bail, Context};
use clap::Parser;
use pam::Authenticator;
use std::{os::unix::prelude::CommandExt, process::Command};
use users::{get_current_username, group_access_list};

mod config;

extern crate pest;
#[macro_use]
extern crate pest_derive;

#[derive(clap::Parser)]
struct Cli {
    #[clap(short = 'C')]
    #[clap(parse(from_os_str))]
    check_config: Option<std::path::PathBuf>,

    #[clap(short = 'u', default_value = "root")]
    execute_as_user: String,

    #[clap(short = 'n')]
    non_interactive: bool,

    #[clap(short = 'L')]
    clear_past_authentications: bool,

    #[clap(short = 's')]
    execute_shell: bool,

    #[clap(value_parser)]
    command: Option<String>,
    
    #[clap(value_parser)]
    args: Vec<String>
}

fn main() -> Result<(), anyhow::Error> {
    // let group = group_access_list().unwrap();

    // let list = group
    //     .iter()
    //     .map(|u| u.name().to_str().unwrap())
    //     .collect::<Vec<&str>>();

    // let is_admin = list.contains(&"admin");

    // if is_admin {
    //     let mut auth = Authenticator::with_password("system_auth")
    //         .with_context(|| format!("Failed to start PAM client"))?;

    //     let username = get_current_username().unwrap();
    //     let username_str = username.to_str().unwrap();

    //     let password = rpassword::prompt_password("Password: ").with_context(|| {
    //         format!("Failed to read password")
    //     })?;

    //     auth.get_handler().set_credentials(username_str, password);

    //     auth.authenticate()
    //         .with_context(|| format!("Failed to authenticate with PAM"))?;
    //     auth.open_session()
    //         .with_context(|| format!("Failed to open session with PAM"))?;

    //     let output = Command::new("whoami").uid(0).exec();
    //     println!("{}", output);

    //     Ok(())
    // } else {
    //     bail!("You must be an admin to run doas!")
    // }

    let args = Cli::parse();

    Ok(())
}
