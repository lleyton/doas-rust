use anyhow::{bail, Context};
use pam::Authenticator;
use std::{os::unix::prelude::CommandExt, process::Command};
use users::{get_current_username, group_access_list};

mod config;

extern crate pest;
#[macro_use]
extern crate pest_derive;

fn main() -> Result<(), anyhow::Error> {
    let group = group_access_list().unwrap();

    let list = group
        .iter()
        .map(|u| u.name().to_str().unwrap())
        .collect::<Vec<&str>>();

    let is_admin = list.contains(&"admin");

    if is_admin {
        let mut auth = Authenticator::with_password("system_auth")
            .with_context(|| format!("Failed to start PAM client"))?;

        let username = get_current_username().unwrap();
        let username_str = username.to_str().unwrap();

        auth.get_handler().set_credentials(username_str, "password");

        auth.authenticate()
            .with_context(|| format!("Failed to authenticate with PAM"))?;
        auth.open_session()
            .with_context(|| format!("Failed to open session with PAM"))?;

        let output = Command::new("whoami").uid(0).exec();
        println!("{}", output);

        Ok(())
    } else {
        bail!("You must be an admin to run doas!")
    }
}
