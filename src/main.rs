use anyhow::{bail, Context, Result};
use clap::Parser;
use config::find_config;
use pam::Authenticator;
use std::{os::unix::prelude::CommandExt, process::Command, env, collections::HashMap};
use users::{
    get_current_gid, get_current_uid, get_user_by_uid,
    switch::{set_effective_gid, set_effective_uid}, get_user_by_name, os::unix::UserExt,
};

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

    #[clap(short = 's', name = "execute_shell")]
    execute_shell: bool,

    #[clap(value_parser, required_unless_present("execute_shell"))]
    command: Option<String>,

    #[clap(value_parser)]
    args: Vec<String>,
}

fn main() -> Result<()> {
    // Hardening, we drop our permissions down to what the user can do.
    set_effective_uid(get_current_uid())?;
    set_effective_gid(get_current_gid())?;

    let args = Cli::parse();

    if let Some(path) = args.check_config {
        let config = config::parse_config(&path)?;
        println!("{} rules successfully parsed!", config.len());

        return Ok(());
    }

    let config = match find_config() {
        None => bail!("No config file found!"),
        Some(path) => config::parse_config(&path)?,
    };

    let user = match get_user_by_uid(get_current_uid()) {
        None => bail!("Could not find user with uid {}", get_current_uid()),
        Some(user) => user,
    };

    let groups: Vec<u32> = match user.groups() {
        Some(groups) => groups.iter().map(|g| g.gid()).collect(),
        None => bail!(
            "Could not find groups for user {}",
            user.name().to_str().unwrap()
        ),
    };

    let target = args.execute_as_user.clone();

    let command = match args.command {
        Some(command) => command,
        None => {
            env::var("SHELL").unwrap_or(user.shell().to_str().unwrap().to_string())
        }
    };

    let (action, rules) = config::evaluate_rules(
        config,
        config::AuthorizationRequest {
            uid: user.uid(),
            gids: groups,
            cmd: command.clone(),
            args: args.args.clone(),
            nopass: args.non_interactive,
            target: args.execute_as_user,
        },
    )?;

    if action == config::Action::Deny {
        bail!("Access denied!");
    }

    let last = rules.last().unwrap();

    if !last.options.contains(&config::Options::NoPass) {
        // TODO: not sure what a service is, but I think we need to install one
        let mut auth = Authenticator::with_password("sudo")
            .with_context(|| format!("Failed to start PAM client"))?;

        let password = rpassword::prompt_password("Password: ")
            .with_context(|| format!("Failed to read password"))?;

        auth.get_handler()
            .set_credentials(user.name().to_str().unwrap(), password);

        auth.authenticate()
            .with_context(|| format!("Failed to authenticate with PAM"))?;

        // TODO: no idea what this does
        auth.open_session()
            .with_context(|| format!("Failed to open session with PAM"))?;
    }

    let target = get_user_by_name(&target).unwrap();

    // TODO: handle envs and all of the other goodies (and shell)

    let mut env = HashMap::new();

    env.insert("DOAS_USER".to_owned(), user.name().to_str().unwrap().to_string());
    env.insert("HOME".to_owned(), target.home_dir().to_str().unwrap().to_string());
    env.insert("LOGNAME".to_owned(), target.name().to_str().unwrap().to_string());
    env.insert("PATH".to_owned(), "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin".to_string());
    // TODO: This might be different from the user's shell
    env.insert("SHELL".to_owned(), target.shell().to_str().unwrap().to_string());
    env.insert("USER".to_owned(), target.name().to_str().unwrap().to_string());

    if let Ok(val) = env::var("DISPLAY") {
        env.insert("DISPLAY".to_owned(), val);
    }

    if let Ok(val) = env::var("TERM") {
        env.insert("TERM".to_owned(), val);
    }

    for option in last.options.clone() {
        match option {
            config::Options::SetEnv(envs) => {
                for e in envs {
                    match e {
                        config::EnvVariable::VariableOnly { negate, name } => {
                            if negate {
                                env.remove(&name);
                            } else {
                                if let Ok(val) = env::var(name.clone()) {
                                    env.insert(name, val);
                                }
                            }
                        },
                        config::EnvVariable::VariableSet { name, value, reference } => {
                            if reference {
                                if let Ok(val) = env::var(value) {
                                    env.insert(name, val);
                                }

                                continue;
                            }

                            env.insert(name, value);
                        },
                    }
                }
            },
            _ => {}
        }
    }

    // TODO: SO MANY CLONES
    // TODO: Look into using &str instead of String
    // TODO: syslog

    let output = Command::new(command).uid(target.uid()).envs(&env).args(args.args).exec();
    Err(anyhow::Error::new(output))
}
