use anyhow::{bail, Context, Result};
use clap::Parser;
use config::{find_config, Action};
use lazy_static::lazy_static;
use nix::{unistd::{getgid, getuid}};
use pam::Authenticator;
use std::{
    collections::HashMap,
    env,
    os::unix::prelude::CommandExt,
    process::{self, Command}, time::Duration,
};
use syslog::{Facility, Formatter3164};
use users::{
    get_current_gid, get_current_uid, get_user_by_name, get_user_by_uid,
    os::unix::UserExt,
    switch::{set_both_gid, set_both_uid, set_effective_gid, set_effective_uid},
};

mod auth;
mod config;
mod timestamp;

extern crate pest;
#[macro_use]
extern crate pest_derive;

lazy_static! {
  static ref TIMEOUT: Duration = Duration::new(5 * 60, 0);
}

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Validates the configuration file, running a permissions check if a command is specified, which returns either 'permit', 'permit nopass', or 'deny'
    #[clap(short = 'C', name = "check_config", parse(from_os_str))]
    check_config: Option<std::path::PathBuf>,

    /// The user to execute the command as
    #[clap(short = 'u', default_value = "root", name = "execute_as")]
    execute_as: String,

    /// Runs non-interactively, fails if the matched rule doesn't set nopass
    #[clap(short = 'n', name = "non_interactive")]
    non_interactive: bool,

    #[clap(short = 'L', name = "clear_past_authentications")]
    clear_past_authentications: bool,

    /// Executes the current user's shell (from $SHELL or /etc/passwd) instead of a command
    #[clap(short = 's', name = "execute_shell")]
    execute_shell: bool,

    /// The command to execute
    #[clap(
        value_parser,
        required_unless_present("execute_shell"),
        required_unless_present("check_config"),
        required_unless_present("clear_past_authentications"),
        name = "command"
    )]
    command: Option<String>,

    #[clap(value_parser)]
    args: Vec<String>,
}

fn main() -> Result<()> {
    // Hardening, we drop our permissions down to what the user can do.
    set_effective_uid(get_current_uid())?;
    set_effective_gid(get_current_gid())?;

    println!("{}, {}", getuid(), getgid());

    let args = Cli::parse();

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

    let target = get_user_by_name(&args.execute_as).unwrap();

    let command = match args.command {
        Some(command) => Some(command),
        None if args.execute_shell => {
            Some(env::var("SHELL").unwrap_or(user.shell().to_str().unwrap().to_string()))
        }
        None => None,
    };

    if args.clear_past_authentications {
        timestamp::clear_timestamp()?;
        return Ok(());
    }

    if let Some(path) = args.check_config {
        let config = config::parse_config(&path)?;

        if command.is_none() {
            return Ok(());
        }

        let (action, rules) = config::evaluate_rules(
            config,
            config::AuthorizationRequest {
                uid: user.uid(),
                gids: &groups,
                cmd: &command.unwrap(),
                args: &args.args,
                nopass: args.non_interactive,
                target: &args.execute_as,
            },
        )?;

        match action {
            Action::Deny => {
                println!("deny");
            }
            Action::Permit => {
                let last = rules.last().unwrap();

                if last.options.contains(&config::Options::NoPass) {
                    println!("permit nopass")
                } else {
                    println!("permit")
                }
            }
        }

        return Ok(());
    }

    let command = command.unwrap();

    let config = match find_config() {
        None => bail!("No config file found!"),
        Some(path) => config::parse_config(&path)?,
    };

    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "doas-rust".into(),
        pid: process::id(),
    };

    // I can't ? here for some reason
    let mut syslog = syslog::unix(formatter).unwrap();

    let (action, rules) = config::evaluate_rules(
        config,
        config::AuthorizationRequest {
            uid: user.uid(),
            gids: &groups,
            cmd: &command,
            args: &args.args,
            nopass: args.non_interactive,
            target: &args.execute_as,
        },
    )?;

    if action == config::Action::Deny {
        syslog
            .notice(format!(
                "user {} denied access to run \"{} {}\" as {}",
                user.name().to_str().unwrap(),
                command,
                args.args.join(" "),
                target.name().to_str().unwrap()
            ))
            .unwrap();
        bail!("Access denied!");
    }

    let last = rules.last().unwrap();
    let timestamp = timestamp::open_timestamp_file(*TIMEOUT)?;

    if !last.options.contains(&config::Options::NoPass) && !timestamp.valid {
        let doas_authenticator =
            auth::DoasAuthenticator::new(user.name().to_str().unwrap().to_owned());

        let mut auth = Authenticator::with_handler("sudo", doas_authenticator)?;

        let result = auth.authenticate();

        if result.is_err() {
            syslog
                .notice(format!(
                    "user {} failed authentication check to run \"{} {}\" as {}",
                    user.name().to_str().unwrap(),
                    command,
                    args.args.join(" "),
                    target.name().to_str().unwrap()
                ))
                .unwrap();
        }

        result.with_context(|| format!("Failed to authenticate with PAM"))?;

        // TODO: no idea what this does
        auth.open_session()
            .with_context(|| format!("Failed to open session with PAM"))?;
    }

    timestamp::set_timestamp_file(&timestamp.file, *TIMEOUT)?;

    // TODO: We handle everything but the "persist" option

    let mut env = HashMap::new();

    env.insert(
        "DOAS_USER".to_owned(),
        user.name().to_str().unwrap().to_string(),
    );
    env.insert(
        "HOME".to_owned(),
        target.home_dir().to_str().unwrap().to_string(),
    );
    env.insert(
        "LOGNAME".to_owned(),
        target.name().to_str().unwrap().to_string(),
    );
    env.insert(
        "PATH".to_owned(),
        "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin".to_string(),
    );
    env.insert(
        "SHELL".to_owned(),
        target.shell().to_str().unwrap().to_string(),
    );
    env.insert(
        "USER".to_owned(),
        target.name().to_str().unwrap().to_string(),
    );

    if let Ok(val) = env::var("DISPLAY") {
        env.insert("DISPLAY".to_owned(), val);
    }

    if let Ok(val) = env::var("TERM") {
        env.insert("TERM".to_owned(), val);
    }

    if last.options.contains(&config::Options::KeepEnv) {
        for (key, value) in env::vars() {
            if vec![
                "DOAS_USER",
                "HOME",
                "LOGNAME",
                "PATH",
                "SHELL",
                "USER",
                "DISPLAY",
                "TERM",
            ]
            .contains(&key.as_str())
            {
                continue;
            }

            env.insert(key, value);
        }
    };

    if let Some(setenv_values) = last.options.iter().find_map(|o| match o {
        config::Options::SetEnv(envs) => Some(envs),
        _ => None,
    }) {
        for e in setenv_values.clone() {
            match e {
                config::EnvVariable::VariableOnly { negate, name } => {
                    if negate {
                        env.remove(&name);
                    } else {
                        if let Ok(val) = env::var(&name) {
                            env.insert(name, val);
                        }
                    }
                }
                config::EnvVariable::VariableSet {
                    name,
                    value,
                    reference,
                } => {
                    if reference {
                        if let Ok(val) = env::var(value) {
                            env.insert(name, val);
                        }

                        continue;
                    }

                    env.insert(name, value);
                }
            }
        }
    };

    if !last.options.contains(&config::Options::NoLog) {
        syslog
            .notice(format!(
                "user {} granted access to run \"{} {}\" as {}",
                user.name().to_str().unwrap(),
                command,
                args.args.join(" "),
                target.name().to_str().unwrap()
            ))
            .unwrap();
    }

    set_both_uid(target.uid(), target.uid())?;
    set_both_gid(target.primary_group_id(), target.primary_group_id())?;

    let output = Command::new(command).envs(&env).args(args.args).exec();
    Err(anyhow::Error::new(output))
}
