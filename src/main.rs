use anyhow::{bail, Context, Result};
use clap::Parser;
use config::{find_config, Action};
use lazy_static::lazy_static;
use nix::unistd::{setresgid, setresuid, Gid, Uid};
use pam_client::conv_cli::Conversation;
use std::{
    collections::HashMap,
    env,
    os::unix::prelude::CommandExt,
    process::{self, Command},
    time::Duration,
    vec,
};
use syslog::{Facility, Formatter3164};
use users::{
    get_current_gid, get_current_uid, get_user_by_name, get_user_by_uid,
    os::unix::UserExt,
    switch::{set_effective_gid, set_effective_uid},
};

mod config;
mod timestamp;

extern crate pest;
#[macro_use]
extern crate pest_derive;

lazy_static! {
    static ref TIMEOUT: Duration = Duration::new(5 * 60, 0);
}

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None, allow_hyphen_values = true, trailing_var_arg = true)]
struct Cli {
    /// Validates the configuration file, running a permissions check if a command is specified, which returns either 'permit', 'permit nopass', or 'deny'
    #[clap(short = 'C', name = "check_config")]
    check_config: Option<std::path::PathBuf>,

    /// The user to execute the command as
    #[clap(short = 'u', default_value = "root", name = "execute_as")]
    execute_as: String,

    /// Runs non-interactively, fails if the matched rule doesn't set nopass
    #[clap(short = 'n', name = "non_interactive")]
    non_interactive: bool,

    /// Clear past authetentications for this session, to require reauthentication on next invocation
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

    #[clap(value_parser, allow_hyphen_values = true)]
    args: Vec<String>,
}

fn main() -> Result<()> {
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

    let target = get_user_by_name(&args.execute_as)
        .with_context(|| format!("Could not find user {}", &args.execute_as))?;

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
        set_effective_uid(get_current_uid())?;
        set_effective_gid(get_current_gid())?;

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
        process: "oko".into(),
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
    let timestamp = if last.options.contains(&config::Options::Persist) {
        Some(timestamp::open_timestamp_file(*TIMEOUT))
    } else {
        None
    };

    if !last.options.contains(&config::Options::NoPass)
        && !timestamp
            .as_ref()
            .map(|o| o.as_ref().map(|t| t.valid).unwrap_or(false))
            .unwrap_or(false)
    {
        let mut context = pam_client::Context::new(
            "oko",
            Some(user.name().to_str().unwrap()),
            Conversation::new(),
        )?;

        let result = context.authenticate(pam_client::Flag::NONE);

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

        context
            .acct_mgmt(pam_client::Flag::NONE)
            .with_context(|| format!("Account is not valid"))?;

        if context.user()? != user.name().to_str().unwrap() {
            bail!("PAM user does not equal the current user");
        }

        let mut _session = context
            .open_session(pam_client::Flag::NONE)
            .with_context(|| format!("Failed to open session with PAM"))?;
    }

    if let Some(Ok(t)) = timestamp {
        timestamp::set_timestamp_file(&t.file, *TIMEOUT)?;
    }

    let mut env = HashMap::new();

    env.insert(
        "DOAS_USER".to_owned(),
        user.name().to_str().unwrap().to_string(),
    );
    env.insert(
        "OKO_USER".to_owned(),
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
                "OKO_USER",
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

    let gid = Gid::from_raw(target.primary_group_id());
    let uid = Uid::from_raw(target.uid());

    setresgid(gid, gid, gid)?;
    setresuid(uid, uid, uid)?;
    let output = Command::new(command).envs(&env).args(args.args).exec();
    Err(anyhow::Error::new(output))
}
