use anyhow::Result;
use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use std::{fs, path::Path};

#[derive(Parser)]
#[grammar = "config.pest"]
pub struct ConfigParser;

// TODO: Security vuln, if file does not exit, then rip
pub fn find_config() -> Option<&'static Path> {
    let doas_rust_path = Path::new("/etc/oko.conf");
    let doas_path = Path::new("/etc/doas.conf");
    if doas_rust_path.exists() {
        Some(doas_rust_path)
    } else if doas_path.exists() {
        Some(doas_path)
    } else {
        None
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Action {
    Permit,
    Deny,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EnvVariable {
    VariableOnly {
        negate: bool,
        name: String,
    }, // VariableOnly is an enviroment variable without a value
    VariableSet {
        name: String,
        value: String,
        reference: bool,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Options {
    NoPass,
    NoLog,
    Persist,
    KeepEnv,
    SetEnv(Vec<EnvVariable>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Identity {
    UserName(String),
    UserId(u32),
    GroupName(String),
    GroupId(u32),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfigRule {
    pub action: Action,
    pub options: Vec<Options>,
    pub identity: Identity,
    pub as_user: Option<String>,
    pub cmd: Option<String>,
    pub args: Option<Vec<String>>,
}

fn parse_options(pairs: Pairs<Rule>) -> Vec<Options> {
    pairs
        .into_iter()
        .map(|o| match o.as_rule() {
            Rule::setenv => {
                let variables =
                    o.into_inner()
                        .next()
                        .unwrap()
                        .into_inner()
                        .map(|o| match o.as_rule() {
                            Rule::setenv_variable_only_option => {
                                let mut inner = o.into_inner();

                                let next = inner.next().unwrap();

                                if matches!(next.as_rule(), Rule::setenv_negate) {
                                    EnvVariable::VariableOnly {
                                        negate: true,
                                        name: inner.next().unwrap().as_str().to_string(),
                                    }
                                } else {
                                    EnvVariable::VariableOnly {
                                        negate: false,
                                        name: next.as_str().to_string(),
                                    }
                                }
                            }
                            Rule::setenv_set_variable_option => {
                                let mut inner = o.into_inner();
                                let name = inner.next().unwrap().as_str().to_string();

                                let next = inner.next().unwrap();

                                if matches!(next.as_rule(), Rule::setenv_set_variable_reference) {
                                    EnvVariable::VariableSet {
                                        name,
                                        value: next
                                            .into_inner()
                                            .next()
                                            .unwrap()
                                            .as_str()
                                            .to_string(),
                                        reference: true,
                                    }
                                } else {
                                    EnvVariable::VariableSet {
                                        name,
                                        value: next.as_str().to_string(),
                                        reference: false,
                                    }
                                }
                            }
                            _ => unreachable!(),
                        });

                Options::SetEnv(variables.collect())
            }
            Rule::nopass => Options::NoPass,
            Rule::nolog => Options::NoLog,
            Rule::persist => Options::Persist,
            Rule::keepenv => Options::KeepEnv,
            _ => unreachable!(),
        })
        .collect()
}

fn parse_identity(pair: Pair<Rule>) -> Identity {
    let inner = pair.into_inner().next().unwrap();
    let rule = inner.as_rule();
    let str = inner.into_inner().next().unwrap().as_str();

    match rule {
        Rule::user_iden => Identity::UserName(str.to_string()),
        Rule::user_id => Identity::UserId(str.parse().unwrap()),
        Rule::group_iden => Identity::GroupName(str.to_string()),
        Rule::group_id => Identity::GroupId(str.parse().unwrap()),
        _ => unreachable!(),
    }
}

pub fn parse_config(path: &Path) -> Result<Vec<ConfigRule>, anyhow::Error> {
    let file = fs::read_to_string(path)?;

    let parsed = ConfigParser::parse(Rule::config, &file)?.next().unwrap();
    let pairs = parsed.into_inner();

    let mut rules = Vec::new();

    for pair in pairs {
        if matches!(pair.as_rule(), Rule::rule_line) {
            let mut inner_rules = pair.into_inner();

            let action = inner_rules.next().unwrap().as_str();
            let action = match action {
                "permit" => Action::Permit,
                "deny" => Action::Deny,
                _ => unreachable!(),
            };

            let next = inner_rules.next().unwrap();

            let (options, identity) = if matches!(next.as_rule(), Rule::option_list) {
                (
                    parse_options(next.into_inner()),
                    parse_identity(inner_rules.next().unwrap()),
                )
            } else {
                (vec![], parse_identity(next))
            };

            let mut rule = ConfigRule {
                action,
                options,
                identity,
                as_user: None,
                cmd: None,
                args: None,
            };

            for rest in inner_rules {
                match rest.as_rule() {
                    Rule::as_target => {
                        let as_user = rest.into_inner().next().unwrap().as_str();
                        rule.as_user = Some(as_user.to_string());
                    }
                    Rule::command => {
                        let cmd = rest.into_inner().next().unwrap().as_str();
                        rule.cmd = Some(cmd.to_string());
                    }
                    Rule::args => {
                        let args = rest.into_inner().map(|o| o.as_str().to_string()).collect();
                        rule.args = Some(args);
                    }
                    _ => unreachable!(),
                }
            }

            rules.push(rule);
        }
    }

    Ok(rules)
}

pub struct AuthorizationRequest<'a> {
    pub uid: u32,
    pub gids: &'a Vec<u32>,
    pub cmd: &'a String,
    pub args: &'a Vec<String>,
    pub nopass: bool,
    pub target: &'a String,
}

pub fn evaluate_rules(
    rules: Vec<ConfigRule>,
    request: AuthorizationRequest,
) -> Result<(Action, Vec<ConfigRule>)> {
    let mut matching_rules = Vec::new();

    for rule in rules {
        let matches = match &rule.identity {
            Identity::UserName(name) => {
                let user = users::get_user_by_name(name);

                match user {
                    Some(user) => user.uid() == request.uid,
                    None => false,
                }
            }
            Identity::UserId(id) => *id == request.uid,
            Identity::GroupName(name) => {
                let group = users::get_group_by_name(name);

                match group {
                    Some(group) => request.gids.contains(&group.gid()),
                    None => false,
                }
            }
            Identity::GroupId(id) => request.gids.contains(id),
        };

        if !matches {
            continue;
        }

        if request.nopass && !rule.options.contains(&Options::NoPass) {
            continue;
        }

        if let Some(rule_cmd) = &rule.cmd {
            if rule_cmd != request.cmd {
                continue;
            }
        }

        if let Some(rule_args) = &rule.args {
            if rule_args != request.args {
                continue;
            }
        }

        if let Some(rule_target) = &rule.as_user {
            if rule_target != request.target {
                continue;
            }
        }

        matching_rules.push(rule);
    }

    let last = matching_rules.last();
    match last {
        Some(rule) => Ok((rule.action, matching_rules)),
        None => Ok((Action::Deny, matching_rules)),
    }
}

#[test]
fn test_parse_config() -> Result<(), anyhow::Error> {
    parse_config(Path::new("test-config"))?;
    Ok(())
}
