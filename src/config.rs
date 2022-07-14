use anyhow::bail;
use pest::{
    iterators::{FlatPairs, Pair, Pairs},
    Parser,
};
use std::{fs, path::Path};

#[derive(Parser)]
#[grammar = "config.pest"]
pub struct ConfigParser;

pub fn find_config() -> Result<&'static Path, anyhow::Error> {
    let doas_rust_path = Path::new("/etc/doas-rust.conf");
    let doas_path = Path::new("/etc/doas.conf");
    if doas_rust_path.exists() {
        Ok(doas_rust_path)
    } else if doas_path.exists() {
        Ok(doas_path)
    } else {
        bail!("Cannot find config file!")
    }
}
#[derive(Debug)]
pub enum Action {
    Permit,
    Deny,
}

#[derive(Debug)]
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

#[derive(Debug)]
pub enum Options {
    NoPass,
    NoLog,
    Persist,
    KeepEnv,
    SetEnv(Vec<EnvVariable>),
}

#[derive(Debug)]
pub enum Identity {
    UserName(String),
    UserId(i32),
    GroupName(String),
    GroupId(i32),
}

#[derive(Debug)]
pub struct ConfigRule {
    action: Action,
    options: Vec<Options>,
    identity: Identity,
    as_user: Option<String>,
    cmd: Option<String>,
    args: Option<Vec<String>>,
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

#[test]
fn test_parse_config() -> Result<(), anyhow::Error> {
    let config = parse_config(Path::new("test-config"))?;
    println!("{:#?}", config);
    Ok(())
}
