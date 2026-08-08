#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Keep,
    Discard,
    FileInto(String),
    Redirect(String),
    Reject(String),
    Vacation(String),
    Notify(String),
    EditHeader { name: String, value: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Test {
    True,
    False,
    Header { name: String, value: String },
    Address { name: String, value: String },
    Envelope { name: String, value: String },
    Exists(String),
    SizeOver(u64),
    AllOf(Vec<Test>),
    AnyOf(Vec<Test>),
    Not(Box<Test>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Require(String),
    If {
        test: Test,
        then: Vec<Command>,
        otherwise: Vec<Command>,
    },
    Action(Action),
    Set {
        name: String,
        value: String,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Message {
    pub headers: Vec<(String, String)>,
    pub envelope_from: String,
    pub envelope_to: String,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    pub instructions: u32,
    pub max_instructions: u32,
    pub depth: u16,
    pub max_depth: u16,
    pub redirects: u16,
    pub max_redirects: u16,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            instructions: 0,
            max_instructions: 10_000,
            depth: 0,
            max_depth: 32,
            redirects: 0,
            max_redirects: 10,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Outcome {
    pub actions: Vec<Action>,
    pub variables: Vec<(String, String)>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SieveError {
    #[error("syntax error at byte {0}")]
    Syntax(usize),
    #[error("unsupported Sieve capability: {0}")]
    Unsupported(String),
    #[error("Sieve execution limit exceeded")]
    Limit,
    #[error("redirect limit exceeded")]
    RedirectLimit,
}

pub fn parse(script: &str) -> Result<Vec<Command>, SieveError> {
    let mut p = Parser {
        input: script,
        pos: 0,
    };
    let result = p.commands(false)?;
    p.ws();
    if p.pos != p.input.len() {
        return Err(SieveError::Syntax(p.pos));
    }
    Ok(result)
}

pub fn execute(
    commands: &[Command],
    message: &Message,
    limits: &mut Limits,
) -> Result<Outcome, SieveError> {
    let mut outcome = Outcome::default();
    let mut vars = Vec::new();
    run(commands, message, limits, &mut vars, &mut outcome)?;
    outcome.variables = vars;
    Ok(outcome)
}

fn run(
    commands: &[Command],
    message: &Message,
    limits: &mut Limits,
    vars: &mut Vec<(String, String)>,
    out: &mut Outcome,
) -> Result<(), SieveError> {
    limits.depth = limits.depth.checked_add(1).ok_or(SieveError::Limit)?;
    if limits.depth > limits.max_depth {
        return Err(SieveError::Limit);
    }
    for command in commands {
        limits.instructions = limits
            .instructions
            .checked_add(1)
            .ok_or(SieveError::Limit)?;
        if limits.instructions > limits.max_instructions {
            return Err(SieveError::Limit);
        }
        match command {
            Command::Require(cap) if !SUPPORTED.contains(&cap.as_str()) => {
                return Err(SieveError::Unsupported(cap.clone()));
            }
            Command::Require(_) => {}
            Command::Action(action) => {
                if let Action::Redirect(_) = action {
                    limits.redirects = limits
                        .redirects
                        .checked_add(1)
                        .ok_or(SieveError::RedirectLimit)?;
                    if limits.redirects > limits.max_redirects {
                        return Err(SieveError::RedirectLimit);
                    }
                }
                out.actions.push(action.clone());
            }
            Command::Set { name, value } => vars.push((name.clone(), value.clone())),
            Command::If {
                test,
                then,
                otherwise,
            } => {
                let branch = if matches_test(test, message) {
                    then
                } else {
                    otherwise
                };
                run(branch, message, limits, vars, out)?;
            }
        }
    }
    limits.depth -= 1;
    Ok(())
}

fn matches_test(test: &Test, message: &Message) -> bool {
    match test {
        Test::True => true,
        Test::False => false,
        Test::Header { name, value } | Test::Address { name, value } => message
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case(name) && v.contains(value)),
        Test::Envelope { name, value } => match name.to_ascii_lowercase().as_str() {
            "from" => message.envelope_from.contains(value),
            "to" => message.envelope_to.contains(value),
            _ => false,
        },
        Test::Exists(name) => message
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(name)),
        Test::SizeOver(limit) => message.size > *limit,
        Test::AllOf(values) => values.iter().all(|v| matches_test(v, message)),
        Test::AnyOf(values) => values.iter().any(|v| matches_test(v, message)),
        Test::Not(value) => !matches_test(value, message),
    }
}

const SUPPORTED: &[&str] = &[
    "fileinto",
    "redirect",
    "reject",
    "variables",
    "envelope",
    "body",
    "relational",
    "regex",
    "include",
    "duplicate",
    "notify",
    "editheader",
    "vacation",
    "environment",
    "spamtest",
    "virustest",
    "ihave",
];

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}
impl Parser<'_> {
    fn ws(&mut self) {
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }
    fn word(&mut self) -> Result<String, SieveError> {
        self.ws();
        let start = self.pos;
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_alphanumeric()
        {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(SieveError::Syntax(self.pos));
        }
        Ok(self.input[start..self.pos].to_ascii_lowercase())
    }
    fn string(&mut self) -> Result<String, SieveError> {
        self.ws();
        if self.input.as_bytes().get(self.pos) != Some(&b'"') {
            return Err(SieveError::Syntax(self.pos));
        }
        self.pos += 1;
        let start = self.pos;
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'"' {
            self.pos += 1;
        }
        if self.pos == self.input.len() {
            return Err(SieveError::Syntax(self.pos));
        }
        let value = self.input[start..self.pos].to_owned();
        self.pos += 1;
        Ok(value)
    }
    fn punct(&mut self, c: u8) -> Result<(), SieveError> {
        self.ws();
        if self.input.as_bytes().get(self.pos) == Some(&c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(SieveError::Syntax(self.pos))
        }
    }
    fn commands(&mut self, until_brace: bool) -> Result<Vec<Command>, SieveError> {
        let mut result = Vec::new();
        loop {
            self.ws();
            if until_brace && self.input.as_bytes().get(self.pos) == Some(&b'}') {
                self.pos += 1;
                break;
            }
            if self.pos == self.input.len() {
                if until_brace {
                    return Err(SieveError::Syntax(self.pos));
                }
                break;
            }
            let word = self.word()?;
            let command = match word.as_str() {
                "require" => {
                    let cap = self.string()?;
                    self.punct(b';')?;
                    Command::Require(cap)
                }
                "keep" | "discard" | "reject" | "redirect" | "fileinto" | "vacation" | "notify"
                | "addheader" => {
                    let action = match word.as_str() {
                        "keep" => Action::Keep,
                        "discard" => Action::Discard,
                        "reject" => Action::Reject(self.string()?),
                        "redirect" => Action::Redirect(self.string()?),
                        "fileinto" => Action::FileInto(self.string()?),
                        "vacation" => Action::Vacation(self.string()?),
                        "notify" => Action::Notify(self.string()?),
                        _ => Action::EditHeader {
                            name: self.string()?,
                            value: self.string()?,
                        },
                    };
                    self.punct(b';')?;
                    Command::Action(action)
                }
                "set" => {
                    let name = self.string()?;
                    let value = self.string()?;
                    self.punct(b';')?;
                    Command::Set { name, value }
                }
                "if" => {
                    let test = self.test()?;
                    self.punct(b'{')?;
                    let then = self.commands(true)?;
                    self.ws();
                    let otherwise = if self.input[self.pos..].starts_with("else") {
                        self.pos += 4;
                        self.punct(b'{')?;
                        self.commands(true)?
                    } else {
                        Vec::new()
                    };
                    Command::If {
                        test,
                        then,
                        otherwise,
                    }
                }
                _ => return Err(SieveError::Unsupported(word)),
            };
            result.push(command);
        }
        Ok(result)
    }
    fn test(&mut self) -> Result<Test, SieveError> {
        let word = self.word()?;
        match word.as_str() {
            "true" => Ok(Test::True),
            "false" => Ok(Test::False),
            "not" => Ok(Test::Not(Box::new(self.test()?))),
            "exists" => Ok(Test::Exists(self.string()?)),
            "size" => {
                let op = self.word()?;
                let value = self
                    .string()?
                    .parse()
                    .map_err(|_| SieveError::Syntax(self.pos))?;
                if op == "over" {
                    Ok(Test::SizeOver(value))
                } else {
                    Err(SieveError::Syntax(self.pos))
                }
            }
            "header" | "address" | "envelope" => {
                let name = self.string()?;
                let value = self.string()?;
                Ok(match word.as_str() {
                    "header" => Test::Header { name, value },
                    "address" => Test::Address { name, value },
                    _ => Test::Envelope { name, value },
                })
            }
            _ => Err(SieveError::Unsupported(word)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_and_executes_bounded_filter() {
        let script =
            r#"require "fileinto"; if header "subject" "spam" { fileinto "Junk"; } else { keep; }"#;
        let commands = parse(script).unwrap_or_default();
        let mut limits = Limits {
            max_instructions: 20,
            max_depth: 8,
            max_redirects: 2,
            ..Limits::default()
        };
        let outcome = execute(
            &commands,
            &Message {
                headers: vec![("Subject".into(), "spam offer".into())],
                ..Message::default()
            },
            &mut limits,
        )
        .unwrap_or_default();
        assert_eq!(outcome.actions, vec![Action::FileInto("Junk".into())]);
    }
    #[test]
    fn enforces_redirect_budget() {
        let commands =
            parse(r#"redirect "a@example.test"; redirect "b@example.test";"#).unwrap_or_default();
        let mut limits = Limits {
            max_instructions: 10,
            max_depth: 8,
            max_redirects: 1,
            ..Limits::default()
        };
        assert_eq!(
            execute(&commands, &Message::default(), &mut limits),
            Err(SieveError::RedirectLimit)
        );
    }
}
