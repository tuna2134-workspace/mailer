use crate::{Command, CommandBody, Status, tagged, untagged};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Responses(Vec<String>),
    StartTls {
        tag: String,
    },
    Authenticate {
        tag: String,
        mechanism: String,
        initial_response: Option<String>,
    },
    Login {
        tag: String,
        username: Vec<u8>,
        password: Vec<u8>,
    },
    Execute {
        tag: String,
        command: CommandBody,
    },
    Close(Vec<String>),
    Idle {
        tag: String,
    },
}

#[derive(Clone, Debug)]
pub struct Session {
    state: State,
    tls_active: bool,
    tls_available: bool,
    enabled: Enabled,
}

#[derive(Clone, Copy, Debug, Default)]
struct Enabled {
    condstore: bool,
    qresync: bool,
}

impl Session {
    #[must_use]
    pub const fn new(tls_active: bool, tls_available: bool) -> Self {
        Self {
            state: State::NotAuthenticated,
            tls_active,
            tls_available,
            enabled: Enabled {
                condstore: false,
                qresync: false,
            },
        }
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub fn capabilities(&self) -> Vec<String> {
        let mut values = vec![
            "IMAP4rev2".into(),
            "IMAP4rev1".into(),
            "ENABLE".into(),
            "LITERAL+".into(),
            "NAMESPACE".into(),
            "UIDPLUS".into(),
            "MOVE".into(),
            "BINARY".into(),
            "IDLE".into(),
            "CONDSTORE".into(),
            "QRESYNC".into(),
        ];
        if self.tls_available && !self.tls_active && self.state == State::NotAuthenticated {
            values.extend(["STARTTLS".into(), "LOGINDISABLED".into()]);
        }
        if self.tls_active && self.state == State::NotAuthenticated {
            values.extend(["AUTH=PLAIN".into(), "SASL-IR".into()]);
        }
        values
    }

    pub fn command(&mut self, command: Command) -> Action {
        let tag = command.tag;
        match command.body {
            CommandBody::Capability => Action::Responses(vec![
                untagged(&format!("CAPABILITY {}", self.capabilities().join(" "))),
                tagged(&tag, Status::Ok, "CAPABILITY completed"),
            ]),
            CommandBody::Noop => {
                Action::Responses(vec![tagged(&tag, Status::Ok, "NOOP completed")])
            }
            CommandBody::Logout => {
                self.state = State::Logout;
                Action::Close(vec![
                    untagged("BYE logging out"),
                    tagged(&tag, Status::Ok, "LOGOUT completed"),
                ])
            }
            CommandBody::StartTls
                if self.state == State::NotAuthenticated
                    && self.tls_available
                    && !self.tls_active =>
            {
                Action::StartTls { tag }
            }
            CommandBody::Authenticate {
                mechanism,
                initial_response,
            } if self.state == State::NotAuthenticated && self.tls_active => Action::Authenticate {
                tag,
                mechanism,
                initial_response,
            },
            CommandBody::Login { username, password }
                if self.state == State::NotAuthenticated && self.tls_active =>
            {
                Action::Login {
                    tag,
                    username: username.0,
                    password: password.0,
                }
            }
            CommandBody::Enable(capabilities)
                if matches!(self.state, State::Authenticated | State::Selected) =>
            {
                let mut enabled = Vec::new();
                for capability in capabilities {
                    match capability.as_str() {
                        "CONDSTORE" => {
                            self.enabled.condstore = true;
                            enabled.push(capability);
                        }
                        "QRESYNC" => {
                            self.enabled.condstore = true;
                            self.enabled.qresync = true;
                            enabled.push(capability);
                        }
                        _ => {}
                    }
                }
                let response = if enabled.is_empty() {
                    untagged("ENABLED")
                } else {
                    untagged(&format!("ENABLED {}", enabled.join(" ")))
                };
                Action::Responses(vec![response, tagged(&tag, Status::Ok, "ENABLE completed")])
            }
            command @ (CommandBody::Select { .. }
            | CommandBody::Create(_)
            | CommandBody::Delete(_)
            | CommandBody::Rename { .. }
            | CommandBody::Subscribe { .. }
            | CommandBody::List { .. }
            | CommandBody::Status { .. }
            | CommandBody::Namespace
            | CommandBody::Append { .. })
                if matches!(self.state, State::Authenticated | State::Selected) =>
            {
                Action::Execute { tag, command }
            }
            command @ (CommandBody::Close
            | CommandBody::Unselect
            | CommandBody::Check
            | CommandBody::Fetch { .. }
            | CommandBody::Store { .. }
            | CommandBody::Search { .. }
            | CommandBody::Copy { .. }
            | CommandBody::Expunge { .. })
                if self.state == State::Selected =>
            {
                Action::Execute { tag, command }
            }
            CommandBody::Idle if self.state == State::Selected => Action::Idle { tag },
            CommandBody::Unknown(_) => {
                Action::Responses(vec![tagged(&tag, Status::Bad, "unknown command")])
            }
            _ => Action::Responses(vec![tagged(
                &tag,
                Status::Bad,
                "command invalid in this state",
            )]),
        }
    }

    pub fn tls_started(&mut self) {
        self.state = State::NotAuthenticated;
        self.tls_active = true;
        self.enabled = Enabled::default();
    }

    #[must_use]
    pub const fn condstore_enabled(&self) -> bool {
        self.enabled.condstore
    }

    #[must_use]
    pub const fn qresync_enabled(&self) -> bool {
        self.enabled.qresync
    }

    pub fn authentication_succeeded(&mut self) {
        self.state = State::Authenticated;
    }

    pub fn mailbox_selected(&mut self) {
        if self.state == State::Authenticated {
            self.state = State::Selected;
        }
    }

    pub fn mailbox_unselected(&mut self) {
        if self.state == State::Selected {
            self.state = State::Authenticated;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_command;

    #[test]
    fn enforces_states_and_resets_after_starttls() -> Result<(), crate::ParseError> {
        let mut session = Session::new(false, true);
        assert!(session.capabilities().contains(&"LOGINDISABLED".into()));
        let command = parse_command(b"A1 STARTTLS\r\n", &[])?;
        assert!(matches!(session.command(command), Action::StartTls { .. }));
        session.tls_started();
        assert!(session.capabilities().contains(&"AUTH=PLAIN".into()));
        assert!(matches!(
            session.command(parse_command(b"A2 LOGIN alice secret\r\n", &[])?),
            Action::Login { .. }
        ));
        session.authentication_succeeded();
        session.mailbox_selected();
        assert_eq!(session.state(), State::Selected);
        session.mailbox_unselected();
        assert_eq!(session.state(), State::Authenticated);
        assert!(matches!(
            session.command(parse_command(b"A3 ENABLE UNKNOWN\r\n", &[])?),
            Action::Responses(_)
        ));
        assert!(matches!(
            session.command(parse_command(b"A4 ENABLE QRESYNC\r\n", &[])?),
            Action::Responses(_)
        ));
        assert!(session.qresync_enabled());
        assert!(session.condstore_enabled());
        Ok(())
    }
}
