#![forbid(unsafe_code)]

mod parser;
mod response;
mod session;

pub use parser::{
    AString, Command, CommandBody, MailboxName, ParseError, SequenceSet, parse_command,
};
pub use response::{Status, continuation, greeting, tagged, untagged};
pub use session::{Action, Session, State};

pub const MAX_COMMAND_LINE: usize = 8 * 1024;
pub const MAX_TAG_BYTES: usize = 128;
