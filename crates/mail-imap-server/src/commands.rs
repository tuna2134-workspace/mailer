use mail_imap_proto::{CommandBody, MailboxName, SequenceSet, SequenceValue};
use mail_mailbox::{FlagSet, StoreMode, SystemFlag};
use mail_storage::{ImapMailbox, ImapMessage, ImapRepository, StorageError, StoreFlags};
use std::collections::BTreeSet;
use time::{OffsetDateTime, format_description::well_known::Rfc2822};
use uuid::Uuid;

#[derive(Clone)]
pub struct Selected {
    pub mailbox: ImapMailbox,
    pub read_only: bool,
}

pub struct Outcome {
    pub responses: Vec<Vec<u8>>,
    pub completion: String,
    pub select: Option<Selected>,
    pub unselect: bool,
}

pub enum CommandError {
    Bad(&'static str),
    No(&'static str),
}

#[allow(clippy::too_many_lines)] // One exhaustive command dispatcher keeps state transitions visible.
pub async fn execute<R: ImapRepository>(
    repo: &R,
    user: Uuid,
    selected: Option<&Selected>,
    command: CommandBody,
) -> Result<Outcome, CommandError> {
    let mut out = Outcome {
        responses: Vec::new(),
        completion: "command completed".into(),
        select: None,
        unselect: false,
    };
    match command {
        CommandBody::Select { mailbox, examine } => {
            let name = text(&mailbox)?;
            let mailbox = repo
                .imap_mailboxes(user)
                .await
                .map_err(storage)?
                .into_iter()
                .find(|item| item.name.eq_ignore_ascii_case(name))
                .ok_or(CommandError::No("mailbox not found"))?;
            out.responses.extend(select_responses(&mailbox));
            out.completion = if examine {
                "[READ-ONLY] EXAMINE completed"
            } else {
                "[READ-WRITE] SELECT completed"
            }
            .into();
            out.select = Some(Selected {
                mailbox,
                read_only: examine,
            });
        }
        CommandBody::Create(name) => {
            repo.imap_create_mailbox(user, text(&name)?)
                .await
                .map_err(storage)?;
            out.completion = "CREATE completed".into();
        }
        CommandBody::Delete(name) => {
            repo.imap_delete_mailbox(user, text(&name)?)
                .await
                .map_err(storage)?;
            out.completion = "DELETE completed".into();
        }
        CommandBody::Rename { from, to } => {
            repo.imap_rename_mailbox(user, text(&from)?, text(&to)?)
                .await
                .map_err(storage)?;
            out.completion = "RENAME completed".into();
        }
        CommandBody::Subscribe { mailbox, subscribe } => {
            repo.imap_subscribe(user, text(&mailbox)?, subscribe)
                .await
                .map_err(storage)?;
            out.completion = if subscribe {
                "SUBSCRIBE completed"
            } else {
                "UNSUBSCRIBE completed"
            }
            .into();
        }
        CommandBody::List {
            reference,
            pattern,
            subscribed_only,
        } => {
            let reference = text(&reference)?;
            let pattern = text(&pattern)?;
            let full = format!("{reference}{pattern}");
            for mailbox in repo.imap_mailboxes(user).await.map_err(storage)? {
                if (!subscribed_only || mailbox.subscribed) && matches_pattern(&mailbox.name, &full)
                {
                    out.responses.push(
                        format!(
                            "* {} () \"/\" \"{}\"\r\n",
                            if subscribed_only { "LSUB" } else { "LIST" },
                            escape(&mailbox.name)
                        )
                        .into_bytes(),
                    );
                }
            }
            out.completion = if subscribed_only {
                "LSUB completed"
            } else {
                "LIST completed"
            }
            .into();
        }
        CommandBody::Status { mailbox, items } => {
            let name = text(&mailbox)?;
            let mailbox = repo
                .imap_mailboxes(user)
                .await
                .map_err(storage)?
                .into_iter()
                .find(|item| item.name.eq_ignore_ascii_case(name))
                .ok_or(CommandError::No("mailbox not found"))?;
            let upper = items.to_ascii_uppercase();
            let mut values = Vec::new();
            if upper.contains("MESSAGES") {
                values.push(format!("MESSAGES {}", mailbox.message_count));
            }
            if upper.contains("UNSEEN") {
                values.push(format!("UNSEEN {}", mailbox.unseen_count));
            }
            if upper.contains("UIDNEXT") {
                values.push(format!("UIDNEXT {}", mailbox.uid_next));
            }
            if upper.contains("UIDVALIDITY") {
                values.push(format!("UIDVALIDITY {}", mailbox.uid_validity));
            }
            if upper.contains("HIGHESTMODSEQ") {
                values.push(format!("HIGHESTMODSEQ {}", mailbox.highest_modseq));
            }
            out.responses.push(
                format!(
                    "* STATUS \"{}\" ({})\r\n",
                    escape(&mailbox.name),
                    values.join(" ")
                )
                .into_bytes(),
            );
            out.completion = "STATUS completed".into();
        }
        CommandBody::Namespace => {
            out.responses
                .push(b"* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n".to_vec());
            out.completion = "NAMESPACE completed".into();
        }
        CommandBody::Check => out.completion = "CHECK completed".into(),
        CommandBody::Unselect => {
            out.unselect = true;
            out.completion = "UNSELECT completed".into();
        }
        CommandBody::Close => {
            let selected = selected.ok_or(CommandError::Bad("no mailbox selected"))?;
            if !selected.read_only {
                repo.imap_expunge(user, selected.mailbox.id, None)
                    .await
                    .map_err(storage)?;
            }
            out.unselect = true;
            out.completion = "CLOSE completed".into();
        }
        CommandBody::Append { mailbox, message } => {
            let (validity, uid) = repo
                .imap_append(user, text(&mailbox)?, &message)
                .await
                .map_err(storage)?;
            out.completion = format!("[APPENDUID {validity} {uid}] APPEND completed");
        }
        CommandBody::Fetch { set, items, uid } => {
            let selected = selected.ok_or(CommandError::Bad("no mailbox selected"))?;
            let mut items = match items.to_ascii_uppercase().as_str() {
                "ALL" => "FLAGS INTERNALDATE RFC822.SIZE ENVELOPE".into(),
                "FAST" => "FLAGS INTERNALDATE RFC822.SIZE".into(),
                "FULL" => "FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY".into(),
                _ => items,
            };
            if uid && !items.to_ascii_uppercase().contains("UID") {
                items.push_str(" UID");
            }
            let mut messages = repo
                .imap_messages(user, selected.mailbox.id)
                .await
                .map_err(storage)?;
            let upper = items.to_ascii_uppercase();
            if !selected.read_only
                && (upper.contains("BODY[") || upper.contains("RFC822"))
                && !upper.contains("BODY.PEEK[")
                && !upper.contains("RFC822.PEEK")
            {
                let uids = chosen(&messages, &set, uid)
                    .into_iter()
                    .map(|message| message.uid)
                    .collect::<Vec<_>>();
                let update = StoreFlags {
                    mode: StoreMode::Add,
                    values: FlagSet::new([SystemFlag::Seen], [])
                        .map_err(|_| CommandError::Bad("invalid flag"))?,
                    unchanged_since: None,
                };
                repo.imap_store_flags(user, selected.mailbox.id, &uids, &update)
                    .await
                    .map_err(storage)?;
                messages = repo
                    .imap_messages(user, selected.mailbox.id)
                    .await
                    .map_err(storage)?;
            }
            for message in chosen(&messages, &set, uid) {
                out.responses.push(fetch_response(message, &items));
            }
            out.completion = "FETCH completed".into();
        }
        CommandBody::Search { criteria, uid } => {
            let selected = selected.ok_or(CommandError::Bad("no mailbox selected"))?;
            let messages = repo
                .imap_messages(user, selected.mailbox.id)
                .await
                .map_err(storage)?;
            let found = search(&messages, &criteria)?;
            out.responses.push(
                format!(
                    "* SEARCH {}\r\n",
                    found
                        .iter()
                        .map(|m| if uid { m.uid } else { m.sequence }.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                )
                .into_bytes(),
            );
            out.completion = "SEARCH completed".into();
        }
        CommandBody::Store {
            set,
            operation,
            flags,
            uid,
        } => {
            let selected = selected.ok_or(CommandError::Bad("no mailbox selected"))?;
            if selected.read_only {
                return Err(CommandError::No("mailbox is read-only"));
            }
            let messages = repo
                .imap_messages(user, selected.mailbox.id)
                .await
                .map_err(storage)?;
            let targets = chosen(&messages, &set, uid);
            let uids = targets.iter().map(|m| m.uid).collect::<Vec<_>>();
            let update = store_update(&operation, &flags)?;
            let silent = operation.ends_with(".SILENT");
            let states = repo
                .imap_store_flags(user, selected.mailbox.id, &uids, &update)
                .await
                .map_err(storage)?;
            if !silent {
                for (message, state) in targets.into_iter().zip(states) {
                    out.responses.push(
                        format!(
                            "* {} FETCH (FLAGS ({}) UID {})\r\n",
                            message.sequence,
                            flags_text(&state.flags),
                            state.uid
                        )
                        .into_bytes(),
                    );
                }
            }
            out.completion = "STORE completed".into();
        }
        CommandBody::Copy {
            set,
            mailbox,
            move_messages,
            uid,
        } => {
            let selected = selected.ok_or(CommandError::Bad("no mailbox selected"))?;
            if move_messages && selected.read_only {
                return Err(CommandError::No("mailbox is read-only"));
            }
            let messages = repo
                .imap_messages(user, selected.mailbox.id)
                .await
                .map_err(storage)?;
            let source = chosen(&messages, &set, uid)
                .into_iter()
                .map(|m| m.uid)
                .collect::<Vec<_>>();
            let destination = text(&mailbox)?;
            let copied = repo
                .imap_copy(
                    user,
                    selected.mailbox.id,
                    &source,
                    destination,
                    move_messages,
                )
                .await
                .map_err(storage)?;
            let validity = repo
                .imap_mailboxes(user)
                .await
                .map_err(storage)?
                .into_iter()
                .find(|m| m.name.eq_ignore_ascii_case(destination))
                .ok_or(CommandError::No("mailbox not found"))?
                .uid_validity;
            out.completion = format!(
                "[COPYUID {validity} {} {}] {} completed",
                join_numbers(&source),
                join_numbers(&copied),
                if move_messages { "MOVE" } else { "COPY" }
            );
        }
        CommandBody::Expunge { uid_set } => {
            let selected = selected.ok_or(CommandError::Bad("no mailbox selected"))?;
            if selected.read_only {
                return Err(CommandError::No("mailbox is read-only"));
            }
            let before = repo
                .imap_messages(user, selected.mailbox.id)
                .await
                .map_err(storage)?;
            let filter = uid_set.as_ref().map(|set| {
                chosen(&before, set, true)
                    .into_iter()
                    .map(|m| m.uid)
                    .collect::<Vec<_>>()
            });
            let removed = repo
                .imap_expunge(user, selected.mailbox.id, filter.as_deref())
                .await
                .map_err(storage)?;
            let mut sequences = before
                .iter()
                .filter(|m| removed.contains(&m.uid))
                .map(|m| m.sequence)
                .collect::<Vec<_>>();
            sequences.sort_unstable_by(|a, b| b.cmp(a));
            for sequence in sequences {
                out.responses
                    .push(format!("* {sequence} EXPUNGE\r\n").into_bytes());
            }
            out.completion = "EXPUNGE completed".into();
        }
        _ => return Err(CommandError::Bad("unsupported command")),
    }
    Ok(out)
}

fn text(name: &MailboxName) -> Result<&str, CommandError> {
    std::str::from_utf8(name.as_bytes())
        .map_err(|_| CommandError::Bad("mailbox name must be UTF-8"))
}
#[allow(clippy::needless_pass_by_value)] // Result::map_err supplies an owned value.
fn storage(error: StorageError) -> CommandError {
    match error {
        StorageError::Unavailable(_) => CommandError::No("storage unavailable"),
        StorageError::QuotaExceeded => CommandError::No("[OVERQUOTA] quota exceeded"),
        StorageError::CounterExhausted => CommandError::No("mailbox counter exhausted"),
        StorageError::NotFound => CommandError::No("mailbox or message not found"),
        StorageError::Conflict => CommandError::No("mailbox conflict"),
    }
}
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
fn select_responses(m: &ImapMailbox) -> Vec<Vec<u8>> {
    vec![
        b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n".to_vec(),
        format!("* {} EXISTS\r\n", m.message_count).into_bytes(),
        b"* 0 RECENT\r\n".to_vec(),
        format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", m.uid_validity).into_bytes(),
        format!("* OK [UIDNEXT {}] predicted next UID\r\n", m.uid_next).into_bytes(),
        format!("* OK [HIGHESTMODSEQ {}] mod-sequence\r\n", m.highest_modseq).into_bytes(),
    ]
}
fn matches_pattern(name: &str, pattern: &str) -> bool {
    fn inner(n: &[u8], p: &[u8]) -> bool {
        match p.split_first() {
            None => n.is_empty(),
            Some((&b'*', rest)) => (0..=n.len()).any(|i| inner(&n[i..], rest)),
            Some((&b'%', rest)) => (0..=n.iter().position(|b| *b == b'/').unwrap_or(n.len()))
                .any(|i| inner(&n[i..], rest)),
            Some((&head, rest)) => n.first().is_some_and(|b| *b == head) && inner(&n[1..], rest),
        }
    }
    inner(name.as_bytes(), pattern.as_bytes())
}
fn chosen<'a>(messages: &'a [ImapMessage], set: &SequenceSet, uid: bool) -> Vec<&'a ImapMessage> {
    let largest = messages
        .last()
        .map_or(0, |m| if uid { m.uid } else { m.sequence });
    messages
        .iter()
        .filter(|m| {
            let value = if uid { m.uid } else { m.sequence };
            set.0.iter().any(|range| {
                let a = sequence(range.start, largest);
                let b = sequence(range.end, largest);
                value >= a.min(b) && value <= a.max(b)
            })
        })
        .collect()
}
fn sequence(value: SequenceValue, largest: u32) -> u32 {
    match value {
        SequenceValue::Number(n) => n,
        SequenceValue::Largest => largest,
    }
}
fn flags_text(flags: &FlagSet) -> String {
    let mut values = flags.system_names();
    values.extend(flags.keywords.iter().cloned());
    values.join(" ")
}
fn store_update(operation: &str, flags: &str) -> Result<StoreFlags, CommandError> {
    let mode = if operation.starts_with('+') {
        StoreMode::Add
    } else if operation.starts_with('-') {
        StoreMode::Remove
    } else {
        StoreMode::Replace
    };
    let words = flags
        .trim_matches(|c| c == '(' || c == ')')
        .split_whitespace();
    let mut system = Vec::new();
    let mut keywords = Vec::new();
    for word in words {
        match word.to_ascii_lowercase().as_str() {
            "\\answered" => system.push(SystemFlag::Answered),
            "\\deleted" => system.push(SystemFlag::Deleted),
            "\\draft" => system.push(SystemFlag::Draft),
            "\\flagged" => system.push(SystemFlag::Flagged),
            "\\seen" => system.push(SystemFlag::Seen),
            value if value.starts_with('\\') => {
                return Err(CommandError::Bad("unknown system flag"));
            }
            _ => keywords.push(word.to_owned()),
        }
    }
    Ok(StoreFlags {
        mode,
        values: FlagSet::new(system, keywords).map_err(|_| CommandError::Bad("invalid flag"))?,
        unchanged_since: None,
    })
}
fn fetch_response(message: &ImapMessage, items: &str) -> Vec<u8> {
    let upper = items.to_ascii_uppercase();
    let mut fields = Vec::new();
    if upper.contains("FLAGS") {
        fields.push(format!("FLAGS ({})", message.flags.join(" ")).into_bytes());
    }
    if upper.contains("UID") {
        fields.push(format!("UID {}", message.uid).into_bytes());
    }
    if upper.contains("RFC822.SIZE") {
        fields.push(format!("RFC822.SIZE {}", message.raw.len()).into_bytes());
    }
    if upper.contains("INTERNALDATE") {
        let date = OffsetDateTime::from(message.internal_date)
            .format(&Rfc2822)
            .unwrap_or_else(|_| "Thu, 1 Jan 1970 00:00:00 +0000".into());
        fields.push(format!("INTERNALDATE \"{date}\"").into_bytes());
    }
    if upper.contains("BODY") || upper.contains("RFC822") {
        let (offset, count) = partial(&upper).unwrap_or((0, message.raw.len()));
        let end = offset.saturating_add(count).min(message.raw.len());
        let bytes = message.raw.get(offset..end).unwrap_or_default();
        let mut field = format!("BODY[]<{offset}> {{{}}}\r\n", bytes.len()).into_bytes();
        field.extend_from_slice(bytes);
        fields.push(field);
    }
    let mut response = format!("* {} FETCH (", message.sequence).into_bytes();
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            response.push(b' ');
        }
        response.extend_from_slice(field);
    }
    response.extend_from_slice(b")\r\n");
    response
}
fn partial(value: &str) -> Option<(usize, usize)> {
    let start = value.find('<')? + 1;
    let end = value[start..].find('>')? + start;
    let (offset, count) = value[start..end].split_once('.')?;
    Some((offset.parse().ok()?, count.parse().ok()?))
}
fn search<'a>(
    messages: &'a [ImapMessage],
    criteria: &str,
) -> Result<Vec<&'a ImapMessage>, CommandError> {
    let terms = criteria
        .trim_matches(|c| c == '(' || c == ')')
        .split_whitespace()
        .map(str::to_ascii_uppercase)
        .collect::<BTreeSet<_>>();
    let known = ["ALL", "SEEN", "UNSEEN", "DELETED", "UNDELETED"];
    if terms.iter().any(|term| !known.contains(&term.as_str())) {
        return Err(CommandError::Bad("unsupported search criterion"));
    }
    Ok(messages
        .iter()
        .filter(|m| {
            let seen = m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
            let deleted = m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Deleted"));
            (!terms.contains("SEEN") || seen)
                && (!terms.contains("UNSEEN") || !seen)
                && (!terms.contains("DELETED") || deleted)
                && (!terms.contains("UNDELETED") || !deleted)
        })
        .collect())
}
fn join_numbers(values: &[u32]) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn patterns_and_partial_fetch() {
        assert!(matches_pattern("Archive/2026", "Archive/%"));
        assert!(!matches_pattern("Archive/2026/Aug", "Archive/%"));
        assert_eq!(partial("BODY[]<2.4>"), Some((2, 4)));
    }
}
