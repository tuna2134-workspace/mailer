#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_dsn::FailureNotice;

fuzz_target!(|input: &[u8]| {
    if input.len() > 64 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let fields = text.split('|').collect::<Vec<_>>();
    let value = |index: usize| fields.get(index).copied().unwrap_or_default();
    let optional = |index: usize| {
        fields
            .get(index)
            .copied()
            .filter(|field| !field.is_empty())
    };
    let _ = mail_dsn::failure_message(&FailureNotice {
        sender: value(0),
        recipient: value(1),
        original_recipient: optional(2),
        action: value(3),
        status: value(4),
        diagnostic: value(5),
        remote_mta: optional(6),
        envelope_id: optional(7),
    });
    let _ = mail_dsn::mdn_message(value(0), value(1), value(2));
});
