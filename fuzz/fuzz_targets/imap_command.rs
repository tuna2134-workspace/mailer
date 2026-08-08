#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if input.len() > mail_imap_proto::MAX_COMMAND_LINE {
        return;
    }
    let _ = mail_imap_proto::parse_command(input, &[]);
});
