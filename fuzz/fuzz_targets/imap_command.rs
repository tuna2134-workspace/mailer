#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = mail_imap_proto::parse_command(input, &[]);
});
