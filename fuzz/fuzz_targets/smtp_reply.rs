#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = mail_smtp_client::parse_reply_line(input);
});
