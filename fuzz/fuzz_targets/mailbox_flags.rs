#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(keyword) = std::str::from_utf8(input) {
        let _ = mail_mailbox::FlagSet::new([], [keyword.to_owned()]);
    }
});
