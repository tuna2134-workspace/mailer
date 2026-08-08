#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if input.len() > 256 * 1024 {
        return;
    }
    if let Ok(script) = std::str::from_utf8(input) {
        let _ = mail_sieve::parse(script);
    }
});
