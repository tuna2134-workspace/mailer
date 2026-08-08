#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if input.len() > 64 * 1024 {
        return;
    }
    let _ = mail_smtp_proto::parse_command(input, false);
    let _ = mail_smtp_proto::unstuff_data_line(input, false);
});
