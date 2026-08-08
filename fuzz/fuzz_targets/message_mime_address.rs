#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_address::{AddressLimits, parse_address_list};
use mail_message::{MessageLimits, MessageParser};
use mail_mime::{MimeLimits, parse_message};

fuzz_target!(|input: &[u8]| {
    if input.len() > 1024 * 1024 {
        return;
    }
    let split = input.len() / 2;
    let limits = MessageLimits {
        max_header_bytes: 64 * 1024,
        max_header_line_bytes: 1_000,
        max_header_fields: 256,
    };
    let mut parser = MessageParser::new(limits);
    let _ = parser.push(&input[..split]);
    let _ = parser.push(&input[split..]);
    let _ = parser.finish();
    let _ = parse_address_list(
        input,
        AddressLimits {
            max_bytes: 64 * 1024,
            max_addresses: 256,
            max_comment_depth: 8,
        },
    );
    let _ = parse_message(
        input,
        MimeLimits {
            max_depth: 8,
            max_parts: 256,
            max_decoded_bytes: 1024 * 1024,
            message: limits,
            ..MimeLimits::default()
        },
    );
});
