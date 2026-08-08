#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_dkim::{DkimKeyRecord, DkimSignature};
use mail_spf::{SpfContext, expand_domain};
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|input: &[u8]| {
    let _ = DkimSignature::parse(input);
    if let Ok(text) = std::str::from_utf8(input) {
        let _ = DkimKeyRecord::parse(text);
        let _ = mail_dmarc::parse(text);
        let _ = expand_domain(
            text,
            &SpfContext {
                client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                sender: "postmaster@example.test",
                helo: "mx.example.test",
            },
            "example.test",
        );
        let fields = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .collect::<Vec<_>>();
        let _ = mail_arc::parse_sets(&fields);
    }
});
