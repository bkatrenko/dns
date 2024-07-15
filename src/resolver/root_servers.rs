use crate::parser::enums::{DNSRecord, DNSRecordClass, DNSRecordType};
use crate::parser::{DNSName, DNSResponsePart};

use std::net::Ipv4Addr;

pub fn get_root_servers() -> Vec<DNSResponsePart> {
    vec![
        DNSResponsePart {
            name: DNSName {
                value: String::from("A.ROOT-SERVERS.NET"),
                offset: 0,
            },
            record_type: DNSRecordType::A,
            record_class: DNSRecordClass::IN,
            udp_length: 0,
            ttl: 0,
            data: DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(198, 41, 0, 4),
            },
        },
        DNSResponsePart {
            name: DNSName {
                value: String::from("B.ROOT-SERVERS.NET"),
                offset: 0,
            },
            record_type: DNSRecordType::A,
            record_class: DNSRecordClass::IN,
            udp_length: 0,
            ttl: 0,
            data: DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(170, 247, 170, 2),
            },
        },
        DNSResponsePart {
            name: DNSName {
                value: String::from("C.ROOT-SERVERS.NET"),
                offset: 0,
            },
            record_type: DNSRecordType::A,
            record_class: DNSRecordClass::IN,
            udp_length: 0,
            ttl: 0,
            data: DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(192, 33, 4, 12),
            },
        },
    ]
}
