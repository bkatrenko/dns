use crate::parser::DNSPacket;
use crate::resolver::{network_resolver, NetworkResolver, UdpResolver};
use nanoid::nanoid;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

use parser::enums;
use std::time::Instant;

use rand::Rng;

pub fn f() {}

mod parser;
mod resolver;

// 512 bytes is sa standard size for DNS message without extensions.
const MAX_MESSAGE_BUFFER_SIZE: usize = 512;

pub fn serve(args: &Vec<String>) {
    let port_number: u16 = args[2].parse::<u16>().unwrap();
    let local_address: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port_number);

    println!("create the resolver instance on port :{port_number}");
    // create a resolver instance.
    let local_resolver: resolver::UdpResolver = resolver::UdpResolver::new(local_address);

    // resolve the request recursively.
    local_resolver.listen(move |data: [u8; MAX_MESSAGE_BUFFER_SIZE]| -> Result<Vec<u8>, Box<dyn Error>> {
        let request_id = nanoid!();

        let sock = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0),
            0,
        )))?;

        let mut resolver = UdpResolver::create(sock);

        match network_resolver::recursive_resolve(&mut resolver, data.to_vec(), &request_id) {
            Ok(resp) => {
                return Ok(resp.to_bytes()?)
            }
            Err(e) => {
                // Since recursive resolve is expected to always return the valid DNS message (even
                // in case it contains an error like serverFailure), error from this function should
                // close the process in case to prevent timeout on client side.
                // LET IT CRASH! ("and fix the error" rather that silently fail)
                panic!("unrecoverable error during the recursive resolution: {e}, request ID: {request_id}")
            },
        };
    });
}

pub fn visually_resolve(args: &Vec<String>) {
    let host_name = &args[2];
    let record_type = &args[3];

    let mut resolver = create_resolver();

    let question_packet = create_question(host_name, record_type);

    let question_bytes = question_packet.to_bytes().unwrap().to_vec();
    let request_id = &nanoid!();

    let start = Instant::now();

    match resolve(&mut resolver, question_bytes, &request_id) {
        Ok(resp) => {
            println!(">>>>>>>>>>>> got results: <<<<<<<<<<<<<");

            println!("message id: {}", resp.header.id);
            println!("is query: {}", resp.header.is_query);
            println!("operation code: {}", resp.header.op_code.to_string());
            println!(
                "authoritative answer: {}",
                resp.header.authoritative_answer_flag
            );
            println!("truncated: {}", resp.header.truncate_flag);
            println!("recursion desired: {}", resp.header.recursion_desired);
            println!("recursion available: {}", resp.header.recursion_available);
            println!("error code: {}", resp.header.error_code.to_string());

            println!("questions: {}", resp.header.qd_count);
            println!("answers: {}", resp.header.an_count);
            println!("resources: {}", resp.header.ns_count);
            println!("additional: {}", resp.header.ns_count);

            let print = |e: &parser::DNSResponsePart| println!("{}", e.to_string());

            if !resp.response_part.is_empty() {
                println!("\n\x1b[31mresponses:\x1b[0m");
                resp.response_part.iter().for_each(print);
            }

            if !resp.resources.is_empty() {
                println!("\n\x1b[31mresources:\x1b[0m");
                resp.resources.iter().for_each(print);
            }

            if !resp.authorities.is_empty() {
                println!("\n\x1b[31mauthorities:\x1b[0m");
                resp.authorities.iter().for_each(print);
            }

            println!("duration: {:?}", start.elapsed());
        }
        Err(e) => {
            // Since recursive resolve is expected to always return the valid DNS message (even
            // in case it contains an error like serverFailure), error from this function should
            // close the process in case to prevent timeout on client side.
            // LET IT CRASH! ("and fix the error" rather that silently fail)
            panic!("unrecoverable error during the recursive resolution: {e}, request ID: {request_id}")
        }
    };
}

pub fn resolve(
    resolver: &mut impl NetworkResolver,
    question: Vec<u8>,
    id: &String,
) -> Result<DNSPacket, Box<dyn Error>> {
    network_resolver::recursive_resolve(resolver, question, id)
}

pub fn create_resolver() -> UdpResolver {
    let sock = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(0, 0, 0, 0),
        0,
    )))
    .unwrap(); // since we have a cli app call, it's the one was to panic

    return UdpResolver::create(sock);
}

pub fn create_question(host_name: &String, record_type: &String) -> parser::DNSPacket {
    let mut question_packet = parser::DNSPacket::default();
    question_packet.header.id = rand::thread_rng().gen::<u16>();
    question_packet.header.is_query = true;
    question_packet.header.qd_count = 1;
    question_packet.header.recursion_desired = true;
    question_packet.question_part.push(parser::DNSQuestionPart {
        buffer_offset: 0,
        question_name: host_name.clone(),
        dns_record_type: record_type.parse::<parser::enums::DNSRecordType>().unwrap(),
        dns_record_class: enums::DNSRecordClass::IN,
    });

    return question_packet;
}
