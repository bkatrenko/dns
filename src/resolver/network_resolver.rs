use crate::parser::enums::{DNSRecord, DNSRecordType};
use crate::parser::{enums, DNSPacket, DNSQuestionPart, DNSResponsePart};
use crate::resolver::root_servers::get_root_servers;
use crate::resolver::UdpResolver;
use rand::{seq::SliceRandom, Rng};
use std::error::Error;
use std::net::{IpAddr, SocketAddr};

use super::NetworkResolver;

const UDP_PORT: u16 = 53;

pub fn recursive_resolve(
    resolver: &mut impl NetworkResolver,
    question: Vec<u8>,
    id: &String,
) -> Result<DNSPacket, Box<dyn Error>> {
    let question_packet = DNSPacket::from_bytes(question)?;

    println!(
        "INFO id: {id}, message id: {}, start recursive resolution, questions: {}",
        question_packet.header.id,
        question_packet.question_part.len()
    );

    if question_packet.question_part.is_empty() {
        println!(
            "ERROR id: {id}, message id: {}, empty question part",
            question_packet.header.id
        );

        return Ok(UdpResolver::error_response(
            enums::ErrorCode::ServerFailure,
            question_packet,
        ));
    }

    let question_part = question_packet.question_part.get(0).unwrap();

    println!(
        "INFO id: {id}, message id: {}, root server resolution: {}, record type: {:?}, record class: {:?}",
        question_packet.header.id, question_part.question_name, question_part.dns_record_type,
        question_part.dns_record_class
    );

    let initial_ns_address = get_root_server_address();
    let mut ns_address = initial_ns_address;

    loop {
        println!(
            "INTO id: {id}, resolve {} with NS address: {}, question is: {:?}",
            question_part.question_name, ns_address, question_part
        );

        let mut root_response = resolve(question_part, resolver, ns_address)?;

        if root_response.response_part.len() > 0 {
            root_response.header.id = question_packet.header.id;

            if check_if_cname(&root_response.response_part) {
                let mut packet = DNSPacket::default();
                packet.header.id = rand::thread_rng().gen::<u16>();
                packet.header.qd_count = 1;
                packet.header.is_query = true;

                let question = make_question(&root_response.response_part, DNSRecordType::CNAME);
                packet.question_part.push(question);

                let mut ns_response = recursive_resolve(resolver, packet.to_bytes()?, id)?;

                root_response
                    .response_part
                    .append(&mut ns_response.response_part);
                root_response.header.an_count = root_response.response_part.len() as u16
            }

            return Ok(root_response);
        }

        if root_response.header.error_code != enums::ErrorCode::NoError {
            root_response.header.id = question_packet.header.id;
            return Ok(root_response);
        }

        if root_response.resources.len() > 0 {
            ns_address = get_server_address(
                get_random_response(&root_response.resources, DNSRecordType::A)
                    .unwrap()
                    .data,
            );
            continue;
        }

        if root_response.authorities.len() > 0 {
            let mut packet = DNSPacket::default();
            packet.header.id = rand::thread_rng().gen::<u16>();
            packet.header.qd_count = 1;
            packet.header.is_query = true;

            let question = make_question(&root_response.authorities, DNSRecordType::NS);

            println!(
                "INFO id: {id}, recursive resolve: {}",
                question.question_name
            );

            let q_name = question.question_name.clone();

            packet.question_part.push(question);
            let ns_response = recursive_resolve(resolver, packet.to_bytes()?, id)?;

            ns_address = get_server_address(
                get_random_response(&ns_response.response_part, DNSRecordType::A)
                    .unwrap()
                    .data,
            );

            println!(
                "INFO id: {id}, new NS address: {ns_address} from name: {}",
                q_name
            );
            continue;
        }

        return Ok(UdpResolver::error_response(
            enums::ErrorCode::NameError,
            question_packet,
        ));
    }
}

fn make_question(responses: &Vec<DNSResponsePart>, record_type: DNSRecordType) -> DNSQuestionPart {
    return DNSQuestionPart {
        buffer_offset: 0,
        question_name: get_server_name(get_random_response(&responses, record_type).unwrap().data),
        dns_record_class: enums::DNSRecordClass::IN,
        dns_record_type: enums::DNSRecordType::A,
    };
}

fn resolve(
    question: &DNSQuestionPart,
    resolver: &mut impl NetworkResolver,
    address: IpAddr,
) -> Result<DNSPacket, Box<dyn Error>> {
    let mut packet = DNSPacket::default();
    let mut rng = rand::thread_rng();

    packet.header.id = rng.gen::<u16>();

    packet.header.qd_count = 1;
    packet.header.is_query = true;
    packet.question_part.push(question.clone());

    let response = resolver.resolve(SocketAddr::new(address, UDP_PORT), packet.to_bytes()?)?;
    let res = match DNSPacket::from_bytes(response) {
        Ok(res) => res,
        Err(e) => panic!("handling DNS response: {e}"),
    };
    return Ok(res);
}

fn get_root_server_address() -> IpAddr {
    let root_server_response = get_random_response(&get_root_servers(), DNSRecordType::A).unwrap();

    return get_server_address(root_server_response.data);
}

fn get_server_address(record: DNSRecord) -> IpAddr {
    match record {
        DNSRecord::A { len, ip } => IpAddr::V4(ip),
        DNSRecord::AAAA { len, ip } => IpAddr::V6(ip),

        _ => panic!("record type not supported"),
    }
}

fn get_server_name(record: DNSRecord) -> String {
    match record {
        DNSRecord::NS { len, name_server } => name_server,
        DNSRecord::CNAME { len, cname } => cname,
        _ => panic!("record type not supported"),
    }
}

fn check_if_cname(responses: &Vec<DNSResponsePart>) -> bool {
    responses
        .iter()
        .any(|x| x.record_type == DNSRecordType::CNAME)
}

fn get_random_response(
    responses: &Vec<DNSResponsePart>,
    rec_type: DNSRecordType,
) -> Option<DNSResponsePart> {
    let a_responses = responses.iter().filter(|x| x.record_type == rec_type);

    let response: Vec<DNSResponsePart> = a_responses.map(|x| x.clone()).collect();

    match response.choose(&mut rand::thread_rng()) {
        Some(e) => return Some(e.clone()),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use self::enums::OpCode;

    use super::*;

    use crate::parser::enums::{DNSRecordClass, DNSRecordType};
    use crate::{
        parser::{DNSName, DNSPacket, DNSPacketHeader, DNSQuestionPart},
        resolver::NetworkResolver,
    };
    use std::error::Error;
    use std::io::Error as errors;
    use std::net::{Ipv4Addr, SocketAddr};

    struct MockResolver<'a> {
        responses: Vec<&'a DNSPacket>,
        requests: usize,
        error: Option<Box<dyn Error>>,
    }

    impl<'a> MockResolver<'a> {
        fn new(responses: Vec<&'a DNSPacket>, error: Option<Box<dyn Error>>) -> MockResolver {
            MockResolver {
                responses: responses,
                requests: 0,
                error: error,
            }
        }
    }

    impl<'a> NetworkResolver for MockResolver<'a> {
        fn resolve(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
            if self.responses.is_empty() {
                panic!("no DNS responses were mocked")
            }

            if self.error.is_some() {
                return Err(Box::new(errors::other("oops")));
            }

            self.requests += 1;

            let bytes = self
                .responses
                .get(self.requests - 1)
                .unwrap()
                .to_bytes()
                .unwrap();

            use std::fs::File;
            use std::io::prelude::*;

            let mut file = File::create("/Users/bohdan/Desktop/lalala dns/foo.hex")?;
            file.write_all(&bytes)?;

            return Ok(bytes);
        }
    }

    // Test simple resolution in case root server returns the right NS
    #[test]
    fn simple_resolve() {
        let mut question_packet = DNSPacket::default();
        question_packet.header = DNSPacketHeader::default();
        question_packet.header.is_query = true;
        question_packet.header.qd_count = 1;
        question_packet.header.id = 1234;
        question_packet.header.op_code = OpCode::Query;
        question_packet.header.recursion_desired = true;

        question_packet.question_part.push(DNSQuestionPart {
            buffer_offset: 12,
            question_name: String::from("test.local"),
            dns_record_type: DNSRecordType::A,
            dns_record_class: DNSRecordClass::IN,
        });

        let mut response_packet = DNSPacket::default();
        response_packet.header = question_packet.header;
        response_packet.header.an_count = 1;
        response_packet.header.recursion_available = true;
        response_packet.header.op_code = OpCode::Query;

        response_packet.question_part = question_packet.question_part.clone();
        response_packet.response_part.push(DNSResponsePart {
            name: DNSName {
                value: String::from("test.local"),
                offset: 12,
            },
            record_type: DNSRecordType::A,
            record_class: DNSRecordClass::IN,
            udp_length: 0,
            ttl: 1059,
            data: DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(0, 0, 0, 0),
            },
        });

        let mut resolver = MockResolver::new(vec![&response_packet], None);
        let resp = recursive_resolve(
            &mut resolver,
            question_packet.to_bytes().unwrap(),
            &String::from("test"),
        );

        assert_eq!(response_packet, resp.unwrap());
    }
}
