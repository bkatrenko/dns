use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

use crate::parser::{enums, DNSPacket};

pub mod network_resolver;
pub mod root_servers;

const MAX_RECV_MESSAGE_SIZE: usize = 4096;

pub trait NetworkResolver {
    fn resolve(&mut self, addr: SocketAddr, question: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
}

#[derive(Debug)]
pub struct UdpResolver {
    pub address: SocketAddr,
    pub socket: UdpSocket,
}

impl UdpResolver {
    pub fn new(address: SocketAddr) -> UdpResolver {
        UdpResolver {
            address: address,
            socket: UdpSocket::bind(address).unwrap(),
        }
    }

    pub fn create(sock: UdpSocket) -> UdpResolver {
        UdpResolver {
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
            socket: sock,
        }
    }

    pub fn listen<F>(&self, f: F)
    where
        F: Fn([u8; 512]) -> Result<Vec<u8>, Box<dyn Error>> + Send + Copy + 'static,
    {
        println!("local DNS server started");
        loop {
            let mut buf = [0; 512];

            let (_, src) = match self.socket.recv_from(&mut buf) {
                Ok(data) => data,
                Err(err) => {
                    println!("error while reading UDP request: {}", err);
                    return;
                }
            };

            let sock = self.socket.try_clone();

            tokio::spawn(async move {
                match f(buf) {
                    Ok(response) => {
                        if let Err(err) = sock.unwrap().send_to(response.as_slice(), &src) {
                            println!("error sending UDP response: {}", err);
                        }
                    }
                    Err(err) => {
                        println!("error while writing UDP response: {}", err);
                        return;
                    }
                };
            });
        }
    }

    fn error_response(error_code: enums::ErrorCode, question: DNSPacket) -> DNSPacket {
        let mut error_answer = DNSPacket::default();

        error_answer.header.id = question.header.id;
        error_answer.header.is_query = false;
        error_answer.header.recursion_desired = question.header.recursion_desired;
        error_answer.header.recursion_available = true;
        error_answer.header.error_code = error_code;

        return error_answer;
    }
}

impl NetworkResolver for UdpResolver {
    fn resolve(&mut self, addr: SocketAddr, question: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        self.socket.send_to(&question, &addr)?;

        let mut buf = [0; MAX_RECV_MESSAGE_SIZE];
        let (size, _) = self.socket.recv_from(&mut buf)?;

        let mut response = buf.to_vec();
        response.truncate(size);

        Ok(response)
    }
}
