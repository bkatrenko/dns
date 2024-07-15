// This application is a simple implementation of DNS protocol
// (https://en.wikipedia.org/wiki/Domain_Name_System) with multithreading DNS server to be able
// to resolve input requests.
// *mod parser* - implementing the DNS message marshal/unMarshal functionality - from binary
// representation to object and vise versa.
// *mod buffer* - implementing simple bytes buffer to work with binary data in an easy day.
// *mod enums* - implementing basic natural DNS entities - like OpCodes, ErrorCodes, RecordTypes etc.
// *mod resolver/network_resolver* responsible for network related logic and recursive or
// non-recursive resolving.
// No external dependencies (except "rand" and "nanoid" which should be quite stable :)).
use crate::resolver::{network_resolver, UdpResolver};
use nanoid::nanoid;
use parser::enums;
use rand::Rng;
use resolver::visual_resolve::visually_resolve;
use std::{env::args, net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket}};
use std::{env, error::Error};
mod parser;
mod resolver;

// 512 bytes is sa standard size for DNS message without extensions.
const MAX_MESSAGE_BUFFER_SIZE: usize = 512;

// In order to run the application, use cargo:
// ```
// cargo run serve 58980
// ```
// Where 35670 is a port number application should listen to.
// In order to try it out, you could use dig, f.e.:
// ```
// dig -p 35670 @127.0.0.1 facebook.com
// ```
// So we ask dig to resolve the hostname with a local DNS server on port 35670.
// Application support A, AAAA, CNAME and MX record types, recursive resolving implemented,
// logs are in stdout.
//
// WARNING: the service is !!!NOT!!! production ready and currently just a pet project, but
// could be a good example of implementing DNS and exploring how DNS actually works.
//
// use the great tokio runtime for easy multithreading.

const RESOLVE_COMMAND: &str = "resolve";
const SERVE_COMMAND: &str = "serve";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).unwrap().as_str() {
        RESOLVE_COMMAND => visually_resolve(&args),
        SERVE_COMMAND => serve(&args),
        _ => panic!("unknown command, use \"serve\" or \"resolve\"")
    }
  
    Ok(())
}

fn serve(args: &Vec<String>){
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

