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

use dns;
use std::{env, error::Error};

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
        RESOLVE_COMMAND => dns::visually_resolve(&args),
        SERVE_COMMAND => dns::serve(&args),
        _ => panic!("unknown command, use \"serve\" or \"resolve\""),
    }

    Ok(())
}
