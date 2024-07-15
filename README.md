
# DNS Protocol Implementation (with client/server features) in Rust

## Overview
This repository contains an implementation of the DNS (Domain Name System) protocol in Rust. It includes both client and server components, demonstrating the ability to handle DNS queries and responses effectively.

## Features
- **DNS Client**: Sends DNS queries to specified DNS servers and processes the responses. Application implements protocol from scratch.
- **DNS Server**: Receives DNS queries and sends appropriate responses based on the implementation.
- **Rust Implementation**: Utilizes the power and safety features of the Rust programming language.

## Project Structure
- **src/**: Contains the main source code for the DNS protocol implementation. Where `parser` package is responsible for encoding/decoding binary DNS messages.
- **test_files/**: Includes various test files to validate the functionality of the DNS client and server. Contains `.hex` files with DNS messages examples.
- **Cargo.toml**: Configuration file for the Rust project.

## Getting Started

### Prerequisites
Ensure you have Rust installed on your system. You can install Rust using [rustup](https://rustup.rs/).

### Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/bkatrenko/dns.git
   cd dns
   ```
2. Build the project:
   ```sh
   cargo build
   ```

### Usage
1. **Use visual resolve (similar to `dig` with trace):**
   ```sh
   cargo run resolve google.com A
   ```
   Some variant of expected output:
   ```sh
   INFO id: RnFGctJ-Q8kSraZZb8o39, message id: 34422, start recursive resolution, questions: 1
   INFO id: RnFGctJ-Q8kSraZZb8o39, message id: 34422, root server resolution: google.com, record type: A, record class: IN
   INTO id: RnFGctJ-Q8kSraZZb8o39, resolve google.com with NS address: 170.247.170.2
   INTO id: RnFGctJ-Q8kSraZZb8o39, resolve google.com with NS address: 192.5.6.30
   INTO id: RnFGctJ-Q8kSraZZb8o39, resolve google.com with NS address: 216.239.38.10
   >>>>>>>>>>>> got results: <<<<<<<<<<<<<
   message id: 34422
   is query: false
   operation code: Query
   authoritative answer: true
   truncated: false
   recursion desired: false
   recursion available: false
   error code: NoError
   questions: 1
   answers: 1
   resources: 0
   additional: 0

   responses:
   google.com class: IN ttl: 300 data: A { len: 4, ip: 142.251.209.142 }
   duration: 238.533235ms
   ```
2. **Use DNS UDP server mode:**
   ```sh
   cargo run serve 58980
   ```
   Where 58980 is a port number (choose any if you want).
   Expected output:
   ```sh
   create the resolver instance on port :58980
   local DNS server started
   ```
   To try it out you could use `dig` itself:
   ```sh
   dig -p 58980 @127.0.0.1 facebook.com
   ```
   And you will have a proper response:
   ```sh
   ; <<>> DiG 9.10.6 <<>> -p 58980 @127.0.0.1 facebook.com
   ; (1 server found)
   ;; global options: +cmd
   ;; Got answer:
   ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15200
   ;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

   ;; QUESTION SECTION:
   ;facebook.com.                  IN      A

   ;; ANSWER SECTION:
   facebook.com.           60      IN      A       185.60.217.35

   ;; Query time: 81 msec
   ;; SERVER: 127.0.0.1#58980(127.0.0.1)
   ;; WHEN: Mon Jul 15 14:31:58 CEST 2024
   ;; MSG SIZE  rcvd: 46
   ```

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements
- Special thanks to the Rust community for their invaluable resources and support.
- The repository is mostly made for run & education. Since I mostly work with JSON/gRPC/REST etc. high level things, the intention was to deep inside some unusual things. Not every day we write some DNS servers, isn't it? `:P`
