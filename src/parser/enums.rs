use super::{buffer::ByteBuffer, DNSName};
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::{error::Error, fmt, str::FromStr};

// Query: A standard query. (OPCODE 0)
// IQUERY: An inverse query. (OPCODE 1)
// STATUS: A server status request. (OPCODE 2)
// RESERVED: Reserved/not used. (OPCODE 3)
// NOTIFY: Used by primary server to notify secondary server that data for a zone has changed and request a zone transfer. (OPCODE 4)
// UPDATE: A special message type to implement dynamic DNS. Allows resource records to be added, deleted, or updated selectively. (OPCODE 5)
// DNS State Operations (DSO): Used to communicate operations within persistent stateful sessions. (OPCODE 6)
// OPCODES 7-15: Unassigned.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OpCode {
    Query,
    IQuery,
    Status,
    Reserved,
    Notify,
    Update,
    DSO,
    Unassigned,
}

impl TryFrom<u8> for OpCode {
    type Error = String;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(OpCode::Query),
            1 => Ok(OpCode::IQuery),
            2 => Ok(OpCode::Status),
            3 => Ok(OpCode::Reserved),
            4 => Ok(OpCode::Notify),
            5 => Ok(OpCode::Update),
            6 => Ok(OpCode::DSO),
            _ => Err(OpCode::Unassigned.to_string()),
        }
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DNSRecordType {
    // A (address) records are one of the most basic and commonly used DNS record types.
    // They translate domain names and store them as IP addresses. A records can only hold IPv4 addresses.
    A = 1,
    // An NS (nameserver) record indicates which server contains the DNS records for a given
    // domain. Domains usually have several NS records pointing to primary and backup nameservers for that domain.
    NS = 2,
    // CNAME (canonical name) record is used instead of an A record if a domain is an alias
    // for another domain. Because of this, all CNAME records point to a domain instead of
    // an IP address.
    CNAME = 5,
    // MX (mail exchange) records store instructions for directing emails to mail servers following
    // the SMTP protocol.
    MX = 15,
    // AAAA records work the same as A records in that they store IP addresses connected to domain names.
    // The only difference is that AAAA records hold IPv6 addresses.
    AAAA = 28,
    // This is a pseudo-record type needed to support EDNS.
    OPT = 41,
    Unknown,
}

impl fmt::Display for DNSRecordType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u16> for DNSRecordType {
    type Error = String;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(DNSRecordType::A),
            2 => Ok(DNSRecordType::NS),
            5 => Ok(DNSRecordType::CNAME),
            15 => Ok(DNSRecordType::MX),
            28 => Ok(DNSRecordType::AAAA),
            41 => Ok(DNSRecordType::OPT),
            _ => {
                println!("unknown DNS record type: {}", v);
                Ok(DNSRecordType::Unknown) //Err(format!("unexpected DNS record type: {v}")),
            }
        }
    }
}

// Set to FALSE or 0 in queries. This field indicates if the query was answered successfully or if an error occured.
// No Error: No error occured. (RCODE 0)
// Format Error: Server unable to respond due to a problem with how the query was constructed. (RCODE 1)
// Server Failure: Server was unable to respond to the query due to an issue with the server itself. (RCODE 2)
// Name Error: The name specified in the query does not exist in the domain. (RCODE 3)
// Not Implemented: The type of query received is not supported by the sever. (RCODE 4)
// Refused: Server refused to process query. (RCODE 5)
// YX Domain: A name exists when it should not. (RCODE 6)
// YX RR Set: A resource record set exists that should not. (RCODE 7)
// NX RR Set: A resource record set that should exist but does not. (RCODE 8)
// Not Auth: The server receiving the query is not authoritative for the zone specified. (RCODE 9)
// Not Zone: A name specified in the message is not within the zone specified in the message. (RCODE 10)
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ErrorCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    YXDomain,
    YxRrSet,
    NxRrSet,
    NotAuth,
    NotZone,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u8> for ErrorCode {
    type Error = String;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(ErrorCode::NoError),
            1 => Ok(ErrorCode::FormatError),
            2 => Ok(ErrorCode::ServerFailure),
            3 => Ok(ErrorCode::NameError),
            4 => Ok(ErrorCode::NotImplemented),
            5 => Ok(ErrorCode::Refused),
            6 => Ok(ErrorCode::YXDomain),
            7 => Ok(ErrorCode::YxRrSet),
            8 => Ok(ErrorCode::NxRrSet),
            9 => Ok(ErrorCode::YxRrSet),
            10 => Ok(ErrorCode::NotAuth),
            11 => Ok(ErrorCode::NotZone),
            _ => Err("unexpected error code".to_string()),
        }
    }
}

// IN            1 the Internet
// CS            2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
// CH            3 the CHAOS class
// HS            4 Hesiod [Dyer 87]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DNSRecordClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    Unknown,
}

impl fmt::Display for DNSRecordClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseDNSTypeError;

impl FromStr for DNSRecordType {
    type Err = ParseDNSTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let record_type = match s {
            "A" => DNSRecordType::A,
            "NS" => DNSRecordType::NS,
            "CNAME" => DNSRecordType::CNAME,
            "MX" => DNSRecordType::MX,
            "AAAA" => DNSRecordType::AAAA,
            _ => DNSRecordType::Unknown,
        };

        Ok(record_type)
    }
}

impl TryFrom<u16> for DNSRecordClass {
    type Error = String;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(DNSRecordClass::IN),
            2 => Ok(DNSRecordClass::CS),
            3 => Ok(DNSRecordClass::CH),
            4 => Ok(DNSRecordClass::HS),
            _ => Ok(DNSRecordClass::Unknown),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum DNSRecord {
    A {
        len: u16,
        ip: Ipv4Addr,
    },
    NS {
        len: u16,
        name_server: String,
    },
    CNAME {
        len: u16,
        cname: String,
    },
    MX {
        len: u16,
        priority: u16,
        host: String,
    },
    AAAA {
        len: u16,
        ip: Ipv6Addr,
    },
    Opt {
        len: u16,
        data: String,
    },
    Unknown,
}

impl DNSRecord {
    pub fn from_bytes(
        bytes: &mut ByteBuffer,
        record_type: DNSRecordType,
    ) -> Result<DNSRecord, Box<dyn Error>> {
        match record_type {
            DNSRecordType::A => Ok(DNSRecord::A {
                len: bytes.get_u16()?,
                ip: Ipv4Addr::new(
                    bytes.get_u8()?,
                    bytes.get_u8()?,
                    bytes.get_u8()?,
                    bytes.get_u8()?,
                ),
            }),
            DNSRecordType::CNAME => {
                let name_length = bytes.get_u16()?;
                let name = super::DNSName::read_name(bytes)?;

                Ok(DNSRecord::CNAME {
                    len: name_length,
                    cname: name.value,
                })
            }
            DNSRecordType::NS => {
                let name_length = bytes.get_u16()?;
                let name = super::DNSName::read_name(bytes)?;

                Ok(DNSRecord::NS {
                    len: name_length,
                    name_server: name.value,
                })
            }

            DNSRecordType::AAAA => Ok(DNSRecord::AAAA {
                len: bytes.get_u16()?,

                ip: Ipv6Addr::new(
                    bytes.get_u16()?,
                    bytes.get_u16()?,
                    bytes.get_u16()?,
                    bytes.get_u16()?,
                    bytes.get_u16()?,
                    bytes.get_u16()?,
                    bytes.get_u16()?,
                    bytes.get_u16()?,
                ),
            }),

            DNSRecordType::MX => {
                let name_length = bytes.get_u16()?;
                let priority = bytes.get_u16()?;
                let host_name = super::DNSName::read_name(bytes)?;

                Ok(DNSRecord::MX {
                    len: name_length,
                    priority: priority,
                    host: host_name.value,
                })
            }

            DNSRecordType::OPT => {
                let data_length = bytes.get_u16()?;
                if data_length == 0 {
                    return Ok(DNSRecord::Opt {
                        len: data_length,
                        data: "".to_string(),
                    });
                }
                let name = super::DNSName::read_name(bytes)?;

                Ok(DNSRecord::Opt {
                    len: data_length,
                    data: name.value,
                })
            }

            _ => Ok(DNSRecord::Unknown),
        }
    }

    pub fn to_bytes(
        &self,
        bytes: &mut ByteBuffer,
        base_name: &DNSName,
    ) -> Result<(), Box<dyn Error>> {
        match self {
            DNSRecord::A { len, ip } => {
                bytes.write_u16(*len);
                ip.octets().iter().for_each(|o| bytes.write_u8(*o));

                Ok(())
            }

            DNSRecord::CNAME { len, cname } => {
                if cname.ends_with(&base_name.value) {
                    bytes.write_u16(*len);
                } else {
                    bytes.write_u16((cname.len() + 2) as u16);
                }

                let mut name = DNSName {
                    value: cname.to_string(),
                    offset: bytes.get_offset() as u16,
                };

                name.write_name(bytes, base_name)?;

                Ok(())
            }

            DNSRecord::NS { len, name_server } => {
                if name_server.ends_with(&base_name.value) {
                    bytes.write_u16(*len);
                } else {
                    bytes.write_u16((name_server.len() + 2) as u16);
                }

                let mut name = DNSName {
                    value: name_server.to_string(),
                    offset: bytes.get_offset() as u16,
                };

                name.write_name(bytes, base_name)?;

                Ok(())
            }

            DNSRecord::MX {
                len,
                priority,
                host,
            } => {
                bytes.write_u16(*len);
                bytes.write_u16(*priority);

                let mut name = DNSName {
                    value: host.to_string(),
                    offset: bytes.get_offset() as u16,
                };

                name.write_name(bytes, base_name)?;

                Ok(())
            }

            DNSRecord::AAAA { len, ip } => {
                bytes.write_u16(*len);

                ip.octets().into_iter().for_each(|b| bytes.write_u8(b));

                Ok(())
            }

            DNSRecord::Opt { len, data } => {
                bytes.write_u16(*len);

                if *len == 0 {
                    return Ok(());
                }

                let mut name = DNSName {
                    value: data.to_string(),
                    offset: bytes.get_offset() as u16,
                };

                name.write_name(bytes, base_name)?;

                Ok(())
            }

            _ => Ok(()),
        }
    }
}
