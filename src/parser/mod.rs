use std::fmt;
use std::{error::Error, path::Display};

pub mod buffer;
pub mod enums;

#[derive(Debug)]
pub struct DNSPacket {
    buf: buffer::ByteBuffer,

    pub header: DNSPacketHeader,
    pub question_part: Vec<DNSQuestionPart>,
    pub response_part: Vec<DNSResponsePart>,
    pub authorities: Vec<DNSResponsePart>,
    pub resources: Vec<DNSResponsePart>,
}

impl DNSPacket {
    pub fn default() -> DNSPacket {
        DNSPacket {
            buf: buffer::ByteBuffer::new(),
            header: DNSPacketHeader::default(),
            question_part: Vec::<DNSQuestionPart>::new(),
            response_part: Vec::<DNSResponsePart>::new(),
            authorities: Vec::<DNSResponsePart>::new(),
            resources: Vec::<DNSResponsePart>::new(),
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<DNSPacket, Box<dyn Error>> {
        let mut buffer = buffer::ByteBuffer::from_bytes_vec(bytes);

        let header: DNSPacketHeader = DNSPacketHeader::from_bytes(&mut buffer)?;

        let questions: Vec<DNSQuestionPart> =
            DNSQuestionPart::read_questions(&mut buffer, header.qd_count)?;
        let responses: Vec<DNSResponsePart> =
            DNSResponsePart::read_responses(&mut buffer, header.an_count)?;
        let authorities: Vec<DNSResponsePart> =
            DNSResponsePart::read_authorities(&mut buffer, header.ns_count)?;
        let resources: Vec<DNSResponsePart> =
            DNSResponsePart::read_resources(&mut buffer, header.ar_count)?;

        Ok(DNSPacket {
            buf: buffer,
            header: header,
            question_part: questions,
            response_part: responses,
            authorities: authorities,
            resources: resources,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut res = Vec::<u8>::new();

        let mut header_bytes = self.header.to_bytes()?;
        res.append(&mut header_bytes);

        for q in &self.question_part {
            let mut question_bytes = q.to_bytes()?;
            res.append(&mut question_bytes);
        }

        for r in &self.response_part {
            let mut response_bytes = r.to_bytes()?;
            res.append(&mut response_bytes)
        }

        for r in &self.authorities {
            let mut response_bytes = r.to_bytes()?;
            res.append(&mut response_bytes)
        }

        for r in &self.resources {
            let mut response_bytes = r.to_bytes()?;
            res.append(&mut response_bytes)
        }

        Ok(res)
    }
}

impl PartialEq for DNSPacket {
    fn eq(&self, other: &DNSPacket) -> bool {
        // header
        if !self.header.id == other.header.id
            && self.header.is_query == other.header.is_query
            && self.header.op_code == other.header.op_code
            && self.header.authoritative_answer_flag == other.header.authoritative_answer_flag
            && self.header.truncate_flag == other.header.truncate_flag
            && self.header.recursion_desired == other.header.recursion_desired
            && self.header.recursion_available == other.header.recursion_available
            && self.header.zero == other.header.zero
            && self.header.error_code == other.header.error_code
            && self.header.qd_count == other.header.qd_count
            && self.header.an_count == other.header.an_count
            && self.header.ns_count == other.header.ns_count
            && self.header.ar_count == other.header.ar_count
        {
            return false;
        };
        // questions
        for (i, question) in self.question_part.iter().enumerate() {
            if !question
                .question_name
                .eq(&other.question_part.get(i).unwrap().question_name)
                && question.dns_record_type == other.question_part.get(i).unwrap().dns_record_type
                && question.dns_record_class == other.question_part.get(i).unwrap().dns_record_class
            {
                return false;
            }
        }

        // responses
        let compare_response = |current: &DNSResponsePart, other: &DNSResponsePart| -> bool {
            return current.name.eq(&other.name)
                && current.record_type == other.record_type
                && current.record_class == other.record_class
                && current.data.eq(&other.data);
        };

        for (i, response) in self.response_part.iter().enumerate() {
            if !compare_response(&response, other.response_part.get(i).unwrap()) {
                return false;
            }
        }

        // authorities
        for (i, response) in self.authorities.iter().enumerate() {
            if !compare_response(&response, other.authorities.get(i).unwrap()) {
                return false;
            }
        }

        // resources
        for (i, response) in self.resources.iter().enumerate() {
            if !compare_response(&response, other.resources.get(i).unwrap()) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct DNSPacketHeader {
    // Identifier: An identification field generated by the devices that creates the DNS query.
    // The ID field is used to match responses with queries.
    pub id: u16,
    // Query/Response Flag: Differentiates between a query (0) or a reply (1).
    pub is_query: bool,
    // Kind of the operation
    pub op_code: enums::OpCode,
    // Set to TRUE or 1 if the DNS server that created the response is authoritative for the queried hostname.
    pub authoritative_answer_flag: bool,
    // Set to TRUE or 1 if the message was truncated due to excessive length.
    // UDP messages are limited to 512 bytes while TCP does not have a length limit for messages.
    pub truncate_flag: bool,
    // When set to TRUE or 1, requests the server receiving the DNS query to answer the query recursively.
    pub recursion_desired: bool,
    // Recursion Available: When set to TRUE or 1 in a response, indicates that the replying DNS server supports recursion.
    pub recursion_available: bool,
    // reserved field (guys who did that have an experience, so, they failed (*_*) sometime, hah?
    pub zero: Option<u8>,
    // Response error code.
    pub error_code: enums::ErrorCode,
    // Question Count: Specifies the number of questions in the Question section of the message.
    pub qd_count: u16,
    // Answer Record Count: Specifies the number of resource records in the Answer section of the message.
    pub an_count: u16,
    // Authority Record Count: Specifies the number of resource records in the Authority section of the message.
    pub ns_count: u16,
    // Additional Record Count: Specifies the number of resource records in the Additional section of the message.
    pub ar_count: u16,
}

impl fmt::Display for DNSPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "header: {:?} questions: {:?} responses: {:?}, authorities: {:?}, resources: {:?}",
            self.header, self.question_part, self.response_part, self.authorities, self.resources
        )
    }
}

impl DNSPacketHeader {
    pub fn default() -> DNSPacketHeader {
        DNSPacketHeader {
            id: 0,
            is_query: false,
            op_code: enums::OpCode::Query,
            authoritative_answer_flag: false,
            truncate_flag: false,
            recursion_desired: false,
            recursion_available: false,
            zero: None,
            error_code: enums::ErrorCode::NoError,
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    pub fn from_bytes(bytes: &mut buffer::ByteBuffer) -> Result<DNSPacketHeader, Box<dyn Error>> {
        let mut header = DNSPacketHeader::default();

        header.id = bytes.get_u16()?;

        let flags_bit = bytes.get_u8()?;

        header.is_query = flags_bit & 0x80 == 0;
        header.op_code = (mask(3, 7) & flags_bit).try_into().unwrap();
        header.authoritative_answer_flag = flags_bit & 0x4 != 0;
        header.truncate_flag = flags_bit & 0x2 != 0;
        header.recursion_desired = flags_bit & 0x1 != 0;

        let recursion_bit = bytes.get_u8()?;

        header.recursion_available = recursion_bit & 0x80 != 0;

        if (recursion_bit & 0x20) != 0 {
            header.zero = Option::Some(recursion_bit & 0x20);
        }

        header.error_code = (mask(0, 4) & recursion_bit).try_into()?;

        header.qd_count = bytes.get_u16()?;
        header.an_count = bytes.get_u16()?;
        header.ns_count = bytes.get_u16()?;
        header.ar_count = bytes.get_u16()?;

        Ok(header)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut bytes = buffer::ByteBuffer::new();

        bytes.write_u16(self.id);

        let mut flags_bit: u8 = 0;
        flags_bit = flags_bit | ((!self.is_query as u8) << 7);
        flags_bit = flags_bit | ((self.op_code as u8) << 3);
        flags_bit = flags_bit | ((self.authoritative_answer_flag as u8) << 2);
        flags_bit = flags_bit | ((self.truncate_flag as u8) << 1);
        flags_bit = flags_bit | (self.recursion_desired as u8);
        bytes.write_u8(flags_bit);

        let mut recursion_bit: u8 = 0;
        recursion_bit = recursion_bit | ((self.recursion_available as u8) << 7);
        if self.zero.is_some() {
            recursion_bit = recursion_bit | 0x20; // Z/DNSSec
        }

        recursion_bit = recursion_bit | self.error_code as u8;
        bytes.write_u8(recursion_bit);

        bytes.write_u16(self.qd_count);
        bytes.write_u16(self.an_count);
        bytes.write_u16(self.ns_count);
        bytes.write_u16(self.ar_count);

        Ok(bytes.get_vec())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DNSQuestionPart {
    pub buffer_offset: usize,
    pub question_name: String,
    pub dns_record_type: enums::DNSRecordType,
    pub dns_record_class: enums::DNSRecordClass,
}

impl DNSQuestionPart {
    fn read_questions(
        bytes: &mut buffer::ByteBuffer,
        questions_count: u16,
    ) -> Result<Vec<DNSQuestionPart>, Box<dyn Error>> {
        let mut questions: Vec<DNSQuestionPart> = Vec::new();

        for _ in 0..questions_count {
            let offset = bytes.get_offset();
            let res = DNSName::read_name_value(bytes);

            let dns_record_type: enums::DNSRecordType = bytes.get_u16()?.try_into()?;

            match dns_record_type {
                enums::DNSRecordType::A
                | enums::DNSRecordType::CNAME
                | enums::DNSRecordType::NS
                | enums::DNSRecordType::AAAA
                | enums::DNSRecordType::MX
                | enums::DNSRecordType::TXT => {
                    let dns_record_class: enums::DNSRecordClass = bytes.get_u16()?.try_into()?;
                    questions.push(DNSQuestionPart {
                        buffer_offset: offset,
                        question_name: res?,
                        dns_record_type: dns_record_type,
                        dns_record_class: dns_record_class.try_into()?,
                    });
                }

                enums::DNSRecordType::OPT => {}
                enums::DNSRecordType::Unknown => {}
            }
        }

        return Ok(questions);
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut bytes = buffer::ByteBuffer::new();

        let splitted_name = self.question_name.split(".");

        splitted_name.for_each(|ch| {
            bytes.write_u8(ch.len() as u8);
            ch.to_ascii_lowercase()
                .as_bytes()
                .iter()
                .for_each(|b| bytes.write_u8(*b))
        });

        bytes.write_u8(0);
        bytes.write_u16(self.dns_record_type as u16);
        bytes.write_u16(self.dns_record_class as u16);

        Ok(bytes.get_vec())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DNSResponsePart {
    pub name: DNSName,
    pub record_type: enums::DNSRecordType,
    pub record_class: enums::DNSRecordClass,
    pub udp_length: u16,
    pub ttl: u32,
    pub data: enums::DNSRecord,
}

impl fmt::Display for DNSResponsePart {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //write!(f, "\x1b[32maddress: {}\x1b[0m\n", self.name.value)?;
        write!(
            f,
            "\x1b[32m{} class: {} ttl: {} data: {:?}\x1b[0m",
            self.name.value,
            self.record_class.to_string(),
            self.ttl,
            self.data
        )
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DNSName {
    pub value: String,
    pub offset: u16,
}

impl DNSName {
    fn default() -> DNSName {
        DNSName {
            value: String::new(),
            offset: 0,
        }
    }

    fn write_name(
        &mut self,
        bytes: &mut buffer::ByteBuffer,
        base_name: &DNSName,
    ) -> Result<(), Box<dyn Error>> {
        if self.value.ends_with(&base_name.value) {
            let stripped = self
                .value
                .strip_suffix(base_name.value.as_str())
                .unwrap()
                .to_string();

            stripped.split(".").for_each(|ch| {
                if ch == "" {
                    return;
                }

                bytes.write_u8(ch.len() as u8);
                ch.to_ascii_lowercase()
                    .as_bytes()
                    .iter()
                    .for_each(|b| bytes.write_u8(*b))
            });

            bytes.write_u8(0xc0);
            bytes.write_u8(base_name.offset as u8);

            return Ok(());
        }

        self.value.split(".").for_each(|ch| {
            bytes.write_u8(ch.len() as u8);
            ch.to_ascii_lowercase()
                .as_bytes()
                .iter()
                .for_each(|b| bytes.write_u8(*b))
        });

        bytes.write_u8(0);

        Ok(())
    }

    fn read_string(bytes: &mut buffer::ByteBuffer) -> Result<DNSName, Box<dyn Error>> {
        let mut name = DNSName::default();
        let initial_offset = bytes.get_offset();

        loop {
            let offset_byte = bytes.get_u8()?;

            if offset_byte == 0 {
                return Ok(name);
            }

            if (offset_byte & 0xc0) == 0xc0 {
                let new_position = (((offset_byte as u16) ^ 0xC0) << 8) | bytes.get_u8()? as u16;
                name.offset = new_position; //initial_offset as u16;

                let current_offset = bytes.get_offset();

                bytes.set_offset(new_position as usize)?;
                name.value
                    .push_str(Self::read_string(bytes)?.value.as_str());

                match bytes.set_offset(current_offset) {
                    Ok(_) => print!(""),
                    Err(e) => {
                        if current_offset == bytes.get_vec().len() {
                            println!("DEBUG: reached end of the buffer while read the name: {current_offset}: {}", 
                            bytes.get_vec().len())
                        } else {
                            panic!(
                                "error while read the name: {}, offset: {}, buffer len: {}",
                                e, current_offset, initial_offset
                            )
                        }
                    }
                };

                return Ok(name);
            } else {
                for _ in 0..offset_byte {
                    name.value
                        .push_str(&String::from_utf8_lossy(&[bytes.get_u8()?]).to_lowercase());
                }

                if bytes.get_byte_at(bytes.get_offset())? != 0 {
                    name.value.push_str(".");
                }

                name.offset = initial_offset as u16;
            }
        }
    }

    fn read_name_value(bytes: &mut buffer::ByteBuffer) -> Result<String, Box<dyn Error>> {
        let mut res: String = "".to_string();

        loop {
            let byte: u8 = bytes.get_u8()?;

            if byte == 0 {
                return Ok(res);
            }

            for _ in 0..byte {
                res.push_str(&String::from_utf8_lossy(&[bytes.get_u8()?]).to_lowercase());
            }

            if bytes.get_byte_at(bytes.get_offset() + 1)? != 0 {
                res.push_str(".");
            }
        }
    }

    fn read_text_label(bytes: &mut buffer::ByteBuffer) -> Result<String, Box<dyn Error>> {
        let mut res: String = "".to_string();

        let byte: u8 = bytes.get_u8()?;

        if byte == 0 {
            return Ok(res);
        }

        for _ in 0..byte {
            res.push_str(&String::from_utf8_lossy(&[bytes.get_u8()?]));
        }

        return Ok(res);
    }
}

impl DNSResponsePart {
    fn default() -> DNSResponsePart {
        DNSResponsePart {
            name: DNSName::default(),
            record_type: enums::DNSRecordType::A,
            record_class: enums::DNSRecordClass::IN,
            udp_length: 0,
            ttl: 0,
            data: enums::DNSRecord::Unknown,
        }
    }

    fn read_responses(
        bytes: &mut buffer::ByteBuffer,
        responses_count: u16,
    ) -> Result<Vec<DNSResponsePart>, Box<dyn Error>> {
        let mut res: Vec<DNSResponsePart> = vec![];

        for _ in 0..responses_count {
            let mut response: DNSResponsePart = DNSResponsePart::default();

            response.name = DNSName::read_string(bytes)?;
            response.record_type = bytes.get_u16()?.try_into()?;

            response.record_class = bytes.get_u16()?.try_into()?;

            response.ttl = bytes.get_u32()?;
            response.data = enums::DNSRecord::from_bytes(bytes, response.record_type)?;

            res.push(response)
        }

        return Ok(res);
    }

    fn read_authorities(
        bytes: &mut buffer::ByteBuffer,
        authorities_count: u16,
    ) -> Result<Vec<DNSResponsePart>, Box<dyn Error>> {
        let mut res: Vec<DNSResponsePart> = vec![];

        for _ in 0..authorities_count {
            let mut response: DNSResponsePart = DNSResponsePart::default();

            response.name = DNSName::read_string(bytes)?;
            response.record_type = bytes.get_u16()?.try_into()?;
            response.record_class = bytes.get_u16()?.try_into()?;

            response.ttl = bytes.get_u32()?;
            response.data = enums::DNSRecord::from_bytes(bytes, response.record_type)?;

            res.push(response)
        }

        return Ok(res);
    }

    fn read_resources(
        bytes: &mut buffer::ByteBuffer,
        resources_count: u16,
    ) -> Result<Vec<DNSResponsePart>, Box<dyn Error>> {
        let mut res: Vec<DNSResponsePart> = vec![];

        for _ in 0..resources_count {
            let mut response: DNSResponsePart = DNSResponsePart::default();

            response.name = DNSName::read_string(bytes)?;
            response.record_type = bytes.get_u16()?.try_into()?;

            match response.record_type {
                enums::DNSRecordType::A
                | enums::DNSRecordType::CNAME
                | enums::DNSRecordType::NS
                | enums::DNSRecordType::AAAA
                | enums::DNSRecordType::MX => {
                    response.record_class = bytes.get_u16()?.try_into()?;

                    response.ttl = bytes.get_u32()?;
                    response.data = enums::DNSRecord::from_bytes(bytes, response.record_type)?;

                    res.push(response)
                }

                enums::DNSRecordType::OPT | enums::DNSRecordType::TXT => {
                    response.udp_length = bytes.get_u16()?;
                    response.ttl = bytes.get_u32()?;
                    response.data = enums::DNSRecord::from_bytes(bytes, response.record_type)?;

                    res.push(response)
                }

                enums::DNSRecordType::Unknown => {}
            }
        }

        return Ok(res);
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buffer = buffer::ByteBuffer::new();

        match self.record_type {
            enums::DNSRecordType::A
            | enums::DNSRecordType::CNAME
            | enums::DNSRecordType::NS
            | enums::DNSRecordType::AAAA
            | enums::DNSRecordType::MX => {
                let mut jump_position: u16 = self.name.offset as u16;
                let mut jump_position_bytes = jump_position.to_be_bytes();
                jump_position_bytes[0] = jump_position_bytes[0] | 0xc0;
                jump_position = u16::from_be_bytes(jump_position_bytes);

                buffer.write_u16(jump_position);
                buffer.write_u16(self.record_type as u16);
                buffer.write_u16(self.record_class as u16);
                buffer.write_u32(self.ttl);

                self.data.to_bytes(&mut buffer, &self.name)?;

                Ok(buffer.get_vec())
            }

            enums::DNSRecordType::OPT | enums::DNSRecordType::TXT => {
                buffer.write_u8(0);
                buffer.write_u16(self.record_type as u16);
                buffer.write_u16(self.udp_length as u16);
                buffer.write_u32(self.ttl);

                self.data.to_bytes(&mut buffer, &self.name)?;

                Ok(buffer.get_vec())
            }

            enums::DNSRecordType::Unknown => Ok(buffer.get_vec()),
        }
    }
}

fn mask(from: u8, to: u8) -> u8 {
    let mut r: u8 = 0;

    for i in from..to {
        r |= 1 << i;
    }

    return r;
}

#[cfg(test)]
mod tests {
    use super::{DNSPacket, DNSPacketHeader, DNSQuestionPart, DNSResponsePart};
    use crate::parser::enums::{DNSRecordClass, DNSRecordType, ErrorCode, OpCode};
    use crate::parser::{buffer::ByteBuffer, enums::DNSRecord};
    use std::{fs, net::Ipv4Addr};

    const QUERY_PACKET_PATH: &str = "test_files/query_packet.hex";
    const RESPONSE_PACKET_PATH: &str = "test_files/response_packet.hex";
    const MULTI_TYPE_RESPONSE_PACKET_PATH: &str = "test_files/multi_type_response.hex";
    const NS_RESPONSE_PACKET_PATH: &str = "test_files/ns_response_packet.hex";
    const MX_QUERY_PACKET_PATH: &str = "test_files/mx_query_packet.hex";
    const MX_RESPONSE_PACKET_PATH: &str = "test_files/mx_response_packet.hex";
    const AAAA_QUERY_PACKET_PATH: &str = "test_files/aaaa_query_packet.hex";
    const AAAA_RESPONSE_PACKET_PATH: &str = "test_files/aaaa_response_packet.hex";
    const TXT_RESPONSE_PACKET_PATH: &str = "test_files/txt_response_packet.hex";
    const MULTIPART_RESPONSE_PACKET_PATH: &str = "test_files/multipart_response.hex";

    #[test]
    fn parse_dns_packet_header_question() {
        let test_file_content = fs::read(QUERY_PACKET_PATH).unwrap();
        let header =
            DNSPacketHeader::from_bytes(&mut ByteBuffer::from_bytes_vec(test_file_content))
                .unwrap();

        println!("{:?}", header);

        assert_eq!(header.id, 65007);
        assert_eq!(header.is_query, true);
        assert_eq!(header.op_code, OpCode::Query);
        assert_eq!(header.authoritative_answer_flag, false);
        assert_eq!(header.truncate_flag, false);
        assert_eq!(header.recursion_desired, true);
        assert_eq!(header.recursion_available, false);
        assert_eq!(header.zero, Some(32));
        assert_eq!(header.error_code, ErrorCode::NoError);
        assert_eq!(header.qd_count, 1);
        assert_eq!(header.an_count, 0);
        assert_eq!(header.ns_count, 0);
        assert_eq!(header.ar_count, 0);

        header_to_bytes();
    }

    #[test]
    fn parse_dns_packet_header_response() {
        let test_file_content = fs::read(RESPONSE_PACKET_PATH).unwrap();
        let header =
            DNSPacketHeader::from_bytes(&mut ByteBuffer::from_bytes_vec(test_file_content))
                .unwrap();

        assert_eq!(header.id, 65007);
        assert_eq!(header.is_query, false);
        assert_eq!(header.op_code, OpCode::Query);
        assert_eq!(header.authoritative_answer_flag, false);
        assert_eq!(header.truncate_flag, false);
        assert_eq!(header.recursion_desired, true);
        assert_eq!(header.recursion_available, true);
        assert_eq!(header.zero, None);
        assert_eq!(header.error_code, ErrorCode::NoError);
        assert_eq!(header.qd_count, 1);
        assert_eq!(header.an_count, 1);
        assert_eq!(header.ns_count, 0);
        assert_eq!(header.ns_count, 0);
    }

    #[test]
    fn parse_dns_packet_question() {
        let test_file_content = fs::read(QUERY_PACKET_PATH).unwrap();
        let question_packet = DNSPacket::from_bytes(test_file_content).unwrap();

        assert_eq!(question_packet.header.id, 65007);
        assert_eq!(question_packet.header.is_query, true);
        assert_eq!(question_packet.header.op_code, OpCode::Query);
        assert_eq!(question_packet.header.authoritative_answer_flag, false);
        assert_eq!(question_packet.header.truncate_flag, false);
        assert_eq!(question_packet.header.recursion_desired, true);
        assert_eq!(question_packet.header.recursion_available, false);
        assert_eq!(question_packet.header.zero, Some(32));
        assert_eq!(question_packet.header.error_code, ErrorCode::NoError);
        assert_eq!(question_packet.header.qd_count, 1);
        assert_eq!(question_packet.header.an_count, 0);
        assert_eq!(question_packet.header.ns_count, 0);
        assert_eq!(question_packet.header.ns_count, 0);

        assert_eq!(question_packet.question_part[0].question_name, "google.com");
        assert_eq!(
            question_packet.question_part[0].dns_record_type,
            DNSRecordType::A
        );

        assert_eq!(
            question_packet.question_part[0].dns_record_class,
            DNSRecordClass::IN
        );

        println!("{:?}", question_packet)
    }

    #[test]
    fn parse_dns_packet_response_only() {
        let test_file_content = fs::read(RESPONSE_PACKET_PATH).unwrap();
        let mut bytes: ByteBuffer = ByteBuffer::from_bytes_vec(test_file_content);
        bytes.set_offset(28).unwrap();

        let responses = DNSResponsePart::read_responses(&mut bytes, 1).unwrap();
        let response = &responses[0];

        assert_eq!(response.name.value, "google.com");
        assert_eq!(response.record_type, DNSRecordType::A);
        assert_eq!(response.record_class, DNSRecordClass::IN);
        assert_eq!(response.ttl, 245);
        assert_eq!(
            response.data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(142, 250, 181, 206)
            }
        );

        println!("{:?}", responses)
    }

    #[test]
    fn parse_dns_packet_response() {
        let test_file_content = fs::read(RESPONSE_PACKET_PATH).unwrap();
        let question_packet = DNSPacket::from_bytes(test_file_content).unwrap();

        assert_eq!(question_packet.header.id, 65007);
        assert_eq!(question_packet.header.is_query, false);
        assert_eq!(question_packet.header.op_code, OpCode::Query);
        assert_eq!(question_packet.header.authoritative_answer_flag, false);
        assert_eq!(question_packet.header.truncate_flag, false);
        assert_eq!(question_packet.header.recursion_desired, true);
        assert_eq!(question_packet.header.recursion_available, true);
        assert_eq!(question_packet.header.zero, None);
        assert_eq!(question_packet.header.error_code, ErrorCode::NoError);
        assert_eq!(question_packet.header.qd_count, 1);
        assert_eq!(question_packet.header.an_count, 1);
        assert_eq!(question_packet.header.ns_count, 0);
        assert_eq!(question_packet.header.ns_count, 0);

        assert_eq!(question_packet.question_part[0].question_name, "google.com");
        assert_eq!(
            question_packet.question_part[0].dns_record_type,
            DNSRecordType::A
        );

        assert_eq!(
            question_packet.question_part[0].dns_record_class,
            DNSRecordClass::IN
        );

        println!("{:?}", question_packet)
    }

    #[test]
    fn header_to_bytes() {
        let mut header = DNSPacketHeader::default();
        header.id = 65007;
        header.is_query = true;
        header.authoritative_answer_flag = false;
        header.recursion_desired = true;
        header.op_code = OpCode::Query;
        header.qd_count = 1;

        let header_bytes = header.to_bytes().unwrap();
        let mut buffer = ByteBuffer::from_bytes_vec(header_bytes);

        let decoded_header = DNSPacketHeader::from_bytes(&mut buffer).unwrap();
        assert_eq!(header, decoded_header);
    }

    #[test]
    fn questions_to_bytes() {
        let question = DNSQuestionPart {
            buffer_offset: 0,
            question_name: String::from("google.com"),
            dns_record_class: DNSRecordClass::IN,
            dns_record_type: DNSRecordType::A,
        };

        let question_bytes = question.to_bytes().unwrap();
        let buffer = &mut ByteBuffer::from_bytes_vec(question_bytes);

        match DNSQuestionPart::read_questions(buffer, 1) {
            Ok(v) => assert_eq!(question, v[0]),
            Err(e) => panic!("{}", e),
        }
    }

    #[test]
    fn response_to_bytes() {
        let mut response = DNSResponsePart::default();
        response.name.offset = 12;
        response.record_type = DNSRecordType::A;
        response.record_class = DNSRecordClass::IN;
        response.ttl = 120;
        response.data = DNSRecord::A {
            len: 4,
            ip: Ipv4Addr::new(192, 168, 12, 31),
        };

        match response.to_bytes() {
            Ok(v) => {
                // assert bytes we have with expected data.
                // It's not very visually, but since we have no question part, is't the
                // only way.
                assert_eq!(
                    Vec::<u8>::from([192, 12, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 168, 12, 31]),
                    v
                )
            }
            Err(e) => panic!("{}", e),
        }
    }

    #[test]
    fn dns_packet_to_bytes() {
        let test_file_content = fs::read(RESPONSE_PACKET_PATH).unwrap();
        let response_packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();

        assert_eq!(test_file_content, response_packet.to_bytes().unwrap())
    }

    #[test]
    fn parse_ns_packet() {
        let test_file_content = fs::read(NS_RESPONSE_PACKET_PATH).unwrap();
        let response_packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();
        println!("{:?}", response_packet);

        let resp_bytes = response_packet.to_bytes().unwrap();
        let parsed_packet = DNSPacket::from_bytes(resp_bytes.clone()).unwrap();

        assert_eq!(test_file_content, resp_bytes);

        assert_eq!(response_packet.header.id, parsed_packet.header.id);
        assert_eq!(
            response_packet.header.is_query,
            parsed_packet.header.is_query
        );
        assert_eq!(response_packet.header.op_code, parsed_packet.header.op_code);
        assert_eq!(
            response_packet.header.authoritative_answer_flag,
            parsed_packet.header.authoritative_answer_flag
        );
        assert_eq!(
            response_packet.header.truncate_flag,
            parsed_packet.header.truncate_flag
        );
        assert_eq!(
            response_packet.header.recursion_desired,
            parsed_packet.header.recursion_desired
        );
        assert_eq!(response_packet.header.zero, parsed_packet.header.zero);
        assert_eq!(
            response_packet.header.error_code,
            parsed_packet.header.error_code
        );
        assert_eq!(
            response_packet.header.qd_count,
            parsed_packet.header.qd_count
        );
        assert_eq!(
            response_packet.header.an_count,
            parsed_packet.header.an_count
        );
        assert_eq!(
            response_packet.header.ns_count,
            parsed_packet.header.ns_count
        );
        assert_eq!(
            response_packet.header.ar_count,
            parsed_packet.header.ar_count
        );

        assert_eq!(response_packet.question_part, parsed_packet.question_part);
        assert_eq!(response_packet.response_part, parsed_packet.response_part);
    }

    #[test]
    fn parse_multi_response_types_object() {
        let test_file_content = fs::read(MULTI_TYPE_RESPONSE_PACKET_PATH).unwrap();
        let response_packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();

        assert_eq!(response_packet.header.id, 6666);
        assert_eq!(response_packet.header.is_query, false);
        assert_eq!(response_packet.header.op_code, OpCode::Query);
        assert_eq!(response_packet.header.authoritative_answer_flag, false);
        assert_eq!(response_packet.header.truncate_flag, false);
        assert_eq!(response_packet.header.recursion_desired, true);
        assert_eq!(response_packet.header.recursion_available, true);
        assert_eq!(response_packet.header.zero, None);
        assert_eq!(response_packet.header.error_code, ErrorCode::NoError);
        assert_eq!(response_packet.header.qd_count, 1);
        assert_eq!(response_packet.header.an_count, 3);
        assert_eq!(response_packet.header.ns_count, 0);

        assert_eq!(response_packet.question_part.len(), 1);
        assert_eq!(
            response_packet.question_part[0].question_name,
            String::from("www.yahoo.com")
        );
        assert_eq!(
            response_packet.question_part[0].dns_record_type,
            DNSRecordType::A
        );
        assert_eq!(
            response_packet.question_part[0].dns_record_class,
            DNSRecordClass::IN
        );

        assert_eq!(response_packet.response_part.len(), 3);
        assert_eq!(
            response_packet.response_part[0].name.value,
            String::from("www.yahoo.com")
        );
        assert_eq!(response_packet.response_part[0].name.offset, 12);
        assert_eq!(
            response_packet.response_part[0].record_type,
            DNSRecordType::CNAME
        );
        assert_eq!(
            response_packet.response_part[0].record_class,
            DNSRecordClass::IN
        );
        assert_eq!(response_packet.response_part[0].ttl, 2);
        assert_eq!(
            response_packet.response_part[0].data,
            DNSRecord::CNAME {
                len: 20,
                cname: String::from("new-fp-shed.wg1.b.yahoo.com")
            }
        );

        assert_eq!(
            response_packet.response_part[1].name.value,
            String::from("new-fp-shed.wg1.b.yahoo.com")
        );
        assert_eq!(response_packet.response_part[1].name.offset, 43);
        assert_eq!(
            response_packet.response_part[1].record_type,
            DNSRecordType::A
        );
        assert_eq!(
            response_packet.response_part[1].record_class,
            DNSRecordClass::IN
        );
        assert_eq!(response_packet.response_part[1].ttl, 2);
        assert_eq!(
            response_packet.response_part[1].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(87, 248, 100, 216)
            }
        );

        assert_eq!(
            response_packet.response_part[2].name.value,
            String::from("new-fp-shed.wg1.b.yahoo.com")
        );
        assert_eq!(response_packet.response_part[2].name.offset, 43);
        assert_eq!(
            response_packet.response_part[2].record_type,
            DNSRecordType::A
        );
        assert_eq!(
            response_packet.response_part[2].record_class,
            DNSRecordClass::IN
        );
        assert_eq!(response_packet.response_part[2].ttl, 2);
        assert_eq!(
            response_packet.response_part[2].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(87, 248, 100, 215)
            }
        );

        println!("{:?}", response_packet);
    }

    #[test]
    fn write_multi_response_types_object() {
        let test_file_content = fs::read(MULTI_TYPE_RESPONSE_PACKET_PATH).unwrap();
        let response_packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();

        let resp_packet_bytes = response_packet.to_bytes().unwrap();

        //assert_eq!(test_file_content,  resp_packet_bytes);

        let response_packet = DNSPacket::from_bytes(resp_packet_bytes).unwrap();

        assert_eq!(response_packet.header.id, 6666);
        assert_eq!(response_packet.header.is_query, false);
        assert_eq!(response_packet.header.op_code, OpCode::Query);
        assert_eq!(response_packet.header.authoritative_answer_flag, false);
        assert_eq!(response_packet.header.truncate_flag, false);
        assert_eq!(response_packet.header.recursion_desired, true);
        assert_eq!(response_packet.header.recursion_available, true);
        assert_eq!(response_packet.header.zero, None);
        assert_eq!(response_packet.header.error_code, ErrorCode::NoError);
        assert_eq!(response_packet.header.qd_count, 1);
        assert_eq!(response_packet.header.an_count, 3);
        assert_eq!(response_packet.header.ns_count, 0);

        assert_eq!(response_packet.question_part.len(), 1);
        assert_eq!(
            response_packet.question_part[0].question_name,
            String::from("www.yahoo.com")
        );
        assert_eq!(
            response_packet.question_part[0].dns_record_type,
            DNSRecordType::A
        );
        assert_eq!(
            response_packet.question_part[0].dns_record_class,
            DNSRecordClass::IN
        );

        assert_eq!(response_packet.response_part.len(), 3);
        assert_eq!(
            response_packet.response_part[0].name.value,
            String::from("www.yahoo.com")
        );
        assert_eq!(response_packet.response_part[0].name.offset, 12);
        assert_eq!(
            response_packet.response_part[0].record_type,
            DNSRecordType::CNAME
        );
        assert_eq!(
            response_packet.response_part[0].record_class,
            DNSRecordClass::IN
        );
        assert_eq!(response_packet.response_part[0].ttl, 2);
        assert_eq!(
            response_packet.response_part[0].data,
            DNSRecord::CNAME {
                len: 29,
                cname: String::from("new-fp-shed.wg1.b.yahoo.com")
            }
        );

        assert_eq!(
            response_packet.response_part[1].name.value,
            String::from("new-fp-shed.wg1.b.yahoo.com")
        );
        assert_eq!(response_packet.response_part[1].name.offset, 43);
        assert_eq!(
            response_packet.response_part[1].record_type,
            DNSRecordType::A
        );
        assert_eq!(
            response_packet.response_part[1].record_class,
            DNSRecordClass::IN
        );
        assert_eq!(response_packet.response_part[1].ttl, 2);
        assert_eq!(
            response_packet.response_part[1].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(87, 248, 100, 216)
            }
        );

        assert_eq!(
            response_packet.response_part[2].name.value,
            String::from("new-fp-shed.wg1.b.yahoo.com")
        );
        assert_eq!(response_packet.response_part[2].name.offset, 43);
        assert_eq!(
            response_packet.response_part[2].record_type,
            DNSRecordType::A
        );
        assert_eq!(
            response_packet.response_part[2].record_class,
            DNSRecordClass::IN
        );
        assert_eq!(response_packet.response_part[2].ttl, 2);
        assert_eq!(
            response_packet.response_part[2].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(87, 248, 100, 215)
            }
        );
    }

    #[test]
    fn parse_mx_query_packet() {
        let test_file_content = fs::read(MX_QUERY_PACKET_PATH).unwrap();
        let packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();

        assert_eq!(packet.header.id, 43242);
        assert_eq!(packet.header.is_query, true);
        assert_eq!(packet.header.op_code, OpCode::Query);
        assert_eq!(packet.header.authoritative_answer_flag, false);
        assert_eq!(packet.header.truncate_flag, false);
        assert_eq!(packet.header.recursion_desired, true);
        assert_eq!(packet.header.recursion_available, false);
        assert_eq!(packet.header.zero, Some(32));
        assert_eq!(packet.header.error_code, ErrorCode::NoError);
        assert_eq!(packet.header.qd_count, 1);
        assert_eq!(packet.header.an_count, 0);
        assert_eq!(packet.header.ns_count, 0);

        assert_eq!(packet.question_part[0].buffer_offset, 12);
        assert_eq!(
            packet.question_part[0].question_name,
            "google.com".to_string()
        );
        assert_eq!(packet.question_part[0].dns_record_class, DNSRecordClass::IN);
        assert_eq!(packet.question_part[0].dns_record_type, DNSRecordType::MX);

        let packet_bytes = packet.to_bytes().unwrap();
        assert_eq!(test_file_content, packet_bytes);
    }

    #[test]
    fn parse_mx_response_packet() {
        let test_file_content = fs::read(MX_RESPONSE_PACKET_PATH).unwrap();
        let packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();
        println!("{:?}", packet);

        let packet_bytes = packet.to_bytes().unwrap();
        assert_eq!(test_file_content, packet_bytes);
    }

    #[test]
    fn parse_aaaa_query_packet() {
        let test_file_content = fs::read(AAAA_QUERY_PACKET_PATH).unwrap();
        let packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();

        println!("{:?}", packet);

        assert_eq!(packet.header.id, 29523);
        assert_eq!(packet.header.is_query, true);
        assert_eq!(packet.header.op_code, OpCode::Query);
        assert_eq!(packet.header.authoritative_answer_flag, false);
        assert_eq!(packet.header.truncate_flag, false);
        assert_eq!(packet.header.recursion_desired, true);
        assert_eq!(packet.header.recursion_available, false);
        assert_eq!(packet.header.zero, Some(32));
        assert_eq!(packet.header.error_code, ErrorCode::NoError);
        assert_eq!(packet.header.qd_count, 1);
        assert_eq!(packet.header.an_count, 0);
        assert_eq!(packet.header.ns_count, 0);

        assert_eq!(packet.question_part[0].buffer_offset, 12);
        assert_eq!(packet.question_part[0].question_name, "google.com");
        assert_eq!(packet.question_part[0].dns_record_type, DNSRecordType::AAAA);
        assert_eq!(packet.question_part[0].dns_record_class, DNSRecordClass::IN);

        let packer_bytes = packet.to_bytes().unwrap();
        assert_eq!(test_file_content, packer_bytes)
    }

    #[test]
    fn parse_aaaa_response_packet() {
        let test_file_content = fs::read(AAAA_RESPONSE_PACKET_PATH).unwrap();
        let packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();

        assert_eq!(packet.header.id, 29523);
        assert_eq!(packet.header.is_query, false);
        assert_eq!(packet.header.op_code, OpCode::Query);
        assert_eq!(packet.header.authoritative_answer_flag, false);
        assert_eq!(packet.header.truncate_flag, false);
        assert_eq!(packet.header.recursion_desired, true);
        assert_eq!(packet.header.recursion_available, true);
        assert_eq!(packet.header.zero, None);
        assert_eq!(packet.header.error_code, ErrorCode::NoError);
        assert_eq!(packet.header.qd_count, 1);
        assert_eq!(packet.header.an_count, 1);
        assert_eq!(packet.header.ns_count, 0);

        assert_eq!(packet.question_part[0].buffer_offset, 12);
        assert_eq!(packet.question_part[0].question_name, "google.com");
        assert_eq!(packet.question_part[0].dns_record_type, DNSRecordType::AAAA);
        assert_eq!(packet.question_part[0].dns_record_class, DNSRecordClass::IN);

        let response_data = match packet.response_part[0].data {
            DNSRecord::AAAA { len, ip } => (len, ip),
            _ => panic!("expect AAAA record"),
        };

        assert_eq!(response_data.1.to_string(), "2a00:1450:4005:800::200e");
        assert_eq!(response_data.0, 16);

        let response_bytes = packet.to_bytes().unwrap();
        assert_eq!(test_file_content, response_bytes)
    }

    #[test]
    fn parse_txt_response_packet() {
        let test_file_content = fs::read(TXT_RESPONSE_PACKET_PATH).unwrap();
        let packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();

        assert_eq!(packet.header.id, 58813);
        assert_eq!(packet.header.is_query, false);
        assert_eq!(packet.header.op_code, OpCode::Query);
        assert_eq!(packet.header.authoritative_answer_flag, false);
        assert_eq!(packet.header.truncate_flag, false);
        assert_eq!(packet.header.recursion_desired, true);
        assert_eq!(packet.header.recursion_available, true);
        assert_eq!(packet.header.zero, None);
        assert_eq!(packet.header.error_code, ErrorCode::NoError);
        assert_eq!(packet.header.qd_count, 1);
        assert_eq!(packet.header.an_count, 3);
        assert_eq!(packet.header.ns_count, 0);

        assert_eq!(packet.question_part[0].buffer_offset, 12);
        assert_eq!(packet.question_part[0].question_name, "korrespondent.net");
        assert_eq!(packet.question_part[0].dns_record_type, DNSRecordType::TXT);
        assert_eq!(packet.question_part[0].dns_record_class, DNSRecordClass::IN);

        let response_data = match &packet.response_part[0].data {
            DNSRecord::TXT { len, data } => (len, data),
            _ => panic!("expect TXT record"),
        };

        assert_eq!(
            response_data.1.to_string(),
            "google-site-verification=CFcAoeqNeHl3uc-VCQkjOZ9EF1Utcn0J9x7bThF7SM4"
        );
        assert_eq!(*response_data.0, 69);

        let response_data = match &packet.response_part[1].data {
            DNSRecord::TXT { len, data } => (len, data),
            _ => panic!("expect TXT record"),
        };

        assert_eq!(
            response_data.1.to_string(),
            "yandex-verification: 67c648566e370b6d"
        );
        assert_eq!(*response_data.0, 38);

        let response_data = match &packet.response_part[2].data {
            DNSRecord::TXT { len, data } => (len, data),
            _ => panic!("expect TXT record"),
        };

        assert_eq!(
            response_data.1.to_string(),
            "v=spf1 ip4:193.29.200.0/24 ~all"
        );
        assert_eq!(*response_data.0, 32);

        // TODO: test the encoding
        // let response_bytes = packet.to_bytes().unwrap();
        // assert_eq!(test_file_content, response_bytes)
    }

    #[test]
    fn parse_multipart_response() {
        let test_file_content = fs::read(MULTIPART_RESPONSE_PACKET_PATH).unwrap();
        let packet = DNSPacket::from_bytes(test_file_content.clone()).unwrap();

        assert_eq!(packet.header.id, 63914);
        assert_eq!(packet.header.is_query, false);
        assert_eq!(packet.header.is_query, false);
        assert_eq!(packet.header.op_code, OpCode::Query);
        assert_eq!(packet.header.authoritative_answer_flag, true);
        assert_eq!(packet.header.truncate_flag, false);
        assert_eq!(packet.header.recursion_desired, false);
        assert_eq!(packet.header.recursion_available, false);
        assert_eq!(packet.header.zero, None);
        assert_eq!(packet.header.error_code, ErrorCode::NoError);
        assert_eq!(packet.header.qd_count, 1);
        assert_eq!(packet.header.an_count, 6);
        assert_eq!(packet.header.ns_count, 4);
        assert_eq!(packet.header.ar_count, 0);

        assert_eq!(packet.question_part.len(), 1);
        assert_eq!(packet.question_part[0].buffer_offset, 12);
        assert_eq!(packet.question_part[0].question_name, "vk.com".to_string());
        assert_eq!(packet.question_part[0].dns_record_type, DNSRecordType::A);
        assert_eq!(packet.question_part[0].dns_record_class, DNSRecordClass::IN);

        assert_eq!(packet.response_part.len(), 6);
        assert_eq!(packet.response_part[0].name.offset, 12);
        assert_eq!(packet.response_part[0].name.value, "vk.com".to_string());
        assert_eq!(packet.response_part[0].record_type, DNSRecordType::A);
        assert_eq!(packet.response_part[0].record_class, DNSRecordClass::IN);
        assert_eq!(
            packet.response_part[0].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(87, 240, 132, 72)
            }
        );

        assert_eq!(packet.response_part[1].name.offset, 12);
        assert_eq!(packet.response_part[1].name.value, "vk.com".to_string());
        assert_eq!(packet.response_part[1].record_type, DNSRecordType::A);
        assert_eq!(packet.response_part[1].record_class, DNSRecordClass::IN);
        assert_eq!(
            packet.response_part[1].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(93, 186, 225, 194)
            }
        );

        assert_eq!(packet.response_part[2].name.offset, 12);
        assert_eq!(packet.response_part[2].name.value, "vk.com".to_string());
        assert_eq!(packet.response_part[2].record_type, DNSRecordType::A);
        assert_eq!(packet.response_part[2].record_class, DNSRecordClass::IN);
        assert_eq!(
            packet.response_part[2].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(87, 240, 129, 133)
            }
        );

        assert_eq!(packet.response_part[3].name.offset, 12);
        assert_eq!(packet.response_part[3].name.value, "vk.com".to_string());
        assert_eq!(packet.response_part[3].record_type, DNSRecordType::A);
        assert_eq!(packet.response_part[3].record_class, DNSRecordClass::IN);
        assert_eq!(
            packet.response_part[3].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(87, 240, 132, 67)
            }
        );

        assert_eq!(packet.response_part[4].name.offset, 12);
        assert_eq!(packet.response_part[4].name.value, "vk.com".to_string());
        assert_eq!(packet.response_part[4].record_type, DNSRecordType::A);
        assert_eq!(packet.response_part[4].record_class, DNSRecordClass::IN);
        assert_eq!(
            packet.response_part[4].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(87, 240, 137, 164)
            }
        );

        assert_eq!(packet.response_part[5].name.offset, 12);
        assert_eq!(packet.response_part[5].name.value, "vk.com".to_string());
        assert_eq!(packet.response_part[5].record_type, DNSRecordType::A);
        assert_eq!(packet.response_part[5].record_class, DNSRecordClass::IN);
        assert_eq!(
            packet.response_part[5].data,
            DNSRecord::A {
                len: 4,
                ip: Ipv4Addr::new(87, 240, 132, 78)
            }
        );

        assert_eq!(packet.authorities.len(), 4);
        assert_eq!(packet.authorities[0].name.offset, 12);
        assert_eq!(packet.authorities[0].name.value, "vk.com".to_string());
        assert_eq!(packet.authorities[0].record_type, DNSRecordType::NS);
        assert_eq!(packet.authorities[0].record_class, DNSRecordClass::IN);
        assert_eq!(
            packet.authorities[0].data,
            DNSRecord::NS {
                len: 18,
                name_server: "ns1.vkontakte.ru".to_string()
            }
        );
    }
}
