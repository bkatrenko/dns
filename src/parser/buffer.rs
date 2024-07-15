// Simple bytes buffer implementation.
use std;

#[derive(Debug, PartialEq)]
pub struct ByteBuffer {
    bytes: Vec<u8>,
    offset: usize,
}

#[derive(Debug)]
pub enum BufferError {
    OutOfBounds,
}

impl std::fmt::Display for BufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Self::OutOfBounds => write!(f, "buffer out of bounds"),
        }
    }
}

type BufferResult<T> = std::result::Result<T, BufferError>;

impl std::error::Error for BufferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            BufferError::OutOfBounds => None,
        }
    }
}

impl ByteBuffer {
    pub fn new() -> ByteBuffer {
        ByteBuffer {
            bytes: Vec::new(),
            offset: 0,
        }
    }

    pub fn from_bytes_vec(v: Vec<u8>) -> ByteBuffer {
        ByteBuffer {
            bytes: v,
            offset: 0,
        }
    }

    pub fn get_byte_at(&self, offset: usize) -> BufferResult<u8> {
        if self.bytes.len() > offset {
            return Ok(self.bytes[offset]);
        }

        Err(BufferError::OutOfBounds)
    }

    pub fn get_u8(&mut self) -> BufferResult<u8> {
        if self.bytes.len() > self.offset {
            let byte = self.bytes[self.offset];
            self.offset += 1;

            return Ok(byte);
        }

        Err(BufferError::OutOfBounds)
    }

    pub fn get_u16(&mut self) -> BufferResult<u16> {
        if self.bytes.len() > self.offset + 1 {
            let val = ((self.bytes[self.offset] as u16) << 8) | self.bytes[self.offset + 1] as u16;
            self.offset += 2;

            return Ok(val);
        }

        Err(BufferError::OutOfBounds)
    }

    pub fn get_u32(&mut self) -> BufferResult<u32> {
        if self.bytes.len() > self.offset + 3 {
            let val = ((self.bytes[self.offset] as u32) << 24)
                | ((self.bytes[self.offset + 1] as u32) << 16)
                | ((self.bytes[self.offset + 2] as u32) << 8)
                | ((self.bytes[self.offset + 3] as u32) << 0);

            self.offset += 4;

            return Ok(val);
        }

        Err(BufferError::OutOfBounds)
    }

    pub fn get_offset(&self) -> usize {
        self.offset
    }

    pub fn set_offset(&mut self, offset: usize) -> BufferResult<()> {
        if self.bytes.len() > offset {
            self.offset = offset;

            return Ok(());
        }

        Err(BufferError::OutOfBounds)
    }

    pub fn add_offset(&mut self, offset: usize) -> BufferResult<()> {
        if self.bytes.len() > self.offset + offset {
            self.offset += offset;

            return Ok(());
        }

        Err(BufferError::OutOfBounds)
    }

    pub fn write_u8(&mut self, byte: u8) {
        self.bytes.push(byte);
        self.offset += 1;
    }

    pub fn write_u16(&mut self, byte: u16) {
        let bts = byte.to_be_bytes();
        self.bytes.extend(bts.iter());
        self.offset += 2;
    }

    pub fn write_u32(&mut self, byte: u32) {
        self.bytes.extend(byte.to_be_bytes().iter());
        self.offset += 4;
    }

    pub fn get_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::ByteBuffer;

    #[test]
    fn buffer_test() {
        let bytes: Vec<u8> = vec![
            0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        ];
        let mut buffer = ByteBuffer::from_bytes_vec(bytes);

        assert_eq!(0xa, buffer.get_u8().unwrap());
        assert_eq!(0xb, buffer.get_u8().unwrap());
        assert_eq!(2, buffer.get_offset());
        assert_eq!(0xc0d, buffer.get_u16().unwrap());
        assert_eq!(4, buffer.get_offset());
        assert_eq!(0xE0F1011, buffer.get_u32().unwrap());
        assert_eq!(8, buffer.get_offset());

        buffer.add_offset(1).unwrap();
        assert_eq!(0x13, buffer.get_u8().unwrap());
        assert_eq!(10, buffer.get_offset());
    }
}
