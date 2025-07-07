use crate::{NdnError, Result};

/// NDN TLV types according to NDN Packet Format Specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TlvType {
    Interest = 0x05,
    Data = 0x06,
    Name = 0x07,
    GenericNameComponent = 0x08,
    Nonce = 0x0a,
    InterestLifetime = 0x0c,
    MustBeFresh = 0x12,
    ForwardingHint = 0x1e,
    MetaInfo = 0x14,
    Content = 0x15,
    SignatureInfo = 0x16,
    SignatureValue = 0x17,
    CanBePrefix = 0x21,
    HopLimit = 0x22,
    ApplicationParameters = 0x24,
}

impl TlvType {
    /// Convert from u32 to TlvType
    pub fn from_u32(value: u32) -> Result<Self> {
        match value {
            0x05 => Ok(TlvType::Interest),
            0x06 => Ok(TlvType::Data),
            0x07 => Ok(TlvType::Name),
            0x08 => Ok(TlvType::GenericNameComponent),
            0x0a => Ok(TlvType::Nonce),
            0x0c => Ok(TlvType::InterestLifetime),
            0x12 => Ok(TlvType::MustBeFresh),
            0x1e => Ok(TlvType::ForwardingHint),
            0x14 => Ok(TlvType::MetaInfo),
            0x15 => Ok(TlvType::Content),
            0x16 => Ok(TlvType::SignatureInfo),
            0x17 => Ok(TlvType::SignatureValue),
            0x21 => Ok(TlvType::CanBePrefix),
            0x22 => Ok(TlvType::HopLimit),
            0x24 => Ok(TlvType::ApplicationParameters),
            _ => Err(NdnError::unsupported_tlv_type(value)),
        }
    }
    
    /// Convert to u32
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

/// TLV encoder/decoder for NDN packets
pub struct TlvEncoder<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> TlvEncoder<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, position: 0 }
    }
    
    pub fn position(&self) -> usize {
        self.position
    }
    
    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.position
    }
    
    /// Encode a variable-length number according to NDN TLV spec
    pub fn encode_varint(&mut self, value: u64) -> Result<()> {
        if value <= 252 {
            self.write_u8(value as u8)?;
        } else if value <= 0xFFFF {
            self.write_u8(0xFD)?;
            self.write_u16(value as u16)?;
        } else if value <= 0xFFFFFFFF {
            self.write_u8(0xFE)?;
            self.write_u32(value as u32)?;
        } else {
            self.write_u8(0xFF)?;
            self.write_u64(value)?;
        }
        Ok(())
    }
    
    /// Encode a TLV block
    pub fn encode_tlv(&mut self, tlv_type: TlvType, value: &[u8]) -> Result<()> {
        self.encode_varint(tlv_type.to_u32() as u64)?;
        self.encode_varint(value.len() as u64)?;
        self.write_bytes(value)?;
        Ok(())
    }
    
    /// Encode a TLV block with pre-encoded content
    pub fn encode_tlv_with_content(&mut self, tlv_type: TlvType, content: &[u8]) -> Result<()> {
        self.encode_varint(tlv_type.to_u32() as u64)?;
        self.encode_varint(content.len() as u64)?;
        self.write_bytes(content)?;
        Ok(())
    }
    
    fn write_u8(&mut self, value: u8) -> Result<()> {
        if self.remaining() < 1 {
            return Err(NdnError::buffer_too_small(1, self.remaining()));
        }
        self.buffer[self.position] = value;
        self.position += 1;
        Ok(())
    }
    
    fn write_u16(&mut self, value: u16) -> Result<()> {
        if self.remaining() < 2 {
            return Err(NdnError::buffer_too_small(2, self.remaining()));
        }
        let bytes = value.to_be_bytes();
        self.buffer[self.position..self.position + 2].copy_from_slice(&bytes);
        self.position += 2;
        Ok(())
    }
    
    fn write_u32(&mut self, value: u32) -> Result<()> {
        if self.remaining() < 4 {
            return Err(NdnError::buffer_too_small(4, self.remaining()));
        }
        let bytes = value.to_be_bytes();
        self.buffer[self.position..self.position + 4].copy_from_slice(&bytes);
        self.position += 4;
        Ok(())
    }
    
    fn write_u64(&mut self, value: u64) -> Result<()> {
        if self.remaining() < 8 {
            return Err(NdnError::buffer_too_small(8, self.remaining()));
        }
        let bytes = value.to_be_bytes();
        self.buffer[self.position..self.position + 8].copy_from_slice(&bytes);
        self.position += 8;
        Ok(())
    }
    
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if self.remaining() < bytes.len() {
            return Err(NdnError::buffer_too_small(bytes.len(), self.remaining()));
        }
        self.buffer[self.position..self.position + bytes.len()].copy_from_slice(bytes);
        self.position += bytes.len();
        Ok(())
    }
}

/// TLV decoder for NDN packets
pub struct TlvDecoder<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> TlvDecoder<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, position: 0 }
    }
    
    pub fn position(&self) -> usize {
        self.position
    }
    
    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.position
    }
    
    /// Decode a variable-length number
    pub fn decode_varint(&mut self) -> Result<u64> {
        if self.remaining() < 1 {
            return Err(NdnError::invalid_tlv("Unexpected end of buffer"));
        }
        
        let first_byte = self.buffer[self.position];
        self.position += 1;
        
        match first_byte {
            0..=252 => Ok(first_byte as u64),
            0xFD => {
                if self.remaining() < 2 {
                    return Err(NdnError::invalid_tlv("Incomplete varint"));
                }
                let value = u16::from_be_bytes([
                    self.buffer[self.position],
                    self.buffer[self.position + 1],
                ]);
                self.position += 2;
                Ok(value as u64)
            }
            0xFE => {
                if self.remaining() < 4 {
                    return Err(NdnError::invalid_tlv("Incomplete varint"));
                }
                let value = u32::from_be_bytes([
                    self.buffer[self.position],
                    self.buffer[self.position + 1],
                    self.buffer[self.position + 2],
                    self.buffer[self.position + 3],
                ]);
                self.position += 4;
                Ok(value as u64)
            }
            0xFF => {
                if self.remaining() < 8 {
                    return Err(NdnError::invalid_tlv("Incomplete varint"));
                }
                let value = u64::from_be_bytes([
                    self.buffer[self.position],
                    self.buffer[self.position + 1],
                    self.buffer[self.position + 2],
                    self.buffer[self.position + 3],
                    self.buffer[self.position + 4],
                    self.buffer[self.position + 5],
                    self.buffer[self.position + 6],
                    self.buffer[self.position + 7],
                ]);
                self.position += 8;
                Ok(value)
            }
        }
    }
    
    /// Decode a TLV block
    pub fn decode_tlv(&mut self) -> Result<(TlvType, &'a [u8])> {
        let tlv_type = TlvType::from_u32(self.decode_varint()? as u32)?;
        let length = self.decode_varint()? as usize;
        
        if self.remaining() < length {
            return Err(NdnError::invalid_tlv("TLV length exceeds buffer"));
        }
        
        let value = &self.buffer[self.position..self.position + length];
        self.position += length;
        
        Ok((tlv_type, value))
    }
    
    /// Peek at the next TLV type without consuming it
    pub fn peek_tlv_type(&self) -> Result<TlvType> {
        let mut temp_decoder = TlvDecoder::new(&self.buffer[self.position..]);
        let tlv_type = TlvType::from_u32(temp_decoder.decode_varint()? as u32)?;
        Ok(tlv_type)
    }
    
    /// Check if there are more TLVs to decode
    pub fn has_next(&self) -> bool {
        self.remaining() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding() {
        let mut buffer = [0u8; 16];
        let position = {
            let mut encoder = TlvEncoder::new(&mut buffer);
            
            // Test small numbers
            encoder.encode_varint(100).unwrap();
            encoder.encode_varint(300).unwrap();
            encoder.encode_varint(70000).unwrap();
            
            encoder.position()
        };
        
        let mut decoder = TlvDecoder::new(&buffer[..position]);
        assert_eq!(decoder.decode_varint().unwrap(), 100);
        assert_eq!(decoder.decode_varint().unwrap(), 300);
        assert_eq!(decoder.decode_varint().unwrap(), 70000);
    }
    
    #[test]
    fn test_tlv_encoding() {
        let mut buffer = [0u8; 32];
        let position = {
            let mut encoder = TlvEncoder::new(&mut buffer);
            
            let content = b"test content";
            encoder.encode_tlv(TlvType::Content, content).unwrap();
            
            encoder.position()
        };
        
        let mut decoder = TlvDecoder::new(&buffer[..position]);
        let (tlv_type, value) = decoder.decode_tlv().unwrap();
        
        assert_eq!(tlv_type, TlvType::Content);
        assert_eq!(value, b"test content");
    }
}