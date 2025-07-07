/// Error types for NDN operations
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum NdnError {
    /// Invalid TLV encoding
    #[cfg_attr(feature = "std", error("Invalid TLV encoding: {message}"))]
    InvalidTlv { message: &'static str },
    
    /// Invalid packet format
    #[cfg_attr(feature = "std", error("Invalid packet format: {message}"))]
    InvalidPacket { message: &'static str },
    
    /// Invalid name format
    #[cfg_attr(feature = "std", error("Invalid name format: {message}"))]
    InvalidName { message: &'static str },
    
    /// Buffer too small
    #[cfg_attr(feature = "std", error("Buffer too small: need {need}, have {have}"))]
    BufferTooSmall { need: usize, have: usize },
    
    /// Unsupported TLV type
    #[cfg_attr(feature = "std", error("Unsupported TLV type: {tlv_type}"))]
    UnsupportedTlvType { tlv_type: u32 },
    
    /// Serialization error
    #[cfg_attr(feature = "std", error("Serialization error: {message}"))]
    Serialization { message: &'static str },
    
    /// Deserialization error
    #[cfg_attr(feature = "std", error("Deserialization error: {message}"))]
    Deserialization { message: &'static str },
}

impl NdnError {
    pub fn invalid_tlv(message: &'static str) -> Self {
        Self::InvalidTlv { message }
    }
    
    pub fn invalid_packet(message: &'static str) -> Self {
        Self::InvalidPacket { message }
    }
    
    pub fn invalid_name(message: &'static str) -> Self {
        Self::InvalidName { message }
    }
    
    pub fn buffer_too_small(need: usize, have: usize) -> Self {
        Self::BufferTooSmall { need, have }
    }
    
    pub fn unsupported_tlv_type(tlv_type: u32) -> Self {
        Self::UnsupportedTlvType { tlv_type }
    }
    
    pub fn serialization(message: &'static str) -> Self {
        Self::Serialization { message }
    }
    
    pub fn deserialization(message: &'static str) -> Self {
        Self::Deserialization { message }
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for NdnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NdnError::InvalidTlv { message } => write!(f, "Invalid TLV encoding: {}", message),
            NdnError::InvalidPacket { message } => write!(f, "Invalid packet format: {}", message),
            NdnError::InvalidName { message } => write!(f, "Invalid name format: {}", message),
            NdnError::BufferTooSmall { need, have } => write!(f, "Buffer too small: need {}, have {}", need, have),
            NdnError::UnsupportedTlvType { tlv_type } => write!(f, "Unsupported TLV type: {}", tlv_type),
            NdnError::Serialization { message } => write!(f, "Serialization error: {}", message),
            NdnError::Deserialization { message } => write!(f, "Deserialization error: {}", message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = NdnError::invalid_tlv("test message");
        assert_eq!(error, NdnError::InvalidTlv { message: "test message" });
        
        let error = NdnError::buffer_too_small(100, 50);
        assert_eq!(error, NdnError::BufferTooSmall { need: 100, have: 50 });
    }
}