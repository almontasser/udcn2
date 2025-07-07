pub mod ndn;
pub mod tlv;
pub mod error;

pub use ndn::*;
pub use tlv::*;
pub use error::*;

#[cfg(feature = "std")]
use std::fmt;

/// Common result type for NDN operations
pub type Result<T> = core::result::Result<T, NdnError>;

/// NDN packet types
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum NdnPacket {
    Interest(Interest),
    Data(Data),
}

impl NdnPacket {
    /// Get the name of the packet
    pub fn name(&self) -> &Name {
        match self {
            NdnPacket::Interest(interest) => interest.name(),
            NdnPacket::Data(data) => data.name(),
        }
    }
    
    /// Check if this is an Interest packet
    pub fn is_interest(&self) -> bool {
        matches!(self, NdnPacket::Interest(_))
    }
    
    /// Check if this is a Data packet
    pub fn is_data(&self) -> bool {
        matches!(self, NdnPacket::Data(_))
    }
}

#[cfg(feature = "std")]
impl fmt::Display for NdnPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NdnPacket::Interest(interest) => write!(f, "Interest({})", interest.name()),
            NdnPacket::Data(data) => write!(f, "Data({})", data.name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ndn_packet_creation() {
        let name = Name::new("/test/packet");
        let interest = Interest::new(name.clone());
        let data = Data::new(name.clone(), b"test data".to_vec());
        
        let interest_packet = NdnPacket::Interest(interest);
        let data_packet = NdnPacket::Data(data);
        
        assert!(interest_packet.is_interest());
        assert!(!interest_packet.is_data());
        assert!(data_packet.is_data());
        assert!(!data_packet.is_interest());
        assert_eq!(interest_packet.name(), &name);
        assert_eq!(data_packet.name(), &name);
    }
}