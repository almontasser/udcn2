use crate::{NdnError, Result, TlvType, TlvEncoder, TlvDecoder};
use core::fmt;
use core::hash::{Hash, Hasher};

/// NDN Name structure
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct Name {
    components: Vec<NameComponent>,
}

impl Name {
    /// Create a new name from a string
    pub fn new<S: AsRef<str>>(name: S) -> Self {
        let name_str = name.as_ref();
        let components = if name_str.starts_with('/') {
            name_str[1..].split('/')
                .filter(|s| !s.is_empty())
                .map(|s| NameComponent::new(s.as_bytes()))
                .collect()
        } else {
            name_str.split('/')
                .filter(|s| !s.is_empty())
                .map(|s| NameComponent::new(s.as_bytes()))
                .collect()
        };
        
        Self { components }
    }
    
    /// Create a new empty name
    pub fn empty() -> Self {
        Self { components: Vec::new() }
    }
    
    /// Add a component to the name
    pub fn append<T: AsRef<[u8]>>(&mut self, component: T) -> &mut Self {
        self.components.push(NameComponent::new(component.as_ref()));
        self
    }
    
    /// Get the number of components
    pub fn len(&self) -> usize {
        self.components.len()
    }
    
    /// Check if the name is empty
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }
    
    /// Get a component by index
    pub fn get(&self, index: usize) -> Option<&NameComponent> {
        self.components.get(index)
    }
    
    /// Get all components
    pub fn components(&self) -> &[NameComponent] {
        &self.components
    }
    
    /// Check if this name is a prefix of another name
    pub fn is_prefix_of(&self, other: &Name) -> bool {
        if self.len() > other.len() {
            return false;
        }
        
        for (i, component) in self.components.iter().enumerate() {
            if component != &other.components[i] {
                return false;
            }
        }
        
        true
    }
    
    /// Encode the name as TLV
    pub fn encode_tlv(&self, encoder: &mut TlvEncoder) -> Result<()> {
        // Encode components to a temporary buffer first
        let mut temp_buffer = Vec::with_capacity(1024);
        let content_length = {
            let mut temp_encoder = TlvEncoder::new(&mut temp_buffer);
            for component in &self.components {
                component.encode_tlv(&mut temp_encoder)?;
            }
            temp_encoder.position()
        };
        temp_buffer.truncate(content_length);
        
        encoder.encode_tlv_with_content(TlvType::Name, &temp_buffer)
    }
    
    /// Decode the name from TLV
    pub fn decode_tlv(decoder: &mut TlvDecoder) -> Result<Self> {
        let (tlv_type, value) = decoder.decode_tlv()?;
        if tlv_type != TlvType::Name {
            return Err(NdnError::invalid_packet("Expected Name TLV"));
        }
        
        let mut name_decoder = TlvDecoder::new(value);
        let mut components = Vec::new();
        
        while name_decoder.has_next() {
            let component = NameComponent::decode_tlv(&mut name_decoder)?;
            components.push(component);
        }
        
        Ok(Self { components })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.components.is_empty() {
            write!(f, "/")
        } else {
            for component in &self.components {
                write!(f, "/{}", component)?;
            }
            Ok(())
        }
    }
}

/// Name component
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct NameComponent {
    value: Vec<u8>,
}

impl NameComponent {
    pub fn new(value: &[u8]) -> Self {
        Self { value: value.to_vec() }
    }
    
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    
    pub fn encode_tlv(&self, encoder: &mut TlvEncoder) -> Result<()> {
        encoder.encode_tlv(TlvType::GenericNameComponent, &self.value)
    }
    
    pub fn decode_tlv(decoder: &mut TlvDecoder) -> Result<Self> {
        let (tlv_type, value) = decoder.decode_tlv()?;
        if tlv_type != TlvType::GenericNameComponent {
            return Err(NdnError::invalid_packet("Expected GenericNameComponent TLV"));
        }
        
        Ok(Self { value: value.to_vec() })
    }
}

impl Hash for NameComponent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl fmt::Display for NameComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Try to display as UTF-8 string, fallback to hex if not valid
        match core::str::from_utf8(&self.value) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => {
                for byte in &self.value {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }
    }
}

/// NDN Interest packet
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct Interest {
    name: Name,
    can_be_prefix: bool,
    must_be_fresh: bool,
    nonce: Option<u32>,
    interest_lifetime: Option<u32>, // in milliseconds
    hop_limit: Option<u8>,
}

impl Interest {
    pub fn new(name: Name) -> Self {
        Self {
            name,
            can_be_prefix: false,
            must_be_fresh: false,
            nonce: None,
            interest_lifetime: None,
            hop_limit: None,
        }
    }
    
    pub fn name(&self) -> &Name {
        &self.name
    }
    
    pub fn can_be_prefix(&self) -> bool {
        self.can_be_prefix
    }
    
    pub fn set_can_be_prefix(&mut self, can_be_prefix: bool) -> &mut Self {
        self.can_be_prefix = can_be_prefix;
        self
    }
    
    pub fn must_be_fresh(&self) -> bool {
        self.must_be_fresh
    }
    
    pub fn set_must_be_fresh(&mut self, must_be_fresh: bool) -> &mut Self {
        self.must_be_fresh = must_be_fresh;
        self
    }
    
    pub fn nonce(&self) -> Option<u32> {
        self.nonce
    }
    
    pub fn set_nonce(&mut self, nonce: u32) -> &mut Self {
        self.nonce = Some(nonce);
        self
    }
    
    pub fn interest_lifetime(&self) -> Option<u32> {
        self.interest_lifetime
    }
    
    pub fn set_interest_lifetime(&mut self, lifetime: u32) -> &mut Self {
        self.interest_lifetime = Some(lifetime);
        self
    }
    
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }
    
    pub fn set_hop_limit(&mut self, hop_limit: u8) -> &mut Self {
        self.hop_limit = Some(hop_limit);
        self
    }
    
    /// Encode the Interest as TLV
    pub fn encode_tlv(&self, encoder: &mut TlvEncoder) -> Result<()> {
        // Encode content to a temporary buffer first
        let mut temp_buffer = Vec::with_capacity(1024);
        let content_length = {
            let mut temp_encoder = TlvEncoder::new(&mut temp_buffer);
            self.name.encode_tlv(&mut temp_encoder)?;
            
            if self.can_be_prefix {
                temp_encoder.encode_tlv(TlvType::CanBePrefix, &[])?;
            }
            
            if self.must_be_fresh {
                temp_encoder.encode_tlv(TlvType::MustBeFresh, &[])?;
            }
            
            if let Some(nonce) = self.nonce {
                temp_encoder.encode_tlv(TlvType::Nonce, &nonce.to_be_bytes())?;
            }
            
            if let Some(lifetime) = self.interest_lifetime {
                temp_encoder.encode_tlv(TlvType::InterestLifetime, &lifetime.to_be_bytes())?;
            }
            
            if let Some(hop_limit) = self.hop_limit {
                temp_encoder.encode_tlv(TlvType::HopLimit, &[hop_limit])?;
            }
            
            temp_encoder.position()
        };
        temp_buffer.truncate(content_length);
        
        encoder.encode_tlv_with_content(TlvType::Interest, &temp_buffer)
    }
}

/// NDN Data packet
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct Data {
    name: Name,
    meta_info: Option<MetaInfo>,
    content: Vec<u8>,
    signature: Option<Signature>,
}

impl Data {
    pub fn new(name: Name, content: Vec<u8>) -> Self {
        Self {
            name,
            meta_info: None,
            content,
            signature: None,
        }
    }
    
    pub fn name(&self) -> &Name {
        &self.name
    }
    
    pub fn content(&self) -> &[u8] {
        &self.content
    }
    
    pub fn set_content(&mut self, content: Vec<u8>) -> &mut Self {
        self.content = content;
        self
    }
    
    pub fn meta_info(&self) -> Option<&MetaInfo> {
        self.meta_info.as_ref()
    }
    
    pub fn set_meta_info(&mut self, meta_info: MetaInfo) -> &mut Self {
        self.meta_info = Some(meta_info);
        self
    }
    
    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
    
    pub fn set_signature(&mut self, signature: Signature) -> &mut Self {
        self.signature = Some(signature);
        self
    }
    
    /// Encode the Data as TLV
    pub fn encode_tlv(&self, encoder: &mut TlvEncoder) -> Result<()> {
        // Encode content to a temporary buffer first
        let mut temp_buffer = Vec::with_capacity(1024);
        let content_length = {
            let mut temp_encoder = TlvEncoder::new(&mut temp_buffer);
            self.name.encode_tlv(&mut temp_encoder)?;
            
            if let Some(meta_info) = &self.meta_info {
                meta_info.encode_tlv(&mut temp_encoder)?;
            }
            
            if !self.content.is_empty() {
                temp_encoder.encode_tlv(TlvType::Content, &self.content)?;
            }
            
            if let Some(signature) = &self.signature {
                signature.encode_tlv(&mut temp_encoder)?;
            }
            
            temp_encoder.position()
        };
        temp_buffer.truncate(content_length);
        
        encoder.encode_tlv_with_content(TlvType::Data, &temp_buffer)
    }
}

/// MetaInfo for Data packets
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct MetaInfo {
    content_type: Option<u32>,
    freshness_period: Option<u32>,
}

impl MetaInfo {
    pub fn new() -> Self {
        Self {
            content_type: None,
            freshness_period: None,
        }
    }
    
    pub fn content_type(&self) -> Option<u32> {
        self.content_type
    }
    
    pub fn set_content_type(&mut self, content_type: u32) -> &mut Self {
        self.content_type = Some(content_type);
        self
    }
    
    pub fn freshness_period(&self) -> Option<u32> {
        self.freshness_period
    }
    
    pub fn set_freshness_period(&mut self, freshness_period: u32) -> &mut Self {
        self.freshness_period = Some(freshness_period);
        self
    }
    
    pub fn encode_tlv(&self, encoder: &mut TlvEncoder) -> Result<()> {
        // For now, just encode an empty MetaInfo
        encoder.encode_tlv_with_content(TlvType::MetaInfo, &[])
    }
}

impl Default for MetaInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature for Data packets
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature {
    signature_info: Vec<u8>,
    signature_value: Vec<u8>,
}

impl Signature {
    pub fn new(signature_info: Vec<u8>, signature_value: Vec<u8>) -> Self {
        Self {
            signature_info,
            signature_value,
        }
    }
    
    pub fn signature_info(&self) -> &[u8] {
        &self.signature_info
    }
    
    pub fn signature_value(&self) -> &[u8] {
        &self.signature_value
    }
    
    pub fn encode_tlv(&self, encoder: &mut TlvEncoder) -> Result<()> {
        encoder.encode_tlv(TlvType::SignatureInfo, &self.signature_info)?;
        encoder.encode_tlv(TlvType::SignatureValue, &self.signature_value)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_creation() {
        let name = Name::new("/test/name");
        assert_eq!(name.len(), 2);
        assert_eq!(name.to_string(), "/test/name");
        
        let empty_name = Name::empty();
        assert!(empty_name.is_empty());
        assert_eq!(empty_name.to_string(), "/");
    }
    
    #[test]
    fn test_name_prefix() {
        let name1 = Name::new("/test");
        let name2 = Name::new("/test/name");
        
        assert!(name1.is_prefix_of(&name2));
        assert!(!name2.is_prefix_of(&name1));
    }
    
    #[test]
    fn test_interest_creation() {
        let name = Name::new("/test/interest");
        let mut interest = Interest::new(name.clone());
        
        assert_eq!(interest.name(), &name);
        assert!(!interest.can_be_prefix());
        assert!(!interest.must_be_fresh());
        
        interest.set_can_be_prefix(true)
                .set_must_be_fresh(true)
                .set_nonce(12345)
                .set_interest_lifetime(4000);
        
        assert!(interest.can_be_prefix());
        assert!(interest.must_be_fresh());
        assert_eq!(interest.nonce(), Some(12345));
        assert_eq!(interest.interest_lifetime(), Some(4000));
    }
    
    #[test]
    fn test_data_creation() {
        let name = Name::new("/test/data");
        let content = b"Hello, NDN!".to_vec();
        let data = Data::new(name.clone(), content.clone());
        
        assert_eq!(data.name(), &name);
        assert_eq!(data.content(), &content);
    }
}