use anyhow::Result;
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::ServerName;
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use std::net::SocketAddr;
use std::sync::Arc;
use udcn2_common::{Interest, Data};
use crate::{TransportConfig, ConnectionManager, PacketStream};

/// QUIC client for NDN
pub struct QuicClient {
    manager: ConnectionManager,
}

impl QuicClient {
    /// Create a new QUIC client
    pub fn new(bind_addr: SocketAddr) -> Result<Self> {
        let mut endpoint = Endpoint::client(bind_addr)?;
        
        // Create client config with default root certificates
        let client_config = ClientConfig::with_platform_verifier();
        
        endpoint.set_default_client_config(client_config);
        
        let config = TransportConfig::default();
        let manager = ConnectionManager::new(endpoint, config);
        
        Ok(Self { manager })
    }
    
    /// Create a new QUIC client with custom configuration
    pub fn with_config(bind_addr: SocketAddr, config: TransportConfig) -> Result<Self> {
        let mut endpoint = Endpoint::client(bind_addr)?;
        
        let client_config = ClientConfig::with_platform_verifier();
        
        endpoint.set_default_client_config(client_config);
        
        let manager = ConnectionManager::new(endpoint, config);
        
        Ok(Self { manager })
    }
    
    /// Create an insecure client for testing (skips certificate verification)
    pub fn insecure(bind_addr: SocketAddr) -> Result<Self> {
        let mut endpoint = Endpoint::client(bind_addr)?;
        
        // Create insecure client config
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        
        let client_config = ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?));
        endpoint.set_default_client_config(client_config);
        
        let config = TransportConfig::default();
        let manager = ConnectionManager::new(endpoint, config);
        
        Ok(Self { manager })
    }
    
    /// Connect to a server
    pub async fn connect(&self, addr: SocketAddr) -> Result<PacketStream> {
        self.manager.connect(addr).await
    }
    
    /// Send an Interest and wait for Data response
    pub async fn send_interest(&self, interest: Interest, server_addr: SocketAddr) -> Result<Data> {
        let stream = self.connect(server_addr).await?;
        stream.send_interest(interest).await
    }
    
    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.manager.local_addr()
    }
}

/// Skip server certificate verification for testing
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_quic_client_creation() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let client = QuicClient::new(addr).unwrap();
        assert!(client.local_addr().is_ok());
    }
    
    #[tokio::test]
    async fn test_insecure_client_creation() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let client = QuicClient::insecure(addr).unwrap();
        assert!(client.local_addr().is_ok());
    }
}