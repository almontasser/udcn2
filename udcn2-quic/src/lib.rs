use anyhow::Result;
use quinn::{Endpoint, ClientConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use std::net::SocketAddr;
use std::sync::Arc;
use udcn2_common::{Interest, Data, NdnPacket};

pub mod client;
pub mod server;
pub mod transport;

pub use client::*;
pub use server::*;
pub use transport::*;

/// Error types for QUIC transport
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("Connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("Send error: {0}")]
    Send(#[from] quinn::WriteError),
    #[error("Receive error: {0}")]
    Receive(#[from] quinn::ReadError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// QUIC-based NDN transport
pub struct QuicTransport {
    endpoint: Endpoint,
}

impl QuicTransport {
    pub fn new(bind_addr: SocketAddr) -> Result<Self> {
        let mut endpoint = Endpoint::client(bind_addr)?;
        
        // Create insecure client config for testing
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        
        let client_config = ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?));
        endpoint.set_default_client_config(client_config);
        
        Ok(Self { endpoint })
    }

    pub async fn send_interest(&self, interest: Interest, addr: SocketAddr) -> Result<Data> {
        let connection = self.endpoint.connect(addr, "localhost")?.await?;
        let (mut send, mut recv) = connection.open_bi().await?;

        let packet = NdnPacket::Interest(interest);
        let data = serde_json::to_vec(&packet)?;
        send.write_all(&data).await?;
        send.finish()?;

        let response = recv.read_to_end(usize::MAX).await?;
        let response_packet: NdnPacket = serde_json::from_slice(&response)?;
        
        match response_packet {
            NdnPacket::Data(data) => Ok(data),
            _ => Err(anyhow::anyhow!("Expected Data packet, got Interest")),
        }
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

/// Generate a dummy certificate for testing
pub fn generate_dummy_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = PrivateKeyDer::try_from(cert.serialize_private_key_der())
        .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))?;
    let cert = CertificateDer::from(cert.serialize_der()?);
    Ok((vec![cert], key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quic_transport_creation() {
        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();
        let addr = "127.0.0.1:0".parse().unwrap();
        let transport = QuicTransport::new(addr).unwrap();
        assert!(transport.endpoint.local_addr().is_ok());
    }
}