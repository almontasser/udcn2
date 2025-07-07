use anyhow::Result;
use quinn::{ServerConfig, Endpoint};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use udcn2_common::{Interest, Data, NdnPacket};
use crate::{TransportConfig, ConnectionManager, PacketStream, generate_dummy_cert};

/// QUIC server for NDN
pub struct QuicServer {
    manager: ConnectionManager,
    message_tx: mpsc::UnboundedSender<ServerMessage>,
    message_rx: mpsc::UnboundedReceiver<ServerMessage>,
}

pub enum ServerMessage {
    Interest(Interest, Box<dyn FnOnce(NdnPacket) -> Result<()> + Send>),
    Data(Data, PacketStream),
    ConnectionClosed(SocketAddr),
}

impl QuicServer {
    /// Create a new QUIC server with self-signed certificate
    pub fn new(bind_addr: SocketAddr) -> Result<Self> {
        let (cert_chain, private_key) = generate_dummy_cert()?;
        Self::with_cert(bind_addr, cert_chain, private_key)
    }
    
    /// Create a new QUIC server with provided certificate
    pub fn with_cert(
        bind_addr: SocketAddr,
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        let server_config = ServerConfig::with_single_cert(cert_chain, private_key)?;
        Self::with_config(bind_addr, server_config, TransportConfig::default())
    }
    
    /// Create a new QUIC server with custom configuration
    pub fn with_config(
        bind_addr: SocketAddr,
        server_config: ServerConfig,
        transport_config: TransportConfig,
    ) -> Result<Self> {
        let endpoint = Endpoint::server(server_config, bind_addr)?;
        let manager = ConnectionManager::new(endpoint, transport_config);
        
        let (message_tx, message_rx) = mpsc::unbounded_channel();
        
        Ok(Self {
            manager,
            message_tx,
            message_rx,
        })
    }
    
    /// Start accepting connections
    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                // Handle incoming connections
                conn_result = self.manager.accept_incoming() => {
                    match conn_result {
                        Ok(stream) => {
                            let tx = self.message_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, tx).await {
                                    log::error!("Connection handling error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                
                // Handle server messages
                msg = self.message_rx.recv() => {
                    match msg {
                        Some(ServerMessage::Interest(interest, responder)) => {
                            self.handle_interest(interest, responder).await;
                        }
                        Some(ServerMessage::Data(data, stream)) => {
                            self.handle_data(data, stream).await;
                        }
                        Some(ServerMessage::ConnectionClosed(addr)) => {
                            log::info!("Connection closed: {}", addr);
                        }
                        None => break,
                    }
                }
            }
        }
        
        Ok(())
    }
    
    async fn handle_connection(
        stream: PacketStream,
        tx: mpsc::UnboundedSender<ServerMessage>,
    ) -> Result<()> {
        loop {
            match stream.handle_incoming_stream().await {
                Ok(Some((packet, responder))) => {
                    match packet {
                        NdnPacket::Interest(interest) => {
                            if let Err(e) = tx.send(ServerMessage::Interest(interest, responder)) {
                                log::error!("Failed to send interest message: {}", e);
                                break;
                            }
                        }
                        NdnPacket::Data(data) => {
                            if let Err(e) = tx.send(ServerMessage::Data(data, stream.clone())) {
                                log::error!("Failed to send data message: {}", e);
                                break;
                            }
                        }
                    }
                }
                Ok(None) => {
                    // Connection closed
                    break;
                }
                Err(e) => {
                    log::error!("Stream handling error: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    async fn handle_interest(
        &self,
        interest: Interest,
        responder: Box<dyn FnOnce(NdnPacket) -> Result<()> + Send>,
    ) {
        log::info!("Received Interest: {}", interest.name());
        
        // For demo purposes, create a simple Data response
        let data = Data::new(
            interest.name().clone(),
            format!("Data for {}", interest.name()).into_bytes(),
        );
        
        if let Err(e) = responder(NdnPacket::Data(data)) {
            log::error!("Failed to send data response: {}", e);
        }
    }
    
    async fn handle_data(&self, data: Data, _stream: PacketStream) {
        log::info!("Received Data: {}", data.name());
        // Handle data packet (e.g., forward to other nodes)
    }
    
    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.manager.local_addr()
    }
}

// PacketStream Clone implementation is in transport.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quic_server_creation() {
        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();
        let addr = "127.0.0.1:0".parse().unwrap();
        let server = QuicServer::new(addr).unwrap();
        assert!(server.local_addr().is_ok());
    }
}