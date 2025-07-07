use anyhow::Result;
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use tokio::time::{timeout, Duration};
use udcn2_common::{Interest, Data, NdnPacket};

/// Configuration for NDN-over-QUIC transport
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub connection_timeout: Duration,
    pub stream_timeout: Duration,
    pub max_packet_size: usize,
    pub keep_alive_interval: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            stream_timeout: Duration::from_secs(5),
            max_packet_size: 65536,
            keep_alive_interval: Duration::from_secs(30),
        }
    }
}

/// NDN packet stream handler
#[derive(Debug, Clone)]
pub struct PacketStream {
    connection: Connection,
    config: TransportConfig,
}

impl PacketStream {
    pub fn new(connection: Connection, config: TransportConfig) -> Self {
        Self { connection, config }
    }

    /// Send an Interest packet and wait for Data response
    pub async fn send_interest(&self, interest: Interest) -> Result<Data> {
        let packet = NdnPacket::Interest(interest);
        let serialized = serde_json::to_vec(&packet)?;
        
        // Open a bidirectional stream for request-response
        let (mut send_stream, mut recv_stream) = timeout(
            self.config.connection_timeout,
            self.connection.open_bi()
        ).await??;
        
        // Send the Interest
        send_stream.write_all(&serialized).await?;
        send_stream.finish().await?;
        
        // Wait for the Data response
        let response_data = timeout(
            self.config.stream_timeout,
            recv_stream.read_to_end(self.config.max_packet_size)
        ).await??;
        
        let response_packet: NdnPacket = serde_json::from_slice(&response_data)?;
        
        match response_packet {
            NdnPacket::Data(data) => Ok(data),
            NdnPacket::Interest(_) => Err(anyhow::anyhow!("Expected Data packet, got Interest")),
        }
    }
    
    /// Send a Data packet (for producer/forwarder)
    pub async fn send_data(&self, data: Data) -> Result<()> {
        let packet = NdnPacket::Data(data);
        let serialized = serde_json::to_vec(&packet)?;
        
        let mut send_stream = timeout(
            self.config.connection_timeout,
            self.connection.open_uni()
        ).await??;
        
        send_stream.write_all(&serialized).await?;
        send_stream.finish()?;
        
        Ok(())
    }
    
    /// Handle incoming stream and respond (for server/forwarder)
    pub async fn handle_incoming_stream(&self) -> Result<Option<(NdnPacket, Box<dyn FnOnce(NdnPacket) -> Result<()> + Send>)>> {
        match self.connection.accept_bi().await {
            Ok((send_stream, mut recv_stream)) => {
                let data = recv_stream.read_to_end(self.config.max_packet_size).await?;
                let packet: NdnPacket = serde_json::from_slice(&data)?;
                
                // Create response closure
                let responder = Box::new(move |response: NdnPacket| -> Result<()> {
                    tokio::task::block_in_place(move || {
                        tokio::runtime::Handle::current().block_on(async move {
                            let mut send_stream = send_stream;
                            let response_data = serde_json::to_vec(&response)?;
                            send_stream.write_all(&response_data).await?;
                            send_stream.finish().await?;
                            Ok(())
                        })
                    })
                });
                
                Ok(Some((packet, responder)))
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    
    /// Get connection statistics
    pub fn stats(&self) -> ConnectionStats {
        let quinn_stats = self.connection.stats();
        ConnectionStats {
            bytes_sent: quinn_stats.udp_tx.bytes,
            bytes_received: quinn_stats.udp_rx.bytes,
            packets_sent: quinn_stats.udp_tx.datagrams,
            packets_received: quinn_stats.udp_rx.datagrams,
            rtt: quinn_stats.path.rtt,
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub rtt: Duration,
}

/// Multiplexed connection manager
pub struct ConnectionManager {
    endpoint: Endpoint,
    config: TransportConfig,
}

impl ConnectionManager {
    pub fn new(endpoint: Endpoint, config: TransportConfig) -> Self {
        Self { endpoint, config }
    }
    
    pub async fn connect(&self, addr: SocketAddr) -> Result<PacketStream> {
        let connection = self.endpoint.connect(addr, "localhost")?.await?;
        Ok(PacketStream::new(connection, self.config.clone()))
    }
    
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
    
    pub async fn accept_incoming(&self) -> Result<PacketStream> {
        let connection = self.endpoint.accept().await.ok_or_else(|| {
            anyhow::anyhow!("No incoming connections")
        })?;
        
        let connection = connection.await?;
        Ok(PacketStream::new(connection, self.config.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.connection_timeout, Duration::from_secs(10));
        assert_eq!(config.stream_timeout, Duration::from_secs(5));
        assert_eq!(config.max_packet_size, 65536);
    }
}