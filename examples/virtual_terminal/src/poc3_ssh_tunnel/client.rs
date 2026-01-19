//! Tunnel client - Master/SCADA side
//!
//! This module implements the client side of the SSH tunnel that runs on
//! the master/SCADA station. It listens for TCP connections (e.g., SSH clients)
//! and forwards data through DNP3 Virtual Terminal objects.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────┐      ┌─────────────────────────────────────┐
//! │   SSH    │      │         TunnelClient                │
//! │  Client  │─TCP─▶│  TCP Listener ──── DNP3 Master      │
//! │ ssh -p   │      │  :2222            + VT Write/Read   │
//! │ 2222     │◀─TCP─│             Tunnel Framing          │
//! └──────────┘      └─────────────────────────────────────┘
//! ```

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use super::framing::{fragment_data, FragmentReassembler, TunnelFrame};

/// Configuration for the tunnel client
#[derive(Debug, Clone)]
pub struct TunnelClientConfig {
    /// Address to listen for incoming TCP connections (e.g., "127.0.0.1:2222")
    pub listen_addr: String,
    /// DNP3 outstation endpoint (e.g., "127.0.0.1:20000")
    pub dnp3_endpoint: String,
    /// DNP3 master address
    pub master_addr: u16,
    /// DNP3 outstation address
    pub outstation_addr: u16,
    /// Virtual terminal port index
    pub vt_port: u16,
    /// Polling interval for reading VT events
    pub poll_interval: Duration,
    /// TCP read buffer size
    pub buffer_size: usize,
}

impl Default for TunnelClientConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:2222".into(),
            dnp3_endpoint: "127.0.0.1:20000".into(),
            master_addr: 1,
            outstation_addr: 10,
            vt_port: 0,
            poll_interval: Duration::from_millis(50),
            buffer_size: 8192,
        }
    }
}

/// Simulated VT channel for the client side
///
/// In a real implementation, this would use actual DNP3 master API
/// to send g112 writes and poll for g113 events.
pub struct SimulatedVtChannel {
    /// Queue of data to send (simulates g112 writes)
    outbound: VecDeque<Vec<u8>>,
    /// Queue of received data (simulates g113 events)
    inbound: VecDeque<Vec<u8>>,
}

impl SimulatedVtChannel {
    /// Create a new simulated VT channel
    pub fn new() -> Self {
        Self {
            outbound: VecDeque::new(),
            inbound: VecDeque::new(),
        }
    }

    /// Simulate writing data via g112 (Master -> Outstation)
    pub fn write_vt(&mut self, data: &[u8]) {
        self.outbound.push_back(data.to_vec());
    }

    /// Simulate polling for g113 data (Outstation -> Master)
    pub fn poll_vt(&mut self) -> Option<Vec<u8>> {
        self.inbound.pop_front()
    }

    /// Inject inbound data (for testing)
    pub fn inject_inbound(&mut self, data: Vec<u8>) {
        self.inbound.push_back(data);
    }

    /// Get pending outbound data (for testing)
    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }
}

impl Default for SimulatedVtChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Tunnel client that listens for TCP and forwards through DNP3 VT
pub struct TunnelClient {
    config: TunnelClientConfig,
    listener: Option<TcpListener>,
}

impl TunnelClient {
    /// Create a new tunnel client with the given configuration
    pub async fn new(config: TunnelClientConfig) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self { config, listener: None })
    }

    /// Bind to the listen address and start accepting connections
    pub async fn bind(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        println!("[TunnelClient] Listening on {}", self.config.listen_addr);
        self.listener = Some(listener);
        Ok(())
    }

    /// Run the tunnel client, accepting and handling connections
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.listener.is_none() {
            self.bind().await?;
        }

        let listener = self.listener.as_ref().unwrap();

        loop {
            let (stream, peer) = listener.accept().await?;
            println!("[TunnelClient] Connection from {}", peer);

            let config = self.config.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_session(stream, config).await {
                    eprintln!("[TunnelClient] Session error: {}", e);
                }
                println!("[TunnelClient] Session with {} ended", peer);
            });
        }
    }

    /// Handle a single tunnel session
    async fn handle_session(
        tcp: TcpStream,
        config: TunnelClientConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create simulated VT channel
        // In production, this would be a real DNP3 master connection
        let vt_channel = Arc::new(Mutex::new(SimulatedVtChannel::new()));

        // Run the tunnel session
        Self::run_session(tcp, vt_channel, config).await
    }

    /// Run the tunnel session, bridging TCP to VT
    async fn run_session(
        mut tcp: TcpStream,
        vt_channel: Arc<Mutex<SimulatedVtChannel>>,
        config: TunnelClientConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Send reset frame to initialize tunnel
        {
            let mut channel = vt_channel.lock().await;
            let reset = TunnelFrame::new_reset();
            channel.write_vt(&reset.to_bytes());
            println!("[TunnelClient] Sent RESET frame");
        }

        let mut tx_seq: u8 = 0;
        let mut reassembler = FragmentReassembler::new();
        let mut buf = vec![0u8; config.buffer_size];

        // Split TCP stream for bidirectional I/O
        let (mut tcp_reader, mut tcp_writer) = tcp.split();

        // Poll interval timer
        let mut poll_timer = tokio::time::interval(config.poll_interval);
        poll_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                // Read from TCP client and send to VT
                result = tcp_reader.read(&mut buf) => {
                    match result {
                        Ok(0) => {
                            // TCP connection closed
                            println!("[TunnelClient] TCP connection closed");
                            // Send close frame
                            let mut channel = vt_channel.lock().await;
                            let close = TunnelFrame::new_close(tx_seq);
                            channel.write_vt(&close.to_bytes());
                            break;
                        }
                        Ok(n) => {
                            let data = &buf[..n];
                            println!("[TunnelClient] TCP -> VT: {} bytes", n);

                            // Fragment and send
                            let frames = fragment_data(data, tx_seq);
                            let mut channel = vt_channel.lock().await;

                            for frame in &frames {
                                channel.write_vt(&frame.to_bytes());
                            }

                            // Update sequence counter
                            tx_seq = tx_seq.wrapping_add(frames.len() as u8);
                        }
                        Err(e) => {
                            eprintln!("[TunnelClient] TCP read error: {}", e);
                            break;
                        }
                    }
                }

                // Poll VT channel for incoming data
                _ = poll_timer.tick() => {
                    let mut channel = vt_channel.lock().await;

                    while let Some(data) = channel.poll_vt() {
                        match TunnelFrame::from_bytes(&data) {
                            Ok(frame) => {
                                // Handle control frames
                                if frame.is_reset() {
                                    println!("[TunnelClient] Received RESET from server");
                                    reassembler.reset();
                                    continue;
                                }

                                if frame.is_keepalive() {
                                    continue;
                                }

                                if frame.is_close() {
                                    println!("[TunnelClient] Received CLOSE from server");
                                    return Ok(());
                                }

                                // Handle data frames
                                if frame.is_data() {
                                    match reassembler.add_frame(frame) {
                                        Ok(Some(msg)) => {
                                            // Complete message received, send to TCP
                                            println!("[TunnelClient] VT -> TCP: {} bytes", msg.len());
                                            if let Err(e) = tcp_writer.write_all(&msg).await {
                                                eprintln!("[TunnelClient] TCP write error: {}", e);
                                                return Err(e.into());
                                            }
                                        }
                                        Ok(None) => {
                                            // More fragments expected
                                        }
                                        Err(e) => {
                                            eprintln!("[TunnelClient] Reassembly error: {}", e);
                                            // Reset reassembler on error
                                            reassembler.reset();
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("[TunnelClient] Frame parse error: {}", e);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Client session statistics
#[derive(Debug, Default, Clone)]
pub struct ClientStats {
    /// Bytes received from TCP
    pub tcp_bytes_in: u64,
    /// Bytes sent to TCP
    pub tcp_bytes_out: u64,
    /// Frames sent to VT
    pub vt_frames_out: u64,
    /// Frames received from VT
    pub vt_frames_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulated_vt_channel() {
        let mut channel = SimulatedVtChannel::new();

        // Test write and drain
        channel.write_vt(&[1, 2, 3]);
        channel.write_vt(&[4, 5, 6]);
        let outbound = channel.drain_outbound();
        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0], vec![1, 2, 3]);
        assert_eq!(outbound[1], vec![4, 5, 6]);

        // Test inject and poll
        channel.inject_inbound(vec![7, 8, 9]);
        assert_eq!(channel.poll_vt(), Some(vec![7, 8, 9]));
        assert_eq!(channel.poll_vt(), None);
    }

    #[test]
    fn test_config_defaults() {
        let config = TunnelClientConfig::default();
        assert_eq!(config.listen_addr, "127.0.0.1:2222");
        assert_eq!(config.dnp3_endpoint, "127.0.0.1:20000");
        assert_eq!(config.master_addr, 1);
        assert_eq!(config.outstation_addr, 10);
        assert_eq!(config.vt_port, 0);
    }

    #[tokio::test]
    async fn test_frame_fragmentation_integration() {
        // Test that large data is properly fragmented and can be reassembled
        let test_data: Vec<u8> = (0..500).map(|i| i as u8).collect();

        // Fragment the data
        let frames = fragment_data(&test_data, 0);
        assert_eq!(frames.len(), 2); // 500 bytes = 2 frames (252 + 248)

        // Reassemble
        let mut reassembler = FragmentReassembler::new();
        let mut result = None;

        for frame in frames {
            result = reassembler.add_frame(frame).unwrap();
        }

        assert_eq!(result, Some(test_data));
    }
}
