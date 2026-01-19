//! Tunnel server - Outstation/IED side
//!
//! This module implements the server side of the SSH tunnel that runs on
//! the outstation/IED device. It receives data via DNP3 Virtual Terminal
//! and forwards it to a target service (e.g., SSH daemon).
//!
//! ## Architecture
//!
//! ```text
//!                  ┌─────────────────────────────────────┐      ┌────────┐
//!                  │        TunnelServer                 │      │  sshd  │
//!  DNP3/TCP ──────▶│  DNP3 Outstation ──── TCP Connector │─TCP─▶│  :22   │
//!  (g112/g113)     │  + VT Handler        to SSH:22     │◀─TCP─│        │
//!            ◀─────│             Tunnel Framing          │      └────────┘
//!                  └─────────────────────────────────────┘
//! ```

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use super::framing::{fragment_data, FragmentReassembler, TunnelFrame};

/// Configuration for the tunnel server
#[derive(Debug, Clone)]
pub struct TunnelServerConfig {
    /// Address to listen for DNP3 connections (e.g., "0.0.0.0:20000")
    pub dnp3_listen_addr: String,
    /// DNP3 outstation address
    pub outstation_addr: u16,
    /// DNP3 master address
    pub master_addr: u16,
    /// Virtual terminal port index
    pub vt_port: u16,
    /// Target endpoint to connect to (e.g., "127.0.0.1:22" for SSH)
    pub target_endpoint: String,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// TCP read buffer size
    pub buffer_size: usize,
}

impl Default for TunnelServerConfig {
    fn default() -> Self {
        Self {
            dnp3_listen_addr: "0.0.0.0:20000".into(),
            outstation_addr: 10,
            master_addr: 1,
            vt_port: 0,
            target_endpoint: "127.0.0.1:22".into(),
            connect_timeout: Duration::from_secs(10),
            buffer_size: 8192,
        }
    }
}

/// Simulated VT handler for the server side
///
/// In a real implementation, this would be integrated with the DNP3 outstation
/// to receive g112 writes and queue g113 events.
pub struct SimulatedVtHandler {
    /// Queue of received data (simulates g112 writes from master)
    inbound: VecDeque<Vec<u8>>,
    /// Queue of data to send (simulates g113 events to master)
    outbound: VecDeque<Vec<u8>>,
}

impl SimulatedVtHandler {
    /// Create a new simulated VT handler
    pub fn new() -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
        }
    }

    /// Simulate receiving g112 write from master
    pub fn receive_g112(&mut self, data: Vec<u8>) {
        self.inbound.push_back(data);
    }

    /// Get next inbound frame (from g112)
    pub fn poll_inbound(&mut self) -> Option<Vec<u8>> {
        self.inbound.pop_front()
    }

    /// Queue data to send as g113 event
    pub fn queue_g113(&mut self, data: &[u8]) {
        self.outbound.push_back(data.to_vec());
    }

    /// Get pending outbound data (for testing)
    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }

    /// Check if there's inbound data waiting
    pub fn has_inbound(&self) -> bool {
        !self.inbound.is_empty()
    }
}

impl Default for SimulatedVtHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Tunnel server that receives from VT and forwards to target
pub struct TunnelServer {
    config: TunnelServerConfig,
}

impl TunnelServer {
    /// Create a new tunnel server with the given configuration
    pub fn new(config: TunnelServerConfig) -> Self {
        Self { config }
    }

    /// Run the tunnel server
    ///
    /// In production, this would be integrated with the DNP3 outstation.
    /// This simulated version demonstrates the data flow.
    pub async fn run_simulated(
        &self,
        vt_handler: Arc<Mutex<SimulatedVtHandler>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("[TunnelServer] Starting (simulated mode)");
        println!("[TunnelServer] Target: {}", self.config.target_endpoint);

        let config = self.config.clone();

        Self::run_session(vt_handler, config).await
    }

    /// Run a single tunnel session
    async fn run_session(
        vt_handler: Arc<Mutex<SimulatedVtHandler>>,
        config: TunnelServerConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut target: Option<TcpStream> = None;
        let mut tx_seq: u8 = 0;
        let mut reassembler = FragmentReassembler::new();
        let mut buf = vec![0u8; config.buffer_size];

        // Poll interval for checking VT handler
        let mut poll_timer = tokio::time::interval(Duration::from_millis(10));
        poll_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                // Check for incoming VT data
                _ = poll_timer.tick() => {
                    let mut handler = vt_handler.lock().await;

                    while let Some(data) = handler.poll_inbound() {
                        match TunnelFrame::from_bytes(&data) {
                            Ok(frame) => {
                                // Handle RESET - establish connection to target
                                if frame.is_reset() {
                                    println!("[TunnelServer] Received RESET - connecting to target");
                                    reassembler.reset();
                                    tx_seq = 0;

                                    // Connect to target service
                                    match tokio::time::timeout(
                                        config.connect_timeout,
                                        TcpStream::connect(&config.target_endpoint)
                                    ).await {
                                        Ok(Ok(stream)) => {
                                            println!("[TunnelServer] Connected to {}", config.target_endpoint);
                                            target = Some(stream);

                                            // Send RESET acknowledgment
                                            let ack = TunnelFrame::new_reset();
                                            handler.queue_g113(&ack.to_bytes());
                                        }
                                        Ok(Err(e)) => {
                                            eprintln!("[TunnelServer] Connect failed: {}", e);
                                            // Send CLOSE to indicate failure
                                            let close = TunnelFrame::new_close(0);
                                            handler.queue_g113(&close.to_bytes());
                                        }
                                        Err(_) => {
                                            eprintln!("[TunnelServer] Connect timeout");
                                            let close = TunnelFrame::new_close(0);
                                            handler.queue_g113(&close.to_bytes());
                                        }
                                    }
                                    continue;
                                }

                                // Handle CLOSE
                                if frame.is_close() {
                                    println!("[TunnelServer] Received CLOSE");
                                    if let Some(mut t) = target.take() {
                                        let _ = t.shutdown().await;
                                    }
                                    return Ok(());
                                }

                                // Handle KEEPALIVE
                                if frame.is_keepalive() {
                                    // Respond with keepalive
                                    let keepalive = TunnelFrame::new_keepalive(frame.sequence);
                                    handler.queue_g113(&keepalive.to_bytes());
                                    continue;
                                }

                                // Handle data frames
                                if frame.is_data() {
                                    if let Some(ref mut t) = target {
                                        match reassembler.add_frame(frame) {
                                            Ok(Some(msg)) => {
                                                // Complete message, send to target
                                                println!("[TunnelServer] VT -> Target: {} bytes", msg.len());
                                                if let Err(e) = t.write_all(&msg).await {
                                                    eprintln!("[TunnelServer] Target write error: {}", e);
                                                    target = None;
                                                    // Send close notification
                                                    let close = TunnelFrame::new_close(tx_seq);
                                                    handler.queue_g113(&close.to_bytes());
                                                }
                                            }
                                            Ok(None) => {
                                                // More fragments expected
                                            }
                                            Err(e) => {
                                                eprintln!("[TunnelServer] Reassembly error: {}", e);
                                                reassembler.reset();
                                            }
                                        }
                                    } else {
                                        eprintln!("[TunnelServer] Data received but no target connection");
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("[TunnelServer] Frame parse error: {}", e);
                            }
                        }
                    }
                }

                // Read from target and send to VT
                result = async {
                    match &mut target {
                        Some(t) => t.read(&mut buf).await,
                        None => std::future::pending().await,
                    }
                } => {
                    match result {
                        Ok(0) => {
                            // Target connection closed
                            println!("[TunnelServer] Target connection closed");
                            target = None;

                            // Send close frame
                            let mut handler = vt_handler.lock().await;
                            let close = TunnelFrame::new_close(tx_seq);
                            handler.queue_g113(&close.to_bytes());
                        }
                        Ok(n) => {
                            let data = &buf[..n];
                            println!("[TunnelServer] Target -> VT: {} bytes", n);

                            // Fragment and send
                            let frames = fragment_data(data, tx_seq);
                            let mut handler = vt_handler.lock().await;

                            for frame in &frames {
                                handler.queue_g113(&frame.to_bytes());
                            }

                            tx_seq = tx_seq.wrapping_add(frames.len() as u8);
                        }
                        Err(e) => {
                            eprintln!("[TunnelServer] Target read error: {}", e);
                            target = None;

                            // Send close frame
                            let mut handler = vt_handler.lock().await;
                            let close = TunnelFrame::new_close(tx_seq);
                            handler.queue_g113(&close.to_bytes());
                        }
                    }
                }
            }
        }
    }
}

/// Server session statistics
#[derive(Debug, Default, Clone)]
pub struct ServerStats {
    /// Bytes received from VT
    pub vt_bytes_in: u64,
    /// Bytes sent to VT
    pub vt_bytes_out: u64,
    /// Bytes sent to target
    pub target_bytes_out: u64,
    /// Bytes received from target
    pub target_bytes_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulated_vt_handler() {
        let mut handler = SimulatedVtHandler::new();

        // Test receive and poll
        handler.receive_g112(vec![1, 2, 3]);
        handler.receive_g112(vec![4, 5, 6]);

        assert!(handler.has_inbound());
        assert_eq!(handler.poll_inbound(), Some(vec![1, 2, 3]));
        assert_eq!(handler.poll_inbound(), Some(vec![4, 5, 6]));
        assert_eq!(handler.poll_inbound(), None);
        assert!(!handler.has_inbound());

        // Test queue and drain
        handler.queue_g113(&[7, 8, 9]);
        let outbound = handler.drain_outbound();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0], vec![7, 8, 9]);
    }

    #[test]
    fn test_config_defaults() {
        let config = TunnelServerConfig::default();
        assert_eq!(config.dnp3_listen_addr, "0.0.0.0:20000");
        assert_eq!(config.outstation_addr, 10);
        assert_eq!(config.master_addr, 1);
        assert_eq!(config.vt_port, 0);
        assert_eq!(config.target_endpoint, "127.0.0.1:22");
    }

    #[tokio::test]
    async fn test_reset_and_close_frames() {
        // Test that reset and close frames are properly created and parsed
        let reset = TunnelFrame::new_reset();
        let reset_bytes = reset.to_bytes();
        let parsed_reset = TunnelFrame::from_bytes(&reset_bytes).unwrap();
        assert!(parsed_reset.is_reset());

        let close = TunnelFrame::new_close(42);
        let close_bytes = close.to_bytes();
        let parsed_close = TunnelFrame::from_bytes(&close_bytes).unwrap();
        assert!(parsed_close.is_close());
        assert_eq!(parsed_close.sequence, 42);
    }

    #[tokio::test]
    async fn test_data_flow_simulation() {
        let handler = Arc::new(Mutex::new(SimulatedVtHandler::new()));

        // Simulate master sending reset
        {
            let mut h = handler.lock().await;
            let reset = TunnelFrame::new_reset();
            h.receive_g112(reset.to_bytes());
        }

        // Simulate master sending data
        {
            let mut h = handler.lock().await;
            let data_frame = TunnelFrame::new_data(0, vec![0x53, 0x53, 0x48], false);
            h.receive_g112(data_frame.to_bytes());
        }

        // Verify frames can be retrieved
        {
            let mut h = handler.lock().await;
            let reset_frame = h.poll_inbound().unwrap();
            let parsed = TunnelFrame::from_bytes(&reset_frame).unwrap();
            assert!(parsed.is_reset());

            let data_frame = h.poll_inbound().unwrap();
            let parsed = TunnelFrame::from_bytes(&data_frame).unwrap();
            assert!(parsed.is_data());
            assert_eq!(parsed.payload, vec![0x53, 0x53, 0x48]);
        }
    }
}
