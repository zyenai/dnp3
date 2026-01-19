//! PoC 3: SSH Tunneling over DNP3 Virtual Terminal Objects
//!
//! This module provides a proof-of-concept implementation for tunneling
//! SSH (or other TCP-based protocols) through DNP3 Virtual Terminal
//! Objects (Groups 112/113).
//!
//! ## Overview
//!
//! The DNP3 Virtual Terminal feature (IEEE 1815-2012) allows binary data
//! streams to be transported between master and outstation. This PoC
//! demonstrates how this feature can be used to tunnel SSH connections,
//! which has implications for ICS security research.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           TUNNEL CLIENT SIDE                                │
//! │  ┌──────────┐      ┌─────────────────────────────────────┐                  │
//! │  │   SSH    │      │         vt_tunnel_client            │                  │
//! │  │  Client  │─TCP─▶│  TCP Listener ──── DNP3 Master      │                  │
//! │  │ ssh -p   │      │  :2222            + VT Write/Read   │                  │
//! │  │ 2222     │◀─TCP─│             Tunnel Framing          │                  │
//! │  └──────────┘      └─────────────────────────────────────┘                  │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!                                       │ DNP3/TCP (g112 ↓ / g113 ↑)
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           TUNNEL SERVER SIDE                                │
//! │                    ┌─────────────────────────────────────┐                  │
//! │                    │        vt_tunnel_server             │      ┌────────┐  │
//! │                    │  DNP3 Outstation ──── TCP Connector │─TCP─▶│  sshd  │  │
//! │                    │  + VT Handler        to SSH:22     │◀─TCP─│  :22   │  │
//! │                    │             Tunnel Framing          │      └────────┘  │
//! │                    └─────────────────────────────────────┘                  │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Protocol
//!
//! The tunnel uses a simple framing protocol on top of DNP3 VT:
//!
//! | Field    | Size   | Description                        |
//! |----------|--------|------------------------------------|
//! | Sequence | 1 byte | Frame sequence number (0-255)      |
//! | Flags    | 1 byte | Control flags                      |
//! | Length   | 1 byte | Payload length (0-252)             |
//! | Payload  | 0-252  | Data payload                       |
//!
//! ## Usage
//!
//! Terminal 1 - Start tunnel server (on outstation/IED):
//! ```bash
//! cargo run --example vt_tunnel_server -- --target 127.0.0.1:22
//! ```
//!
//! Terminal 2 - Start tunnel client (on master/SCADA):
//! ```bash
//! cargo run --example vt_tunnel_client -- --dnp3-endpoint 127.0.0.1:20000
//! ```
//!
//! Terminal 3 - Connect via SSH:
//! ```bash
//! ssh -p 2222 user@localhost
//! ```
//!
//! ## MITRE ATT&CK References
//!
//! | ID     | Technique                              |
//! |--------|----------------------------------------|
//! | T1572  | Protocol Tunneling                     |
//! | T1071  | Application Layer Protocol             |
//! | T0869  | Standard Application Layer Protocol    |
//! | T0886  | Remote Services                        |
//!
//! ## Security Notice
//!
//! This PoC is for authorized security research and testing only.
//! Use only with proper authorization and in controlled environments.

pub mod client;
pub mod framing;
pub mod server;

// Re-export main types for convenience
pub use client::{SimulatedVtChannel, TunnelClient, TunnelClientConfig};
pub use framing::{
    fragment_data, flags, frames_needed, FrameError, FragmentReassembler, ReassemblyError,
    TunnelFrame, MAX_PAYLOAD_SIZE, MAX_VT_SIZE,
};
pub use server::{SimulatedVtHandler, TunnelServer, TunnelServerConfig};

/// Tunnel protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Default VT port index for tunnel operations
pub const DEFAULT_VT_PORT: u16 = 0;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Test bidirectional data flow through simulated VT channel
    #[tokio::test]
    async fn test_bidirectional_flow() {
        let client_channel = Arc::new(Mutex::new(SimulatedVtChannel::new()));
        let server_handler = Arc::new(Mutex::new(SimulatedVtHandler::new()));

        // Simulate client sending data to server
        let client_data = b"Hello from client!";
        {
            let mut client = client_channel.lock().await;
            let frames = fragment_data(client_data, 0);
            for frame in frames {
                client.write_vt(&frame.to_bytes());
            }
        }

        // Transfer from client channel to server handler (simulates DNP3 transport)
        {
            let mut client = client_channel.lock().await;
            let mut server = server_handler.lock().await;
            for data in client.drain_outbound() {
                server.receive_g112(data);
            }
        }

        // Server receives and processes
        {
            let mut server = server_handler.lock().await;
            let mut reassembler = FragmentReassembler::new();

            while let Some(data) = server.poll_inbound() {
                let frame = TunnelFrame::from_bytes(&data).unwrap();
                if let Some(msg) = reassembler.add_frame(frame).unwrap() {
                    assert_eq!(msg, client_data);
                }
            }
        }

        // Server sends response
        let server_data = b"Hello from server!";
        {
            let mut server = server_handler.lock().await;
            let frames = fragment_data(server_data, 0);
            for frame in frames {
                server.queue_g113(&frame.to_bytes());
            }
        }

        // Transfer from server handler to client channel (simulates DNP3 transport)
        {
            let mut client = client_channel.lock().await;
            let mut server = server_handler.lock().await;
            for data in server.drain_outbound() {
                client.inject_inbound(data);
            }
        }

        // Client receives and processes
        {
            let mut client = client_channel.lock().await;
            let mut reassembler = FragmentReassembler::new();

            while let Some(data) = client.poll_vt() {
                let frame = TunnelFrame::from_bytes(&data).unwrap();
                if let Some(msg) = reassembler.add_frame(frame).unwrap() {
                    assert_eq!(msg, server_data);
                }
            }
        }
    }

    /// Test tunnel reset and close handshake
    #[tokio::test]
    async fn test_reset_close_handshake() {
        let client_channel = Arc::new(Mutex::new(SimulatedVtChannel::new()));
        let server_handler = Arc::new(Mutex::new(SimulatedVtHandler::new()));

        // Client sends reset
        {
            let mut client = client_channel.lock().await;
            let reset = TunnelFrame::new_reset();
            client.write_vt(&reset.to_bytes());
        }

        // Transfer to server
        {
            let mut client = client_channel.lock().await;
            let mut server = server_handler.lock().await;
            for data in client.drain_outbound() {
                server.receive_g112(data);
            }
        }

        // Server processes reset
        {
            let mut server = server_handler.lock().await;
            let data = server.poll_inbound().unwrap();
            let frame = TunnelFrame::from_bytes(&data).unwrap();
            assert!(frame.is_reset());

            // Server responds with reset ack
            let reset_ack = TunnelFrame::new_reset();
            server.queue_g113(&reset_ack.to_bytes());
        }

        // Client sends close
        {
            let mut client = client_channel.lock().await;
            let close = TunnelFrame::new_close(0);
            client.write_vt(&close.to_bytes());
        }

        // Transfer to server
        {
            let mut client = client_channel.lock().await;
            let mut server = server_handler.lock().await;
            for data in client.drain_outbound() {
                server.receive_g112(data);
            }
        }

        // Server processes close
        {
            let mut server = server_handler.lock().await;
            let data = server.poll_inbound().unwrap();
            let frame = TunnelFrame::from_bytes(&data).unwrap();
            assert!(frame.is_close());
        }
    }

    /// Test large data fragmentation through tunnel
    #[tokio::test]
    async fn test_large_data_fragmentation() {
        // Create 1KB of test data (simulates SSH packet)
        let test_data: Vec<u8> = (0..1024).map(|i| i as u8).collect();

        // Fragment into frames
        let frames = fragment_data(&test_data, 0);
        assert_eq!(frames.len(), 5); // 1024 / 252 = 5 frames (252*4 + 16)

        // Reassemble
        let mut reassembler = FragmentReassembler::new();
        let mut result = None;

        for frame in frames {
            // Serialize and deserialize (simulates network transport)
            let bytes = frame.to_bytes();
            let parsed = TunnelFrame::from_bytes(&bytes).unwrap();
            result = reassembler.add_frame(parsed).unwrap();
        }

        assert_eq!(result, Some(test_data));
    }

    /// Test sequence number wraparound
    #[tokio::test]
    async fn test_sequence_wraparound() {
        let mut reassembler = FragmentReassembler::new();

        // Start near wraparound
        reassembler.reset_to(254);

        // Send frames that wrap around
        let frame1 = TunnelFrame::new_data(254, vec![1], true);
        let frame2 = TunnelFrame::new_data(255, vec![2], true);
        let frame3 = TunnelFrame::new_data(0, vec![3], false); // Wrapped to 0

        assert!(reassembler.add_frame(frame1).unwrap().is_none());
        assert!(reassembler.add_frame(frame2).unwrap().is_none());

        let result = reassembler.add_frame(frame3).unwrap();
        assert_eq!(result, Some(vec![1, 2, 3]));
    }
}
