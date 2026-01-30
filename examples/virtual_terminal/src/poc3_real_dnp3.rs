//! PoC 3: Real DNP3 Traffic with Virtual Terminal Objects
//!
//! This module implements SSH tunneling over DNP3 using Virtual Terminal objects
//! (Groups 112/113) as specified in IEEE 1815-2012.
//!
//! ## Architecture
//!
//! ```text
//! SSH Client --[2222]--> Master --[G112 Write]--> Outstation --[22]--> SSH Server
//! SSH Client <--[2222]-- Master <--[G113 Event]-- Outstation <--[22]-- SSH Server
//! ```
//!
//! ## Usage
//!
//! Terminal 1 - Start tunnel server (outstation side):
//! ```bash
//! cargo run -p example-virtual-terminal --bin vt_tunnel_server -- --real-dnp3
//! ```
//!
//! Terminal 2 - Start tunnel client (master side):
//! ```bash
//! cargo run -p example-virtual-terminal --bin vt_tunnel_client -- --real-dnp3
//! ```
//!
//! Terminal 3 - Connect via SSH:
//! ```bash
//! ssh -p 2222 user@localhost
//! ```
//!
//! Wireshark filter: `tcp.port == 20000`
//!
//! ## DNP3 Object Groups
//!
//! - Group 112: Virtual Terminal Output Block (master -> outstation)
//! - Group 113: Virtual Terminal Event Data (outstation -> master)

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use dnp3::app::measurement::*;
use dnp3::app::*;
use dnp3::decode::*;
use dnp3::link::*;
use dnp3::master::*;
use dnp3::outstation::database::*;
use dnp3::outstation::*;
use dnp3::tcp::*;

use crate::poc3_ssh_tunnel::framing::{fragment_data, FragmentReassembler, TunnelFrame};

/// Configuration for real DNP3 tunnel
pub struct RealDnp3Config {
    pub dnp3_addr: SocketAddr,
    pub master_addr: u16,
    pub outstation_addr: u16,
}

impl Default for RealDnp3Config {
    fn default() -> Self {
        Self {
            dnp3_addr: "127.0.0.1:20000".parse().unwrap(),
            master_addr: 1,
            outstation_addr: 10,
        }
    }
}

// ============================================================================
// OUTSTATION (TUNNEL SERVER)
// ============================================================================

/// Shared state for the tunnel server outstation
struct TunnelServerState {
    /// Queue of data received from G112 writes to forward to SSH
    ssh_outbound: Mutex<VecDeque<Vec<u8>>>,
    /// Queue of data received from SSH to send as G113 events
    dnp3_outbound: Mutex<VecDeque<Vec<u8>>>,
    /// SSH connection stream
    ssh_stream: Mutex<Option<TcpStream>>,
    /// Reassembler for incoming G112 frames
    reassembler: Mutex<FragmentReassembler>,
    /// Sequence number for outgoing G113 frames
    sequence: Mutex<u8>,
}

impl TunnelServerState {
    fn new() -> Self {
        Self {
            ssh_outbound: Mutex::new(VecDeque::new()),
            dnp3_outbound: Mutex::new(VecDeque::new()),
            ssh_stream: Mutex::new(None),
            reassembler: Mutex::new(FragmentReassembler::new()),
            sequence: Mutex::new(0),
        }
    }
}

/// Outstation application that handles VT writes
struct TunnelOutstationApp {
    state: Arc<TunnelServerState>,
}

impl TunnelOutstationApp {
    fn new(state: Arc<TunnelServerState>) -> Self {
        Self { state }
    }
}

impl OutstationApplication for TunnelOutstationApp {
    fn get_processing_delay_ms(&self) -> u16 {
        0
    }

    fn support_virtual_terminal_writes(&self) -> bool {
        true
    }

    fn handle_virtual_terminal_write(&mut self, port: u16, data: &[u8]) {
        println!(
            "[Outstation] << G112 write: port={}, len={}",
            port,
            data.len()
        );

        // Try to parse as tunnel frame
        if let Ok(frame) = TunnelFrame::from_bytes(data) {
            println!(
                "[Outstation]    Frame: seq={}, flags={:02X}, payload={}",
                frame.sequence,
                frame.flags,
                frame.payload.len()
            );

            // Queue for SSH forwarding
            let state = self.state.clone();
            let payload = frame.payload.clone();
            tokio::spawn(async move {
                let mut queue = state.ssh_outbound.lock().await;
                queue.push_back(payload);
            });
        } else {
            println!("[Outstation]    Raw data (not a tunnel frame)");
        }
    }
}

struct TunnelOutstationInfo;
impl OutstationInformation for TunnelOutstationInfo {}

/// Run the tunnel server (outstation side)
pub async fn run_demo_outstation(
    config: RealDnp3Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!();
    println!("================================================================");
    println!("  PoC 3: DNP3-SSH Tunnel Server (Outstation)");
    println!("================================================================");
    println!();
    println!("  DNP3 Listen: {}", config.dnp3_addr);
    println!("  SSH Target:  127.0.0.1:22");
    println!("  Outstation:  {}", config.outstation_addr);
    println!("  Master:      {}", config.master_addr);
    println!();
    println!("  Data flow:");
    println!("    G112 (master->outstation) -> SSH server");
    println!("    SSH server -> G113 (outstation->master)");
    println!();
    println!("  Wireshark filter: tcp.port == {}", config.dnp3_addr.port());
    println!();
    println!("----------------------------------------------------------------");
    println!();

    let state = Arc::new(TunnelServerState::new());

    // Create outstation config with VT event buffer
    let mut outstation_config = OutstationConfig::new(
        EndpointAddress::try_new(config.outstation_addr).unwrap(),
        EndpointAddress::try_new(config.master_addr).unwrap(),
        EventBufferConfig::new(0, 0, 0, 0, 0, 0, 0, 0, 100),
    );
    outstation_config.decode_level = AppDecodeLevel::ObjectValues.into();

    // Create server
    let mut server = Server::new_tcp_server(LinkErrorMode::Close, config.dnp3_addr);

    let outstation = server.add_outstation(
        outstation_config,
        Box::new(TunnelOutstationApp::new(state.clone())),
        Box::new(TunnelOutstationInfo),
        DefaultControlHandler::create(),
        NullListener::create(),
        AddressFilter::Any,
    )?;

    // Initialize database with Virtual Terminal point
    outstation.transaction(|db| {
        db.add(0, Some(EventClass::Class1), VirtualTerminalConfig);
    });

    // Spawn SSH connection handler
    let ssh_state = state.clone();
    let outstation_handle = outstation.clone();
    tokio::spawn(async move {
        loop {
            // Check for data to send to SSH
            let data = {
                let mut queue = ssh_state.ssh_outbound.lock().await;
                queue.pop_front()
            };

            if let Some(data) = data {
                // Try to connect to SSH server if not connected
                let mut stream_guard = ssh_state.ssh_stream.lock().await;
                if stream_guard.is_none() {
                    match TcpStream::connect("127.0.0.1:22").await {
                        Ok(stream) => {
                            println!("[Outstation] Connected to SSH server");
                            *stream_guard = Some(stream);
                        }
                        Err(e) => {
                            println!("[Outstation] Failed to connect to SSH: {}", e);
                            continue;
                        }
                    }
                }

                // Send data to SSH
                if let Some(stream) = stream_guard.as_mut() {
                    if let Err(e) = stream.write_all(&data).await {
                        println!("[Outstation] SSH write error: {}", e);
                        *stream_guard = None;
                    } else {
                        println!("[Outstation] >> Sent {} bytes to SSH", data.len());
                    }
                }
            }

            // Check for data from SSH to send as G113 events
            {
                let mut stream_guard = ssh_state.ssh_stream.lock().await;
                if let Some(stream) = stream_guard.as_mut() {
                    let mut buf = [0u8; 1024];
                    match tokio::time::timeout(
                        Duration::from_millis(10),
                        stream.read(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(0)) => {
                            println!("[Outstation] SSH connection closed");
                            *stream_guard = None;
                        }
                        Ok(Ok(n)) => {
                            println!("[Outstation] << Received {} bytes from SSH", n);
                            let data = buf[..n].to_vec();

                            // Fragment and send as G113 events
                            let mut seq = ssh_state.sequence.lock().await;
                            let frames = fragment_data(&data, *seq);
                            *seq = seq.wrapping_add(frames.len() as u8);

                            for frame in frames {
                                let frame_bytes = frame.to_bytes();
                                println!(
                                    "[Outstation] >> G113 event: seq={}, len={}",
                                    frame.sequence,
                                    frame_bytes.len()
                                );

                                outstation_handle.transaction(|db| {
                                    if let Ok(vt) = VirtualTerminal::new(&frame_bytes) {
                                        db.update(0, &vt, UpdateOptions::detect_event());
                                    }
                                });
                            }
                        }
                        Ok(Err(e)) => {
                            println!("[Outstation] SSH read error: {}", e);
                            *stream_guard = None;
                        }
                        Err(_) => {} // Timeout, no data available
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    // Start server - must store the handle to keep server running
    println!("[Outstation] Server starting...");
    let _server_handle = server.bind().await?;
    println!("[Outstation] Server running. Press Ctrl+C to exit.");

    // Keep running (server handle must stay alive)
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

// ============================================================================
// MASTER (TUNNEL CLIENT)
// ============================================================================

/// Shared state for the tunnel client master
struct TunnelClientState {
    /// Queue of data received from SSH clients to send as G112
    dnp3_outbound: Mutex<VecDeque<Vec<u8>>>,
    /// Queue of data received from G113 events to send to SSH
    ssh_outbound: Mutex<VecDeque<Vec<u8>>>,
    /// Reassembler for incoming G113 frames
    reassembler: Mutex<FragmentReassembler>,
    /// Sequence number for outgoing G112 frames
    sequence: Mutex<u8>,
}

impl TunnelClientState {
    fn new() -> Self {
        Self {
            dnp3_outbound: Mutex::new(VecDeque::new()),
            ssh_outbound: Mutex::new(VecDeque::new()),
            reassembler: Mutex::new(FragmentReassembler::new()),
            sequence: Mutex::new(0),
        }
    }
}

/// Read handler that receives G113 events
struct TunnelReadHandler {
    state: Arc<TunnelClientState>,
}

impl TunnelReadHandler {
    fn new(state: Arc<TunnelClientState>) -> Self {
        Self { state }
    }
}

impl ReadHandler for TunnelReadHandler {
    fn begin_fragment(&mut self, _read_type: ReadType, header: ResponseHeader) -> MaybeAsync<()> {
        println!(
            "[Master] << Response (IIN: {:04X})",
            header.iin.iin1.value as u16 | ((header.iin.iin2.value as u16) << 8)
        );
        MaybeAsync::ready(())
    }

    fn end_fragment(&mut self, _read_type: ReadType, _header: ResponseHeader) -> MaybeAsync<()> {
        MaybeAsync::ready(())
    }

    fn handle_virtual_terminal_event<'a>(
        &mut self,
        info: HeaderInfo,
        iter: &'a mut dyn Iterator<Item = (&'a [u8], u16)>,
    ) {
        println!(
            "[Master] << G113 event: variation={}, is_event={}",
            info.variation, info.is_event
        );

        for (data, index) in iter {
            println!("[Master]    Port {}: {} bytes", index, data.len());

            // Try to parse as tunnel frame
            if let Ok(frame) = TunnelFrame::from_bytes(data) {
                println!(
                    "[Master]    Frame: seq={}, payload={}",
                    frame.sequence,
                    frame.payload.len()
                );

                // Queue for SSH forwarding
                let state = self.state.clone();
                let payload = frame.payload.clone();
                tokio::spawn(async move {
                    let mut queue = state.ssh_outbound.lock().await;
                    queue.push_back(payload);
                });
            }
        }
    }
}

struct TunnelAssociationHandler;
impl AssociationHandler for TunnelAssociationHandler {}

struct TunnelAssociationInfo;
impl AssociationInformation for TunnelAssociationInfo {
    fn task_start(&mut self, task_type: TaskType, fc: FunctionCode, _seq: Sequence) {
        if matches!(task_type, TaskType::WriteVirtualTerminal) {
            println!("[Master] >> G112 write task started (FC={:?})", fc);
        }
    }

    fn task_success(&mut self, task_type: TaskType, _fc: FunctionCode, _seq: Sequence) {
        if matches!(task_type, TaskType::WriteVirtualTerminal) {
            println!("[Master] >> G112 write succeeded");
        }
    }

    fn task_fail(&mut self, task_type: TaskType, error: TaskError) {
        println!("[Master] >> Task {:?} failed: {:?}", task_type, error);
    }
}

/// Run the tunnel client (master side)
pub async fn run_demo_master(
    config: RealDnp3Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!();
    println!("================================================================");
    println!("  PoC 3: DNP3-SSH Tunnel Client (Master)");
    println!("================================================================");
    println!();
    println!("  SSH Listen:  127.0.0.1:2222");
    println!("  DNP3:        {}", config.dnp3_addr);
    println!("  Master:      {}", config.master_addr);
    println!("  Outstation:  {}", config.outstation_addr);
    println!();
    println!("  Data flow:");
    println!("    SSH client -> G112 (master->outstation)");
    println!("    G113 (outstation->master) -> SSH client");
    println!();
    println!("  Connect with: ssh -p 2222 user@localhost");
    println!();
    println!("----------------------------------------------------------------");
    println!();

    let state = Arc::new(TunnelClientState::new());

    // Create master config
    let mut master_config =
        MasterChannelConfig::new(EndpointAddress::try_new(config.master_addr).unwrap());
    master_config.decode_level = AppDecodeLevel::ObjectValues.into();

    // Create channel
    let mut channel = spawn_master_tcp_client(
        LinkErrorMode::Close,
        master_config,
        EndpointList::new(config.dnp3_addr.to_string(), &[]),
        ConnectStrategy::default(),
        NullListener::create(),
    );

    // Association config - poll for events
    let assoc_config = AssociationConfig::new(
        EventClasses::all(),
        EventClasses::all(),
        Classes::all(),
        EventClasses::all(),
    );

    // Add association
    let mut association = channel
        .add_association(
            EndpointAddress::try_new(config.outstation_addr).unwrap(),
            assoc_config,
            Box::new(TunnelReadHandler::new(state.clone())),
            Box::new(TunnelAssociationHandler),
            Box::new(TunnelAssociationInfo),
        )
        .await?;

    // Add poll for class events (this receives G113 data)
    let _poll = association
        .add_poll(
            ReadRequest::class_scan(Classes::class123()),
            Duration::from_millis(100), // Poll every 100ms for low latency
        )
        .await?;

    println!("[Master] Enabling communications...");
    channel.enable().await?;

    // Spawn SSH listener
    let ssh_state = state.clone();
    let ssh_listener = TcpListener::bind("127.0.0.1:2222").await?;
    println!("[Master] SSH listener started on port 2222");

    // Store the current SSH client stream
    let ssh_client: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
    let ssh_client_reader = ssh_client.clone();
    let ssh_client_writer = ssh_client.clone();

    // Spawn task to accept SSH connections
    tokio::spawn(async move {
        loop {
            match ssh_listener.accept().await {
                Ok((stream, addr)) => {
                    println!("[Master] SSH client connected from {}", addr);
                    let mut guard = ssh_client_reader.lock().await;
                    *guard = Some(stream);
                }
                Err(e) => {
                    println!("[Master] Accept error: {}", e);
                }
            }
        }
    });

    // Spawn task to read from SSH client and queue for G112
    let read_state = state.clone();
    let read_client = ssh_client_writer.clone();
    tokio::spawn(async move {
        loop {
            let data = {
                let mut guard = read_client.lock().await;
                if let Some(stream) = guard.as_mut() {
                    let mut buf = [0u8; 1024];
                    match tokio::time::timeout(Duration::from_millis(10), stream.read(&mut buf))
                        .await
                    {
                        Ok(Ok(0)) => {
                            println!("[Master] SSH client disconnected");
                            *guard = None;
                            None
                        }
                        Ok(Ok(n)) => {
                            println!("[Master] << Received {} bytes from SSH client", n);
                            Some(buf[..n].to_vec())
                        }
                        Ok(Err(e)) => {
                            println!("[Master] SSH read error: {}", e);
                            *guard = None;
                            None
                        }
                        Err(_) => None, // Timeout
                    }
                } else {
                    None
                }
            };

            if let Some(data) = data {
                let mut queue = read_state.dnp3_outbound.lock().await;
                queue.push_back(data);
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    // Spawn task to write G113 data to SSH client
    let write_state = state.clone();
    let write_client = ssh_client.clone();
    tokio::spawn(async move {
        loop {
            let data = {
                let mut queue = write_state.ssh_outbound.lock().await;
                queue.pop_front()
            };

            if let Some(data) = data {
                let mut guard = write_client.lock().await;
                if let Some(stream) = guard.as_mut() {
                    if let Err(e) = stream.write_all(&data).await {
                        println!("[Master] SSH write error: {}", e);
                        *guard = None;
                    } else {
                        println!("[Master] >> Sent {} bytes to SSH client", data.len());
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    // Main loop: send G112 writes for queued SSH data
    println!("[Master] Running tunnel loop...");
    loop {
        let data = {
            let mut queue = state.dnp3_outbound.lock().await;
            queue.pop_front()
        };

        if let Some(data) = data {
            // Fragment into tunnel frames
            let mut seq = state.sequence.lock().await;
            let frames = fragment_data(&data, *seq);
            *seq = seq.wrapping_add(frames.len() as u8);

            // Send each frame as a G112 write
            for frame in frames {
                let frame_bytes = frame.to_bytes();
                println!(
                    "[Master] >> G112 write: seq={}, len={}",
                    frame.sequence,
                    frame_bytes.len()
                );

                let header = VirtualTerminalHeader::new(0, frame_bytes);
                if let Err(e) = association.write_virtual_terminal(vec![header]).await {
                    println!("[Master] G112 write error: {:?}", e);
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ============================================================================
// COMBINED TEST
// ============================================================================

/// Run both outstation and master in same process for testing
pub async fn run_combined_test() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = RealDnp3Config::default();

    println!();
    println!("================================================================");
    println!("  PoC 3: Combined DNP3-SSH Tunnel Test");
    println!("================================================================");
    println!();
    println!("  This runs both outstation and master in the same process.");
    println!("  Connect with: ssh -p 2222 user@localhost");
    println!();
    println!("  Wireshark filter: tcp.port == 20000");
    println!();

    // Start outstation
    let outstation_config = config.dnp3_addr;
    let outstation_handle = tokio::spawn(async move {
        let cfg = RealDnp3Config {
            dnp3_addr: outstation_config,
            ..Default::default()
        };
        if let Err(e) = run_demo_outstation(cfg).await {
            eprintln!("Outstation error: {}", e);
        }
    });

    // Give outstation time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start master
    let master_config = config.dnp3_addr;
    let master_handle = tokio::spawn(async move {
        let cfg = RealDnp3Config {
            dnp3_addr: master_config,
            ..Default::default()
        };
        if let Err(e) = run_demo_master(cfg).await {
            eprintln!("Master error: {}", e);
        }
    });

    // Wait for either to complete
    tokio::select! {
        _ = outstation_handle => {}
        _ = master_handle => {}
    }

    Ok(())
}
