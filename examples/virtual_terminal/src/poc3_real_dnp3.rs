//! PoC 3: Real DNP3 Traffic Demo with Virtual Terminal Objects
//!
//! This module demonstrates real DNP3 traffic using Virtual Terminal objects
//! (Groups 112/113) as specified in IEEE 1815-2012.
//!
//! Run the outstation and master in separate terminals to see DNP3 packets
//! in Wireshark with proper VT object groups.
//!
//! ## Usage
//!
//! Terminal 1 - Start outstation:
//! ```bash
//! cargo run -p example-virtual-terminal --bin vt_tunnel_server -- --real-dnp3
//! ```
//!
//! Terminal 2 - Start master:
//! ```bash
//! cargo run -p example-virtual-terminal --bin vt_tunnel_client -- --real-dnp3
//! ```
//!
//! Wireshark filter: `tcp.port == 20000`
//!
//! ## DNP3 Object Groups
//!
//! - Group 112: Virtual Terminal Output Block (master -> outstation)
//! - Group 113: Virtual Terminal Event Data (outstation -> master)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dnp3::app::measurement::*;
use dnp3::app::*;
use dnp3::decode::*;
use dnp3::link::*;
use dnp3::master::*;
use dnp3::outstation::database::*;
use dnp3::outstation::*;
use dnp3::tcp::*;

use crate::poc3_ssh_tunnel::framing::{fragment_data, TunnelFrame};

/// Configuration for real DNP3 demo
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
            outstation_addr: 1024,
        }
    }
}

// ============================================================================
// OUTSTATION
// ============================================================================

struct DemoOutstationApp;

impl OutstationApplication for DemoOutstationApp {
    fn get_processing_delay_ms(&self) -> u16 {
        0
    }
}

struct DemoOutstationInfo;
impl OutstationInformation for DemoOutstationInfo {}

/// Run the demo outstation - generates Virtual Terminal events with tunnel frames
pub async fn run_demo_outstation(
    config: RealDnp3Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!();
    println!("================================================================");
    println!("  PoC 3: Real DNP3 Outstation with Virtual Terminal Objects");
    println!("================================================================");
    println!();
    println!("  Listening on: {}", config.dnp3_addr);
    println!("  Outstation address: {}", config.outstation_addr);
    println!("  Master address: {}", config.master_addr);
    println!();
    println!("  DNP3 Objects:");
    println!("    - Group 112: Virtual Terminal Output Block (master -> outstation)");
    println!("    - Group 113: Virtual Terminal Event Data (outstation -> master)");
    println!();
    println!("  Wireshark filter: tcp.port == {}", config.dnp3_addr.port());
    println!();
    println!("----------------------------------------------------------------");
    println!();

    // Create outstation config with VT event buffer
    let mut outstation_config = OutstationConfig::new(
        EndpointAddress::try_new(config.outstation_addr).unwrap(),
        EndpointAddress::try_new(config.master_addr).unwrap(),
        // Last parameter is max_virtual_terminal events
        EventBufferConfig::new(0, 0, 0, 0, 0, 0, 0, 0, 100),
    );
    outstation_config.decode_level = AppDecodeLevel::ObjectValues.into();

    // Create server
    let mut server = Server::new_tcp_server(LinkErrorMode::Close, config.dnp3_addr);

    let outstation = server.add_outstation(
        outstation_config,
        Box::new(DemoOutstationApp),
        Box::new(DemoOutstationInfo),
        DefaultControlHandler::create(),
        NullListener::create(),
        AddressFilter::Any,
    )?;

    // Initialize database with Virtual Terminal point (port 0)
    outstation.transaction(|db| {
        db.add(0, Some(EventClass::Class1), VirtualTerminalConfig);
    });

    // Spawn event generator
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    tokio::spawn(async move {
        let mut seq: u8 = 0;

        // Simulated data - SSH banner
        let ssh_banner = b"SSH-2.0-DNP3_VT_Tunnel\r\n";

        println!("[Outstation] Starting VT event generator...");
        println!("[Outstation] Will generate Group 113 (VT Event) objects with tunnel frames");
        println!();

        // Initial delay
        tokio::time::sleep(Duration::from_secs(2)).await;

        while running_clone.load(Ordering::Relaxed) {
            // Generate tunnel frames
            let frames = fragment_data(ssh_banner, seq);

            for frame in &frames {
                let frame_bytes = frame.to_bytes();
                println!(
                    "[Outstation] Generating VT event: seq={}, len={}, more={}",
                    frame.sequence,
                    frame.payload.len(),
                    frame.is_more_fragments()
                );

                outstation.transaction(|db| {
                    if let Ok(vt_data) = VirtualTerminal::new(&frame_bytes) {
                        db.update(0, &vt_data, UpdateOptions::detect_event());
                    }
                });
            }

            seq = seq.wrapping_add(frames.len() as u8);

            // Wait before next batch
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Run server
    println!("[Outstation] Server starting...");
    server.bind().await?;

    // Keep running until interrupted
    println!("[Outstation] Server running. Press Ctrl+C to exit.");
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

// ============================================================================
// MASTER
// ============================================================================

/// Read handler that prints received Virtual Terminal events
struct DemoReadHandler;

impl ReadHandler for DemoReadHandler {
    fn begin_fragment(&mut self, _read_type: ReadType, header: ResponseHeader) -> MaybeAsync<()> {
        println!(
            "[Master] << Response fragment (IIN: {:04X})",
            header.iin.iin1.value as u16 | ((header.iin.iin2.value as u16) << 8)
        );
        MaybeAsync::ready(())
    }

    fn end_fragment(&mut self, _read_type: ReadType, _header: ResponseHeader) -> MaybeAsync<()> {
        println!("[Master] << Fragment complete");
        MaybeAsync::ready(())
    }

    fn handle_virtual_terminal_output<'a>(
        &mut self,
        info: HeaderInfo,
        iter: &'a mut dyn Iterator<Item = (&'a [u8], u16)>,
    ) {
        println!(
            "[Master] << VT Output (G112) header: variation={}, is_event={}",
            info.variation, info.is_event
        );
        self.handle_vt_data(iter, "Output");
    }

    fn handle_virtual_terminal_event<'a>(
        &mut self,
        info: HeaderInfo,
        iter: &'a mut dyn Iterator<Item = (&'a [u8], u16)>,
    ) {
        println!(
            "[Master] << VT Event (G113) header: variation={}, is_event={}",
            info.variation, info.is_event
        );
        self.handle_vt_data(iter, "Event");
    }
}

impl DemoReadHandler {
    fn handle_vt_data<'a>(
        &mut self,
        iter: &'a mut dyn Iterator<Item = (&'a [u8], u16)>,
        vt_type: &str,
    ) {
        for (data, index) in iter {
            println!(
                "[Master] << VT {} [port {}]: {} bytes",
                vt_type,
                index,
                data.len()
            );

            // Try to parse as tunnel frame
            if let Ok(frame) = TunnelFrame::from_bytes(data) {
                println!(
                    "[Master]    Tunnel frame: seq={}, flags={:02X}, payload={} bytes",
                    frame.sequence,
                    frame.flags,
                    frame.payload.len()
                );

                if frame.is_data() && !frame.payload.is_empty() {
                    // Try to print as ASCII
                    let ascii: String = frame
                        .payload
                        .iter()
                        .map(|&b| {
                            if b.is_ascii_graphic() || b == b' ' {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    println!("[Master]    Payload (ASCII): {}", ascii);
                }
            } else {
                // Print raw hex
                let hex: String = data.iter().map(|b| format!("{:02X}", b)).collect();
                println!("[Master]    Raw hex: {}", hex);
            }
        }
    }
}

struct DemoAssociationHandler;
impl AssociationHandler for DemoAssociationHandler {}

struct DemoAssociationInfo;
impl AssociationInformation for DemoAssociationInfo {
    fn task_start(&mut self, task_type: TaskType, fc: FunctionCode, _seq: Sequence) {
        println!("[Master] >> Task {:?} started (FC={:?})", task_type, fc);
    }

    fn task_success(&mut self, task_type: TaskType, _fc: FunctionCode, _seq: Sequence) {
        println!("[Master] >> Task {:?} succeeded", task_type);
    }

    fn task_fail(&mut self, task_type: TaskType, error: TaskError) {
        println!("[Master] >> Task {:?} failed: {:?}", task_type, error);
    }
}

/// Run the demo master - polls for Virtual Terminal events
pub async fn run_demo_master(
    config: RealDnp3Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!();
    println!("================================================================");
    println!("  PoC 3: Real DNP3 Master with Virtual Terminal Objects");
    println!("================================================================");
    println!();
    println!("  Connecting to: {}", config.dnp3_addr);
    println!("  Master address: {}", config.master_addr);
    println!("  Outstation address: {}", config.outstation_addr);
    println!();
    println!("  DNP3 Objects:");
    println!("    - Group 112: Virtual Terminal Output Block (master -> outstation)");
    println!("    - Group 113: Virtual Terminal Event Data (outstation -> master)");
    println!();
    println!("  Wireshark filter: tcp.port == {}", config.dnp3_addr.port());
    println!();
    println!("----------------------------------------------------------------");
    println!();

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
            Box::new(DemoReadHandler),
            Box::new(DemoAssociationHandler),
            Box::new(DemoAssociationInfo),
        )
        .await?;

    // Add poll for class events
    let _poll = association
        .add_poll(
            ReadRequest::class_scan(Classes::class123()),
            Duration::from_secs(2),
        )
        .await?;

    println!("[Master] Enabling communications...");
    channel.enable().await?;

    println!("[Master] Polling for VT events (G113) every 2 seconds");
    println!("[Master] Press Ctrl+C to exit");
    println!();

    // Keep running
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
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
    println!("  PoC 3: Real DNP3 Combined Test with Virtual Terminal Objects");
    println!("  This generates REAL DNP3 traffic on port 20000");
    println!("  Using Group 112/113 (Virtual Terminal) objects");
    println!("================================================================");
    println!();
    println!("Wireshark filter: tcp.port == 20000");
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
