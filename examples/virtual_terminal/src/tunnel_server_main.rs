//! PoC 3: SSH Tunnel Server over DNP3 Virtual Terminal
//!
//! This binary implements the server side of the SSH tunnel that runs on
//! the outstation/IED device.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p example-virtual-terminal --bin vt_tunnel_server -- --help
//!
//! # Start server with defaults (forwards to local SSH)
//! cargo run -p example-virtual-terminal --bin vt_tunnel_server -- \
//!     --target 127.0.0.1:22
//! ```
//!
//! ## MITRE ATT&CK References
//! - T1572: Protocol Tunneling
//! - T1071: Application Layer Protocol
//! - T0869: Standard Application Layer Protocol (ICS)
//! - T0886: Remote Services

mod common;
mod poc3_real_dnp3;
mod poc3_ssh_tunnel;

use std::sync::Arc;
use std::time::Duration;

use poc3_ssh_tunnel::{SimulatedVtHandler, TunnelServer, TunnelServerConfig};
use tokio::sync::Mutex;

/// Command-line arguments for the tunnel server
struct Args {
    /// Address to listen for DNP3 connections
    dnp3_listen: String,
    /// Target endpoint to forward connections to
    target: String,
    /// DNP3 outstation address
    outstation_addr: u16,
    /// DNP3 master address
    master_addr: u16,
    /// Virtual terminal port index
    vt_port: u16,
    /// Run integration test instead of server
    test_mode: bool,
    /// Run real DNP3 demo (visible in Wireshark)
    real_dnp3: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            dnp3_listen: "0.0.0.0:20000".into(),
            target: "127.0.0.1:22".into(),
            outstation_addr: 10,
            master_addr: 1,
            vt_port: 0,
            test_mode: false,
            real_dnp3: false,
        }
    }
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut argv = std::env::args().skip(1);

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-d" | "--dnp3-listen" => {
                if let Some(val) = argv.next() {
                    args.dnp3_listen = val;
                }
            }
            "-t" | "--target" => {
                if let Some(val) = argv.next() {
                    args.target = val;
                }
            }
            "--outstation-addr" => {
                if let Some(val) = argv.next() {
                    args.outstation_addr = val.parse().unwrap_or(10);
                }
            }
            "--master-addr" => {
                if let Some(val) = argv.next() {
                    args.master_addr = val.parse().unwrap_or(1);
                }
            }
            "--vt-port" => {
                if let Some(val) = argv.next() {
                    args.vt_port = val.parse().unwrap_or(0);
                }
            }
            "--test" => {
                args.test_mode = true;
            }
            "--real-dnp3" => {
                args.real_dnp3 = true;
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                print_help();
                std::process::exit(1);
            }
        }
    }

    args
}

fn print_help() {
    println!(
        r#"
DNP3-SSH Tunnel Server (PoC 3)

USAGE:
    vt_tunnel_server [OPTIONS]

OPTIONS:
    -d, --dnp3-listen <ADDR>      Address to listen for DNP3 connections [default: 0.0.0.0:20000]
    -t, --target <ADDR>           Target endpoint to forward to [default: 127.0.0.1:22]
    --outstation-addr <ADDR>      DNP3 outstation address [default: 10]
    --master-addr <ADDR>          DNP3 master address [default: 1]
    --vt-port <PORT>              Virtual terminal port index [default: 0]
    --test                        Run integration test mode
    --real-dnp3                   Run real DNP3 demo (generates Wireshark-visible traffic)
    -h, --help                    Print help information

EXAMPLE:
    # Start the tunnel server forwarding to SSH
    vt_tunnel_server --target 127.0.0.1:22

    # Forward to a different service
    vt_tunnel_server --target 192.168.1.50:80

SECURITY NOTICE:
    This tool is for authorized security research and testing only.
    Use only with proper authorization in controlled environments.
"#
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let args = parse_args();

    println!();
    println!("================================================================");
    println!("  PoC 3: DNP3-SSH Tunnel Server");
    println!("  Protocol Tunneling over DNP3 Virtual Terminal Objects");
    println!("================================================================");
    println!();
    println!("  DNP3 Listen: {}", args.dnp3_listen);
    println!("  Target:      {}", args.target);
    println!("  Outstation:  {}", args.outstation_addr);
    println!("  Master:      {}", args.master_addr);
    println!("  VT Port:     {}", args.vt_port);
    println!();
    println!("----------------------------------------------------------------");
    println!();

    if args.test_mode {
        return run_integration_test().await;
    }

    if args.real_dnp3 {
        let config = poc3_real_dnp3::RealDnp3Config {
            dnp3_addr: args.dnp3_listen.parse().unwrap_or_else(|_| "127.0.0.1:20000".parse().unwrap()),
            master_addr: args.master_addr,
            outstation_addr: args.outstation_addr,
        };
        return poc3_real_dnp3::run_demo_outstation(config).await.map_err(|e| -> Box<dyn std::error::Error> { e });
    }

    let config = TunnelServerConfig {
        dnp3_listen_addr: args.dnp3_listen,
        target_endpoint: args.target,
        outstation_addr: args.outstation_addr,
        master_addr: args.master_addr,
        vt_port: args.vt_port,
        connect_timeout: Duration::from_secs(10),
        ..Default::default()
    };

    let vt_handler = Arc::new(Mutex::new(SimulatedVtHandler::new()));
    let server = TunnelServer::new(config);

    // Note: In production, the VT handler would be integrated with
    // the actual DNP3 outstation. This simulated version demonstrates
    // the architecture and data flow.
    println!("[TunnelServer] Running in simulated mode");
    println!("[TunnelServer] Waiting for VT data...");
    println!();
    println!("In production, integrate with DNP3 outstation:");
    println!("  1. Handle g112 writes via handle_virtual_terminal_output()");
    println!("  2. Queue g113 events via OctetString database updates");
    println!();

    server.run_simulated(vt_handler).await
}

/// Run integration test demonstrating tunnel data flow
async fn run_integration_test() -> Result<(), Box<dyn std::error::Error>> {
    use poc3_ssh_tunnel::{fragment_data, FragmentReassembler, SimulatedVtChannel, TunnelFrame};

    println!("Running Integration Test");
    println!("------------------------");
    println!();

    // Create simulated channels
    let client_channel = Arc::new(Mutex::new(SimulatedVtChannel::new()));
    let server_handler = Arc::new(Mutex::new(SimulatedVtHandler::new()));

    // Test 1: Reset handshake
    println!("Test 1: Reset Handshake");
    {
        let mut client = client_channel.lock().await;
        let reset = TunnelFrame::new_reset();
        client.write_vt(&reset.to_bytes());
        println!("  Client -> Server: RESET frame");
    }

    {
        let mut client = client_channel.lock().await;
        let mut server = server_handler.lock().await;
        for data in client.drain_outbound() {
            server.receive_g112(data);
        }
    }

    {
        let mut server = server_handler.lock().await;
        let data = server.poll_inbound().unwrap();
        let frame = TunnelFrame::from_bytes(&data).unwrap();
        assert!(frame.is_reset());
        println!("  Server received RESET: OK");

        let reset_ack = TunnelFrame::new_reset();
        server.queue_g113(&reset_ack.to_bytes());
        println!("  Server -> Client: RESET ACK");
    }
    println!("  [PASS]");
    println!();

    // Test 2: Data transfer (simulated SSH banner)
    println!("Test 2: Data Transfer (SSH Banner Simulation)");
    let ssh_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
    {
        let mut client = client_channel.lock().await;
        let frames = fragment_data(ssh_banner, 0);
        for frame in &frames {
            client.write_vt(&frame.to_bytes());
        }
        println!("  Client -> Server: {} bytes ({} frame(s))", ssh_banner.len(), frames.len());
    }

    {
        let mut client = client_channel.lock().await;
        let mut server = server_handler.lock().await;
        for data in client.drain_outbound() {
            server.receive_g112(data);
        }
    }

    {
        let mut server = server_handler.lock().await;
        let mut reassembler = FragmentReassembler::new();

        while let Some(data) = server.poll_inbound() {
            let frame = TunnelFrame::from_bytes(&data).unwrap();
            if let Some(msg) = reassembler.add_frame(frame).unwrap() {
                assert_eq!(&msg, ssh_banner);
                println!("  Server received: \"{}\"", String::from_utf8_lossy(&msg).trim());
            }
        }
    }
    println!("  [PASS]");
    println!();

    // Test 3: Large data fragmentation
    println!("Test 3: Large Data Fragmentation (1KB)");
    let large_data: Vec<u8> = (0..1024).map(|i| i as u8).collect();
    {
        let mut client = client_channel.lock().await;
        let frames = fragment_data(&large_data, 0);
        println!("  Fragmenting {} bytes into {} frames", large_data.len(), frames.len());
        for frame in &frames {
            client.write_vt(&frame.to_bytes());
        }
    }

    {
        let mut client = client_channel.lock().await;
        let mut server = server_handler.lock().await;
        for data in client.drain_outbound() {
            server.receive_g112(data);
        }
    }

    {
        let mut server = server_handler.lock().await;
        let mut reassembler = FragmentReassembler::new();
        let mut received_len = 0;

        while let Some(data) = server.poll_inbound() {
            let frame = TunnelFrame::from_bytes(&data).unwrap();
            if let Some(msg) = reassembler.add_frame(frame).unwrap() {
                assert_eq!(msg.len(), large_data.len());
                assert_eq!(msg, large_data);
                received_len = msg.len();
            }
        }
        println!("  Server received {} bytes intact", received_len);
    }
    println!("  [PASS]");
    println!();

    // Test 4: Close handshake
    println!("Test 4: Close Handshake");
    {
        let mut client = client_channel.lock().await;
        let close = TunnelFrame::new_close(5);
        client.write_vt(&close.to_bytes());
        println!("  Client -> Server: CLOSE frame (seq=5)");
    }

    {
        let mut client = client_channel.lock().await;
        let mut server = server_handler.lock().await;
        for data in client.drain_outbound() {
            server.receive_g112(data);
        }
    }

    {
        let mut server = server_handler.lock().await;
        let data = server.poll_inbound().unwrap();
        let frame = TunnelFrame::from_bytes(&data).unwrap();
        assert!(frame.is_close());
        assert_eq!(frame.sequence, 5);
        println!("  Server received CLOSE (seq={}): OK", frame.sequence);
    }
    println!("  [PASS]");
    println!();

    println!("================================================================");
    println!("  All Integration Tests PASSED");
    println!("================================================================");
    println!();
    println!("Ready for PoC validation:");
    println!("  1. Start server: cargo run -p example-virtual-terminal --bin vt_tunnel_server");
    println!("  2. Start client: cargo run -p example-virtual-terminal --bin vt_tunnel_client");
    println!("  3. Connect: ssh -p 2222 localhost");
    println!();

    Ok(())
}
