//! PoC 3: SSH Tunnel Client over DNP3 Virtual Terminal
//!
//! This binary implements the client side of the SSH tunnel that runs on
//! the master/SCADA station.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p example-virtual-terminal --bin vt_tunnel_client -- --help
//!
//! # Start client with defaults
//! cargo run -p example-virtual-terminal --bin vt_tunnel_client -- \
//!     --dnp3-endpoint 127.0.0.1:20000
//!
//! # Connect via SSH
//! ssh -p 2222 user@localhost
//! ```
//!
//! ## MITRE ATT&CK References
//! - T1572: Protocol Tunneling
//! - T1071: Application Layer Protocol
//! - T0869: Standard Application Layer Protocol (ICS)

mod common;
mod poc3_ssh_tunnel;

use std::time::Duration;

use poc3_ssh_tunnel::{TunnelClient, TunnelClientConfig};

/// Command-line arguments for the tunnel client
struct Args {
    /// Address to listen for incoming TCP connections
    listen: String,
    /// DNP3 outstation endpoint to connect to
    dnp3_endpoint: String,
    /// DNP3 master address
    master_addr: u16,
    /// DNP3 outstation address
    outstation_addr: u16,
    /// Virtual terminal port index
    vt_port: u16,
    /// Polling interval in milliseconds
    poll_interval: u64,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:2222".into(),
            dnp3_endpoint: "127.0.0.1:20000".into(),
            master_addr: 1,
            outstation_addr: 10,
            vt_port: 0,
            poll_interval: 50,
        }
    }
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut argv = std::env::args().skip(1);

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-l" | "--listen" => {
                if let Some(val) = argv.next() {
                    args.listen = val;
                }
            }
            "-d" | "--dnp3-endpoint" => {
                if let Some(val) = argv.next() {
                    args.dnp3_endpoint = val;
                }
            }
            "--master-addr" => {
                if let Some(val) = argv.next() {
                    args.master_addr = val.parse().unwrap_or(1);
                }
            }
            "--outstation-addr" => {
                if let Some(val) = argv.next() {
                    args.outstation_addr = val.parse().unwrap_or(10);
                }
            }
            "--vt-port" => {
                if let Some(val) = argv.next() {
                    args.vt_port = val.parse().unwrap_or(0);
                }
            }
            "--poll-interval" => {
                if let Some(val) = argv.next() {
                    args.poll_interval = val.parse().unwrap_or(50);
                }
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
DNP3-SSH Tunnel Client (PoC 3)

USAGE:
    vt_tunnel_client [OPTIONS]

OPTIONS:
    -l, --listen <ADDR>           Address to listen for SSH connections [default: 127.0.0.1:2222]
    -d, --dnp3-endpoint <ADDR>    DNP3 outstation to connect to [default: 127.0.0.1:20000]
    --master-addr <ADDR>          DNP3 master address [default: 1]
    --outstation-addr <ADDR>      DNP3 outstation address [default: 10]
    --vt-port <PORT>              Virtual terminal port index [default: 0]
    --poll-interval <MS>          VT polling interval in milliseconds [default: 50]
    -h, --help                    Print help information

EXAMPLE:
    # Start the tunnel client
    vt_tunnel_client --dnp3-endpoint 192.168.1.100:20000

    # Then connect via SSH
    ssh -p 2222 user@localhost

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
    println!("  PoC 3: DNP3-SSH Tunnel Client");
    println!("  Protocol Tunneling over DNP3 Virtual Terminal Objects");
    println!("================================================================");
    println!();
    println!("  Listen:      {}", args.listen);
    println!("  DNP3:        {}", args.dnp3_endpoint);
    println!("  Master:      {}", args.master_addr);
    println!("  Outstation:  {}", args.outstation_addr);
    println!("  VT Port:     {}", args.vt_port);
    println!("  Poll:        {} ms", args.poll_interval);
    println!();
    println!("  Connect with: ssh -p {} localhost", args.listen.split(':').last().unwrap_or("2222"));
    println!();
    println!("----------------------------------------------------------------");
    println!();

    let config = TunnelClientConfig {
        listen_addr: args.listen,
        dnp3_endpoint: args.dnp3_endpoint,
        master_addr: args.master_addr,
        outstation_addr: args.outstation_addr,
        vt_port: args.vt_port,
        poll_interval: Duration::from_millis(args.poll_interval),
        ..Default::default()
    };

    let mut client = TunnelClient::new(config).await?;
    client.run().await
}
