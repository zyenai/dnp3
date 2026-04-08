# SSH Tunneling over DNP3 Virtual Terminal (PoC 3)

Proof-of-concept demonstrating SSH (or any TCP stream) tunneled through real
DNP3 Virtual Terminal objects (G112/G113) over an actual TCP connection.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  MASTER SIDE  (vt_tunnel_client)                                     │
│                                                                      │
│   ssh -p 2222 host                                                   │
│        │                                                             │
│   TcpListener :2222  ──►  DNP3 Master  ──► G112 WRITE ──► port 20000│
│                      ◄──  ReadHandler  ◄── G111 EVENT ◄─────────────│
└──────────────────────────────────────────────────────────────────────┘
                              DNP3/TCP  port 20000
┌──────────────────────────────────────────────────────────────────────┐
│  OUTSTATION SIDE  (vt_tunnel_server)                                 │
│                                                                      │
│   port 20000 ──► DNP3 Outstation ──► handle_virtual_terminal_write  │
│                                               │                      │
│                                         TcpStream :22  ──► sshd     │
│              G111 OctetString events ◄── mpsc channel ◄── sshd      │
└──────────────────────────────────────────────────────────────────────┘
```

**Data paths:**
- Master → Outstation: SSH client bytes sent as **G112 WRITE** requests
- Outstation → Master: SSH server bytes returned as **G111 OctetString events**
  polled by the master on a configurable interval

## Quick Start

Open three terminals.

**Terminal 1 — Tunnel server (outstation/IED side):**
```bash
cargo run -p example-virtual-terminal --bin vt_tunnel_server
```

**Terminal 2 — Tunnel client (master/SCADA side):**
```bash
cargo run -p example-virtual-terminal --bin vt_tunnel_client
```

**Terminal 3 — Connect via SSH through the tunnel:**
```bash
ssh -p 2222 localhost
```

All defaults are pre-wired: server listens on `0.0.0.0:20000`, client connects
to `127.0.0.1:20000`, SSH proxy listens on `127.0.0.1:2222`, and the server
forwards to the local SSH daemon on `127.0.0.1:22`.

## Command-Line Reference

### `vt_tunnel_server`

```
USAGE:
    vt_tunnel_server [OPTIONS]

OPTIONS:
    -d, --dnp3-listen <ADDR>    Address to listen for DNP3 connections
                                [default: 0.0.0.0:20000]

    -t, --target <ADDR>         SSH (or other TCP) server to forward to
                                [default: 127.0.0.1:22]

    --outstation-addr <N>       DNP3 link-layer address of this outstation
                                [default: 10]

    --master-addr <N>           DNP3 link-layer address of the master
                                [default: 1]

    -h, --help                  Print help
```

### `vt_tunnel_client`

```
USAGE:
    vt_tunnel_client [OPTIONS]

OPTIONS:
    -l, --listen <ADDR>         TCP address to accept SSH clients on
                                [default: 127.0.0.1:2222]

    -d, --dnp3-endpoint <ADDR>  DNP3 outstation to connect to
                                [default: 127.0.0.1:20000]

    --master-addr <N>           DNP3 link-layer address of this master
                                [default: 1]

    --outstation-addr <N>       DNP3 link-layer address of the outstation
                                [default: 10]

    --poll-interval <MS>        How often to poll the outstation for G111
                                OctetString events (lower = less latency)
                                [default: 100]

    -h, --help                  Print help
```

## Verifying Traffic in Wireshark

### Native Linux / Mac

Capture on the loopback interface with filter `tcp.port == 20000`:

```bash
# Wireshark GUI
# Interface: lo  |  Filter: tcp.port == 20000

# Or with tshark / tcpdump in a terminal
sudo tshark -i lo -f "tcp port 20000"
sudo tcpdump -i lo -n port 20000 -X
```

### WSL2 (Windows Subsystem for Linux)

Traffic between two WSL processes on `127.0.0.1` stays inside the WSL kernel
and is **not visible** to Windows Wireshark on the loopback or Npcap adapter.

**Option A — Capture inside WSL (quickest):**
```bash
sudo tcpdump -i lo -n port 20000 -X
```

**Option B — Route through the WSL virtual ethernet adapter so Windows
Wireshark can see it:**

1. Find the WSL2 VM IP:
   ```bash
   ip addr show eth0 | grep 'inet '
   # e.g. 172.26.48.1
   ```
2. Start the client pointing at that IP instead of `127.0.0.1`:
   ```bash
   cargo run -p example-virtual-terminal --bin vt_tunnel_client -- \
       --dnp3-endpoint 172.26.48.1:20000
   ```
3. In Windows Wireshark, capture on **"vEthernet (WSL)"** with filter:
   ```
   tcp.port == 20000
   ```

The server already binds to `0.0.0.0:20000` so no server-side change is needed.

## How It Works

### G112 Write (master → outstation)

The master calls `AssociationHandle::write_virtual_terminal(port, data)`, which
queues a `WriteVirtualTerminalTask`. The task encodes a DNP3 WRITE request:

```
G112 VarX  |  Qualifier 0x00 (Range8)  |  start=port  stop=port  |  data[X]
```

where `X = data.len()` (max 240 bytes per write; larger payloads are chunked).

The outstation's session layer dispatches each `(data, port_index)` pair to
`OutstationApplication::handle_virtual_terminal_write()`. The tunnel
implementation forwards that data to the SSH server over a plain TCP stream.

### G111 OctetString Events (outstation → master)

When the SSH server responds, the outstation bridge calls:

```rust
db.update(VT_PORT, &OctetString::new(&chunk)?, UpdateOptions::new(false, EventMode::Force));
```

`EventMode::Force` ensures an event is always generated even if the byte
content is identical to the previous chunk. The master polls class-1 events
every `--poll-interval` ms and receives these as G111 objects, which the
`VtReadHandler` forwards to the waiting SSH client socket.

## Library Changes and Backward Compatibility

These changes were made to the `dnp3` crate to support real G112 writes.
All changes are purely additive — existing applications are unaffected.

| Change | File | Impact on existing code |
|--------|------|------------------------|
| `write_virtual_terminal_output(port, data)` added to `HeaderWriter` | `app/format/write.rs` | Additive — no existing method changed |
| `WriteVirtualTerminalTask` (new file) | `master/tasks/virtual_terminal.rs` | Additive — new file only |
| `NonReadTask::VirtualTerminalWrite` new enum variant | `master/tasks/mod.rs` | Additive — all match arms updated |
| `TaskType::WriteVirtualTerminal` new enum variant | `master/handler.rs` | Additive — new variant only |
| `AssociationHandle::write_virtual_terminal()` new method | `master/handler.rs` | Additive — new method only |
| `OutstationApplication::handle_virtual_terminal_write()` new trait method | `outstation/traits.rs` | Default impl returns `Ok(())` — existing impls inherit automatically |
| G112 handling in session write handler | `outstation/session.rs` | Previously returned `NO_FUNC_CODE_SUPPORT`; now calls callback which defaults to `Ok(())` — no change for apps that never receive G112 |

## MITRE ATT&CK References

| ID | Technique |
|----|-----------|
| T1572 | Protocol Tunneling |
| T1071 | Application Layer Protocol |
| T0869 | Standard Application Layer Protocol (ICS) |
| T0886 | Remote Services |

## Authorization

For authorized security research and penetration testing only.
Use exclusively in controlled environments with explicit permission.
