# DNP3 Virtual Terminal Examples

Proof-of-concept implementations demonstrating DNP3 Virtual Terminal Objects
(Groups 112/113) for security research purposes.

## Overview

Virtual Terminal Objects (Groups 112 and 113) provide a mechanism for transmitting
arbitrary binary data through DNP3 connections. This functionality is defined in
IEEE 1815-2012 Section 5.2.3.

- **Group 112**: Virtual Terminal Output Block - Data going TO the outstation
- **Group 113**: Virtual Terminal Event Data - Data coming FROM the outstation

The variation number (1-255) indicates the data length in bytes.

## Examples

| Example | Description | Run Command |
|---------|-------------|-------------|
| vt_ieee_session | IEEE 1815-2012 Section 5.2.3 example | `cargo run -p example-virtual-terminal` |

## IEEE 1815-2012 Section 5.2.3 Example Session

The standard provides this exact example of a VT session:

```
Step  Direction  Message                        Comment
----  ---------  -----------------------------  ------------------------------
1     M->O       Write g112v1, data='<CR>'      Wakeup command (0x0D)
2     O->M       Null response                  Outstation has no data to send
3     M->O       Read g113v0                    Master polls for VT data
4     O->M       Null response                  Outstation still has no data
5     M->O       Read g113v0                    Master polls again
6     O->M       Respond with g113v3, 'OK<CR>'  Response received (0x4F 0x4B 0x0D)
7     M->O       Write g112v6, 'CLEAR<CR>'      Clear command
8     M->O       Write g112v7, 'LOGOFF<CR>'     Logoff command
9     M->O       Read g113v0                    Master polls for response
10    O->M       Respond with g113v7,           Combined responses
                 'OK<CR>BYE<CR>'

Legend:
  M = Master, O = Outstation
  <CR> = Carriage Return (0x0D)
  g112vN = Group 112, Variation N (N = byte length)
  g113vN = Group 113, Variation N (N = byte length)
```

## Protocol Details

### Group 112 - Virtual Terminal Output Block

- **Direction**: Master -> Outstation
- **Purpose**: Send arbitrary binary data to the outstation's virtual terminal
- **Variation**: Indicates the number of octets in the data (1-255)
- **Point Index**: Specifies the virtual port/channel number

### Group 113 - Virtual Terminal Event Data

- **Direction**: Outstation -> Master
- **Purpose**: Send response data from the outstation's virtual terminal
- **Variation**: Indicates the number of octets in the data (1-255)
- **Point Index**: Specifies the virtual port/channel number

## Implementation Status

The dnp3 library currently supports:

- [x] Parsing of Group 112 objects (ranged format)
- [x] Parsing of Group 113 objects (prefixed/event format)
- [x] ReadHandler callbacks for receiving VT data (`ReadHandler::handle_virtual_terminal_event`)
- [x] Master API for writing Group 112 data (`AssociationHandle::write_virtual_terminal`)
- [x] Outstation callbacks for receiving Group 112 writes (`OutstationApplication::handle_virtual_terminal_write`)
- [x] Outstation generation of Group 113 events (`VirtualTerminal` + `db.add`/`db.update` with `VirtualTerminalConfig`)

See [TUNNEL.md](TUNNEL.md) for the full SSH tunneling PoC built on these primitives.

This example uses a simulated terminal interpreter to demonstrate the protocol
flow defined in IEEE 1815-2012.

## Live SSH-over-DNP3 Tunnel Test (with PCAP capture)

This walkthrough reproduces a real, interactive SSH session carried over DNP3
Virtual Terminal objects — SSH client bytes travel as **G112** writes, and the SSH
server's responses travel back as **G113** events — and captures the DNP3 traffic to a
PCAP for inspection in Wireshark. All commands run on a single host over loopback.

> SSH and Telnet are both opaque interactive byte streams, so the same tunnel transports
> either; just point `--target` at a Telnet daemon and connect with `telnet` instead.

### 1. Prerequisites

```bash
# An SSH daemon to tunnel to (any reachable sshd works; this uses the local one on :22)
sudo systemctl start ssh        # or: sudo service ssh start
ss -ltn '( sport = :22 )'       # confirm sshd is listening

# Tools used below
which ssh tcpdump tshark        # tshark is optional (CLI inspection); Wireshark works too
```

### 2. (Test convenience) enable key-based login to the local sshd

So the session can run non-interactively. This adds a **throwaway** key for loopback
testing only — remove it afterward (step 7).

```bash
ssh-keygen -t ed25519 -N "" -f /tmp/vt_tunnel_key -q
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat /tmp/vt_tunnel_key.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys

# baseline: confirm the key works directly against :22 (not yet through the tunnel)
ssh -i /tmp/vt_tunnel_key -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=no localhost 'echo DIRECT_OK'
```

### 3. Start capturing the DNP3 traffic

The DNP3 link between the two tunnel processes runs on TCP **20000** — DNP3's registered
port, which the Wireshark/tshark DNP3 dissector decodes automatically. Capture it on the
loopback interface (run in its own terminal; needs sudo):

```bash
sudo tcpdump -i lo -w /tmp/vt_tunnel.pcap 'tcp port 20000' &
TCPDUMP_PID=$!
```

> On WSL2, loopback traffic between two WSL processes is only visible to `tcpdump`/`tshark`
> **inside** WSL, not to Windows Wireshark. See [TUNNEL.md](TUNNEL.md#verifying-traffic-in-wireshark)
> for how to route through the WSL vEthernet adapter so Windows Wireshark can see it.

### 4. Start the tunnel (outstation side, then master side)

```bash
# Terminal A — outstation: serves DNP3 on :20000, bridges to the local sshd on :22
cargo run -p example-virtual-terminal --bin vt_tunnel_server -- \
    --dnp3-listen 127.0.0.1:20000 --target 127.0.0.1:22

# Terminal B — master: accepts SSH on :2222, speaks DNP3 to the outstation on :20000
cargo run -p example-virtual-terminal --bin vt_tunnel_client -- \
    --listen 127.0.0.1:2222 --dnp3-endpoint 127.0.0.1:20000
```

Each side prints a `[Bridge]`/`[Client]` banner once the DNP3 association is up.

### 5. Run an SSH session through the tunnel

```bash
ssh -i /tmp/vt_tunnel_key -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 localhost 'echo TUNNELED_OK; hostname; uname -sr; seq 1 200 | tr "\n" " "; echo'
```

You should see `TUNNELED_OK` and the command output. The outstation terminal logs the
byte flow, e.g. `Master → SSH: 240 bytes` (G112 in) and `SSH → Master: 1120 bytes (g113)`
(G113 out), with responses larger than 240 bytes chunked into multiple G113 events.

### 6. Stop the capture and confirm G113 on the wire

```bash
sudo kill $TCPDUMP_PID          # stop tcpdump
```

The DNP3 dissector decodes port-20000 traffic automatically, so the built-in `dnp3` filter
plus the dissector's own object labels are all you need — no custom field expression.

**CLI (tshark):** dump the DNP3 detail and look for the dissector's object names. G112 writes
appear as "Virtual Terminal Output Block", G113 responses as "Virtual Terminal Event Data":

```bash
tshark -r /tmp/vt_tunnel.pcap -Y dnp3 -O dnp3 | grep -i "virtual terminal"
```

**GUI (Wireshark):** open `/tmp/vt_tunnel.pcap` and type `dnp3` in the display-filter bar.
Expand any response packet's *Distributed Network Protocol 3.0 → Object* tree to see the
**Virtual Terminal Event Data (Obj:113)** entries carrying the SSH server bytes.

### 7. Clean up

```bash
# stop the tunnel processes (Ctrl-C in terminals A and B), then remove the throwaway key
grep -vF "$(cat /tmp/vt_tunnel_key.pub)" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp \
  && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
rm -f /tmp/vt_tunnel_key /tmp/vt_tunnel_key.pub /tmp/vt_tunnel.pcap
```

## MITRE ATT&CK References

- **T1572** - Protocol Tunneling
- **T1071** - Application Layer Protocol
- **T0869** - Standard Application Layer Protocol (ICS)
- **T0885** - Commonly Used Port

## Authorization

These tools are for authorized security testing and penetration testing research only.

## Validation Criteria

| Criterion | Validation |
|-----------|------------|
| g112 variation = data length | Var 1 for 1 byte, Var 6 for 6 bytes, Var 7 for 7 bytes |
| g113 variation = data length | Var 3 for "OK\r", Var 7 for "OK\rBYE\r" |
| Point index preserved | All operations use port index 0 |
| Multiple writes without poll | Steps 7-8 work correctly |
| Response accumulation | Step 10 contains combined responses |
| Binary data integrity | All bytes match expected values exactly |

## Building and Running

```bash
# Build the example
cargo build -p example-virtual-terminal

# Run the IEEE session simulation
cargo run -p example-virtual-terminal

# Run with debug logging
RUST_LOG=debug cargo run -p example-virtual-terminal

# Run the unit tests
cargo test -p example-virtual-terminal
```
