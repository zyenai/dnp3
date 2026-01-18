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
- [x] ReadHandler callbacks for receiving VT data
- [ ] Master API for writing Group 112 data
- [ ] Outstation callbacks for receiving Group 112 writes
- [ ] Database support for VT event generation

This example uses a simulated terminal interpreter to demonstrate the protocol
flow defined in IEEE 1815-2012.

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
