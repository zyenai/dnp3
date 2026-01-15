# Claude Code Prompt: Implement DNP3 Virtual Terminal Objects (Groups 112/113) in Stepfunc DNP3 Library

## Project Context

I'm working on an authorized penetration testing engagement involving Industrial Control Systems (ICS). My goal is to create a utility that tunnels SSH over DNP3 using Virtual Terminal Objects (Groups 112/113). This is for legitimate security research and defensive purposes.

**Repository:** https://github.com/zyenai/dnp3 (fork of https://github.com/stepfunc/dnp3)

## Objective

Add support for DNP3 Virtual Terminal Objects (Groups 112 and 113) to the Stepfunc DNP3 Rust library. These groups are similar to the existing Octet String support (Groups 110/111) but are specifically designed for virtual terminal communication channels.

## DNP3 Standard Reference (IEEE 1815-2012)

### Group 112: Virtual Terminal Output Block
- **Purpose:** Conveys binary octet data streams GOING TO an outstation device (command interpreter)
- **Type:** Static object (not returned in Class 0 polls)
- **Variation:** The variation number equals the length of the octet string (1-255 octets max)
- **Usage:** Master writes Group 112 objects using the point index to specify the virtual port number
- **Format:** Variable-length octet string where each octet can have value 0-255

### Group 113: Virtual Terminal Event Data
- **Purpose:** Conveys binary octet data streams COMING FROM an outstation device (command interpreter)
- **Type:** Event object (can be assigned to Class 1, 2, or 3)
- **Variation:** The variation number equals the length of the octet string (1-255 octets max)
- **Usage:** Outstations return Group 113 objects in response to read requests or unsolicited responses
- **Format:** Variable-length octet string where each octet can have value 0-255

### Virtual Terminal Communication Model
```
┌─────────────────┐                           ┌─────────────────────────────┐
│  DNP3 Master    │                           │     DNP3 Outstation (IED)   │
│                 │                           │                             │
│  Terminal 0 ────┼── Group 112 Objects ─────→│ Port 0 → Terminal Command  │
│  Terminal 1 ────┼── Group 112 Objects ─────→│ Port 1    Interpreter      │
│                 │                           │                             │
│  Terminal 0 ←───┼── Group 113 Objects ←─────│ Port 0 ← Terminal Command  │
│  Terminal 1 ←───┼── Group 113 Objects ←─────│ Port 1    Interpreter      │
└─────────────────┘                           └─────────────────────────────┘
```

### Key Protocol Behaviors
1. Point index identifies the virtual port/channel number
2. Multiple messages can be sent without intervening polls
3. Responses can be accumulated and concatenated
4. Data content is opaque to DNP3 - specific to terminal protocol
5. No timestamps are typically used
6. Discontinuous octet streams - gaps between packets are expected

## Implementation Requirements

### Phase 1: Core Object Definitions

1. **Define Group 112 variation enum** (similar to existing `StaticOctetStringVariation`)
   - Location: Likely in `dnp3/src/app/variations.rs` or similar
   - Should support variations 0-255 (variation = octet string length)

2. **Define Group 113 variation enum** (similar to existing `EventOctetStringVariation`)
   - Location: Same as above
   - Should support variations 0-255 (variation = octet string length)

3. **Create VirtualTerminalOutput struct** (Group 112)
   - Fields: `index: u16`, `value: Vec<u8>` (or similar buffer type)
   - Similar pattern to existing `OctetString` implementation

4. **Create VirtualTerminalEvent struct** (Group 113)
   - Fields: `index: u16`, `value: Vec<u8>`, optional `time: Option<Timestamp>`
   - Similar pattern to existing octet string event handling

### Phase 2: Parser Implementation

1. **Add parsing support for Group 112**
   - Add to object header parsing in `dnp3/src/app/parse/` 
   - Handle qualifier codes (likely 0x5B for variable length with size prefix)
   - Parse variable-length octet strings

2. **Add parsing support for Group 113**
   - Same parsing infrastructure as Group 112
   - Event-specific handling for class data

### Phase 3: Master API

1. **Write operation for Group 112**
   - Function to write virtual terminal data to outstation
   - Accept point index and byte buffer
   - Build appropriate DNP3 WRITE request

2. **Read operation for Group 113**
   - Function to request virtual terminal event data
   - Support class polling (Class 1/2/3) for VT events
   - Handle responses containing Group 113 objects

3. **ReadHandler callbacks**
   - Add `handle_virtual_terminal_output` callback (if masters need to parse g112)
   - Add `handle_virtual_terminal_event` callback for g113 data

### Phase 4: Outstation API

1. **Database support for virtual terminal points**
   - Add VT point storage to outstation database
   - Support add/remove/update operations

2. **Event generation for Group 113**
   - Queue VT events when terminal data is ready
   - Support class assignment (1, 2, or 3)

3. **Write handler for Group 112**
   - Callback to notify application when VT data is written
   - Application processes data and may queue response via Group 113

### Phase 5: FFI Bindings (if time permits)

1. Add C bindings for VT functions
2. Add .NET bindings
3. Add Java bindings

## Reference: Existing Octet String Implementation

The library already implements Groups 110/111 (Octet Strings). Use these as templates:

### Key Files to Reference
- Object variations: Look for `OctetStringVariation` definitions
- Parsing: Look for `Group110` and `Group111` parsing code
- Database: Look for `OctetString` in database module
- Handlers: Look for `handle_octet_string` callbacks

### Patterns to Follow
```rust
// Example variation enum pattern (conceptual)
pub enum StaticVirtualTerminalVariation {
    Group112Var0,  // 0-length (special case)
    Group112Var1,  // 1 octet
    Group112Var2,  // 2 octets
    // ... up to 255
}

// Example data structure pattern (conceptual)
pub struct VirtualTerminalOutput {
    pub index: u16,
    pub value: ByteCollection,  // or Vec<u8>
}
```

## Testing Plan

1. **Unit tests** for parsing Group 112/113 objects
2. **Integration tests** for master write operations
3. **Integration tests** for outstation event handling
4. **Round-trip tests** simulating VT session

## Expected Workflow

1. First, explore the existing codebase structure:
   ```bash
   # Understand the project layout
   tree -L 2 dnp3/src/
   
   # Find octet string implementations
   grep -r "OctetString" dnp3/src/
   grep -r "Group110" dnp3/src/
   grep -r "Group111" dnp3/src/
   ```

2. Identify all locations that need modification:
   - Variation definitions
   - Parser code
   - Object handling
   - Database module
   - API surface (master and outstation)

3. Implement changes incrementally, testing each component

4. Update any documentation or examples

## MITRE ATT&CK / ICS Mapping

This capability relates to:
- **MITRE ATT&CK for Enterprise:**
  - T1071.001 - Application Layer Protocol: Web Protocols (adaptation for industrial protocols)
  - T1572 - Protocol Tunneling
  
- **MITRE ATT&CK for ICS:**
  - T0885 - Commonly Used Port
  - T0869 - Standard Application Layer Protocol

- **ICS Cyber Kill Chain:**
  - Stage 1: Reconnaissance (understanding VT capabilities)
  - Stage 2: Weaponization (building tunnel utility)

## Important Notes

1. This is for authorized security testing with proper Statement of Work
2. Follow existing code style and patterns in the Stepfunc library
3. Ensure changes don't break existing functionality
4. Consider backward compatibility
5. The library uses `tokio` for async - follow existing async patterns

## Questions to Answer During Implementation

1. Does the library use a macro or code generation for object definitions?
2. How does qualifier code handling work for variable-length objects?
3. What's the pattern for adding new point types to the outstation database?
4. How are FFI bindings generated (look for `dnp3-bindings` tool)?

## Success Criteria

- [ ] Group 112 objects can be written by master to outstation
- [ ] Group 113 events can be generated by outstation
- [ ] Group 113 events can be read/polled by master
- [ ] Existing tests still pass
- [ ] New unit tests for VT functionality pass
- [ ] Code follows existing library patterns and style

---

**Start by exploring the codebase structure and finding the existing Octet String (Group 110/111) implementation as a template.**
