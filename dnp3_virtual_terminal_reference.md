# DNP3 Virtual Terminal Objects Technical Reference

## IEEE 1815-2012 Specification Summary

**Document:** IEEE Std 1815-2012 - IEEE Standard for Electric Power Systems Communications—Distributed Network Protocol (DNP3)

### Section References
- **Section 5.2:** Using Virtual Terminal Objects (pages 151-154)
- **Section 11.9.9:** Virtual Terminal Point Type (page 390)
- **Annex A.43:** Object Group 112: Virtual Terminal Output Blocks (page 759)
- **Annex A.44:** Object Group 113: Virtual Terminal Event Data (page 760)

---

## Group 112: Virtual Terminal Output Block

### Object Definition
| Attribute | Value |
|-----------|-------|
| Group Number | 112 |
| Variation | 0-255 (equals octet string length) |
| Type | Static |
| Parsing Code | Table 12-30 |

### Description
Virtual Terminal Output Block objects convey binary octet data streams **going to** an outstation device. The content is specific to the terminal protocol being emulated and is opaque to DNP3.

### Data Structure
```
OSTRn: Terminal data
  - Each octet: 0-255 (no ASCII restriction)
  - String length (n) = variation number
  - Maximum length: 255 octets
```

### Key Characteristics
- NOT returned in Class 0 polls
- Point index specifies the virtual port number
- DNP3 does not interpret the data content
- Masters write these objects to send data to outstation terminal

### Qualifier Codes (Expected)
- 0x5B: Variable-length with size prefix (for arbitrary length up to 255)
- Indexed with 16-bit point number

---

## Group 113: Virtual Terminal Event Data

### Object Definition
| Attribute | Value |
|-----------|-------|
| Group Number | 113 |
| Variation | 0-255 (equals octet string length) |
| Type | Event |
| Parsing Code | Table 12-30 |

### Description
Virtual Terminal Event Data objects convey binary octet data streams **coming from** an outstation device. These are returned in response to read requests or in unsolicited response messages.

### Data Structure
```
OSTRn: Terminal data
  - Each octet: 0-255 (no ASCII restriction)  
  - String length (n) = variation number
  - Maximum length: 255 octets
```

### Key Characteristics
- CAN be assigned to Class 1, 2, or 3
- Returned via read requests or unsolicited responses
- Point index specifies the virtual port number
- DNP3 does not interpret the data content
- Timestamp is optional

---

## Protocol Usage Pattern

### Example Session (from IEEE 1815-2012 Section 5.2.3)

```
Step  Direction  Object       Content                    Comment
────  ─────────  ──────────   ─────────────────────────  ─────────────────────────
1     M→O        g112v1       <CR>                       Wake-up command
2     O→M        (null)                                  Outstation has no data
3     M→O        READ g113v0                             Master requests VT data
4     O→M        (null)                                  Still no data
5     M→O        READ g113v0                             Poll again
6     O→M        g113v3       'OK<CR>'                   Response received
7     M→O        g112v6       'CLEAR<CR>'                Send clear command
8     M→O        g112v7       'LOGOFF<CR>'               Send logoff command
9     M→O        READ g113v0                             Poll for response
10    O→M        g113v7       'OK<CR>BYE<CR>'            Combined responses

M = Master, O = Outstation
<CR> = Carriage Return (0x0D)
```

### Key Observations
- Multiple commands can be sent without intervening polls
- Outstation can accumulate responses
- Responses can be concatenated into single event
- Partial commands/responses are valid ("discontinuous octet streams")

---

## Implementation Notes

### Discontinuous Octet Streams
The protocol explicitly supports "discontinuous octet streams":
- Data gaps between packets are normal
- Character timing is unpredictable
- Complete commands/responses may span multiple DNP3 messages
- Application layer must handle stream reassembly

### Bandwidth Considerations (Section 5.2.6)
To limit VT traffic impact on the DNP3 link:
1. Limit which Event Class (1, 2, or 3) VT events are assigned to
2. Limit maximum octets per message to ≤255
3. Implement schemes to constrain data transmission rates
4. Consider message frequency limits

### Rules (Section 5.2.5)
- No explicit DNP3 rules for session initiation/termination
- Master and outstation must understand terminal protocol
- Message flow can occur in either direction at any time
- Implicit connections exist by having compatible master/outstation
- Master responsible for maintaining environment (polling regularly)
- In unsolicited mode, check background traffic doesn't impact events

---

## Comparison with Octet Strings (Groups 110/111)

| Feature | Groups 110/111 | Groups 112/113 |
|---------|----------------|----------------|
| Purpose | General data | Terminal emulation |
| Type | Static/Event | Static/Event |
| Max Length | 255 octets | 255 octets |
| Class Polling | Yes (g111) | Yes (g113) |
| Point Index | Identifies point | Identifies virtual port |
| Semantic | Opaque to DNP3 | Opaque to DNP3 |

The implementation should be structurally similar but with distinct type definitions.

---

## Object Header Format

### Variable Length Format (Qualifier 0x5B)
```
Byte 0:    Group (112 or 113)
Byte 1:    Variation (1-255, equals data length)
Byte 2:    Qualifier (0x5B = 1-octet count, 1-octet size prefix)
Byte 3:    Count (number of objects)
Per Object:
  Byte 0:    Size (equals variation)
  Byte 1-2:  Point Index (16-bit)
  Bytes 3+:  Data octets (length = variation)
```

### Indexed Format (Qualifier 0x28 or 0x29)
For known lengths:
```
Byte 0:    Group (112 or 113)
Byte 1:    Variation (1-255)
Byte 2:    Qualifier (0x28 = 8-bit index, 0x29 = 16-bit index)
Byte 3-4:  Count (or range)
Per Object:
  Index bytes
  Data octets (length = variation)
```

---

## References

1. IEEE Std 1815-2012, "IEEE Standard for Electric Power Systems Communications—Distributed Network Protocol (DNP3)"
2. DNP3 User Group Technical Documentation
3. MITRE ATT&CK for ICS - https://attack.mitre.org/techniques/ics/
4. ICS-CERT Virtual Terminal Security Advisories

---

## Security Considerations

Virtual Terminal functionality presents security considerations:
- Provides command-line access to IED functionality
- May bypass normal SCADA data flow controls
- Should be restricted to authorized maintenance operations
- Traffic should be monitored for anomalous patterns
- Consider authentication requirements before enabling VT

**Note:** This documentation is for authorized security research purposes.
