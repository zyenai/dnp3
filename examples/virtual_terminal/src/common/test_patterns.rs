//! Test data pattern generators for binary validation
//!
//! Provides various byte patterns to stress-test VT binary transparency.

use std::fmt;

/// Test case with name and data
pub struct TestPattern {
    /// Test name for identification
    pub name: &'static str,
    /// Binary data to test
    pub data: Vec<u8>,
    /// Human-readable description
    pub description: &'static str,
}

impl fmt::Display for TestPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({} bytes)",
            self.name,
            self.description,
            self.data.len()
        )
    }
}

/// Generate deterministic pseudo-random data using LCG
pub fn prng_data(seed: u64, length: usize) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            // Simple LCG PRNG
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// Generate all byte values 0x00-0xFF (256 bytes)
pub fn all_byte_values() -> Vec<u8> {
    (0u8..=255u8).collect()
}

/// Generate all byte values that fit in 255 bytes (0x00-0xFE)
/// This is the maximum size for a single DNP3 VT object
pub fn all_byte_values_max_vt() -> Vec<u8> {
    (0u8..=254u8).collect()
}

/// Generate pattern with embedded null bytes
pub fn null_embedded_pattern() -> Vec<u8> {
    vec![0x41, 0x00, 0x42, 0x00, 0x43] // A\0B\0C
}

/// Generate DNP3-like sync bytes (should not confuse framing)
pub fn dnp3_sync_pattern() -> Vec<u8> {
    vec![0x05, 0x64, 0x05, 0x64, 0x00, 0x00]
}

/// Generate SSH version banner (realistic test data)
pub fn ssh_banner() -> Vec<u8> {
    b"SSH-2.0-OpenSSH_8.9\r\n".to_vec()
}

/// Get all special byte sequence test patterns
pub fn special_byte_patterns() -> Vec<TestPattern> {
    vec![
        // Null byte tests
        TestPattern {
            name: "null_single",
            data: vec![0x00],
            description: "Single null byte",
        },
        TestPattern {
            name: "null_surrounded",
            data: vec![0x41, 0x00, 0x42],
            description: "Null between ASCII (A\\0B)",
        },
        TestPattern {
            name: "null_prefix",
            data: vec![0x00, 0x41, 0x42],
            description: "Null at start",
        },
        TestPattern {
            name: "null_suffix",
            data: vec![0x41, 0x42, 0x00],
            description: "Null at end",
        },
        TestPattern {
            name: "all_nulls",
            data: vec![0x00; 10],
            description: "10 consecutive nulls",
        },
        TestPattern {
            name: "many_nulls",
            data: vec![0x00; 100],
            description: "100 consecutive nulls",
        },
        // High byte tests
        TestPattern {
            name: "high_single",
            data: vec![0xFF],
            description: "Single 0xFF byte",
        },
        TestPattern {
            name: "high_sequence",
            data: vec![0xFE, 0xFF, 0xFD],
            description: "High byte sequence",
        },
        TestPattern {
            name: "high_low_alternate",
            data: vec![0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00],
            description: "Alternating 0xFF and 0x00",
        },
        TestPattern {
            name: "all_high",
            data: vec![0xFF; 100],
            description: "100 consecutive 0xFF",
        },
        // DNP3 frame markers (should NOT cause framing issues)
        TestPattern {
            name: "dnp3_sync",
            data: vec![0x05, 0x64],
            description: "DNP3 sync bytes",
        },
        TestPattern {
            name: "dnp3_sync_repeated",
            data: vec![0x05, 0x64, 0x05, 0x64, 0x05, 0x64],
            description: "Repeated DNP3 sync bytes",
        },
        TestPattern {
            name: "dnp3_like_frame",
            data: vec![0x05, 0x64, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00],
            description: "DNP3-like frame header",
        },
        // Common escape sequences
        TestPattern {
            name: "cr",
            data: vec![0x0D],
            description: "Carriage return",
        },
        TestPattern {
            name: "lf",
            data: vec![0x0A],
            description: "Line feed",
        },
        TestPattern {
            name: "crlf",
            data: vec![0x0D, 0x0A],
            description: "CRLF sequence",
        },
        TestPattern {
            name: "escape",
            data: vec![0x1B],
            description: "Escape character",
        },
        TestPattern {
            name: "tab",
            data: vec![0x09],
            description: "Tab character",
        },
        TestPattern {
            name: "control_chars",
            data: (0x00..=0x1F).collect(),
            description: "All control characters",
        },
        // Binary patterns
        TestPattern {
            name: "alternating_bits",
            data: vec![0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55],
            description: "Alternating bit pattern",
        },
        TestPattern {
            name: "walking_ones",
            data: vec![0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
            description: "Walking ones",
        },
        TestPattern {
            name: "walking_zeros",
            data: vec![0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F],
            description: "Walking zeros",
        },
        // SSH-like patterns
        TestPattern {
            name: "ssh_banner",
            data: b"SSH-2.0-OpenSSH_8.9\r\n".to_vec(),
            description: "SSH version banner",
        },
        TestPattern {
            name: "ssh_binary_mix",
            data: {
                let mut d = b"SSH-2.0-Test\r\n".to_vec();
                d.extend(prng_data(42, 100)); // Random key exchange data
                d
            },
            description: "SSH banner + binary data",
        },
    ]
}

/// Get size boundary test patterns
pub fn size_boundary_patterns() -> Vec<TestPattern> {
    vec![
        TestPattern {
            name: "size_0",
            data: vec![],
            description: "Empty (0 bytes)",
        },
        TestPattern {
            name: "size_1",
            data: vec![0x42],
            description: "Minimum (1 byte)",
        },
        TestPattern {
            name: "size_2",
            data: vec![0x41, 0x42],
            description: "2 bytes",
        },
        TestPattern {
            name: "size_127",
            data: prng_data(127, 127),
            description: "127 bytes (half max)",
        },
        TestPattern {
            name: "size_128",
            data: prng_data(128, 128),
            description: "128 bytes (power of 2)",
        },
        TestPattern {
            name: "size_200",
            data: prng_data(200, 200),
            description: "200 bytes",
        },
        TestPattern {
            name: "size_254",
            data: prng_data(254, 254),
            description: "254 bytes (max - 1)",
        },
        TestPattern {
            name: "size_255",
            data: prng_data(255, 255),
            description: "255 bytes (DNP3 VT max)",
        },
    ]
}

/// Hex dump utility for debugging
pub fn hex_dump(label: &str, data: &[u8]) {
    print!("{} ({} bytes): ", label, data.len());
    if data.len() <= 32 {
        for b in data {
            print!("{:02X} ", b);
        }
        println!();
    } else {
        // Show first 16 and last 16 bytes
        for b in &data[..16] {
            print!("{:02X} ", b);
        }
        print!("... ");
        for b in &data[data.len() - 16..] {
            print!("{:02X} ", b);
        }
        println!();
    }
}

/// ASCII dump with non-printable escaping
pub fn ascii_dump(label: &str, data: &[u8]) {
    print!("{}: \"", label);
    let max_show = 64;
    for (i, &b) in data.iter().enumerate() {
        if i >= max_show {
            print!("...");
            break;
        }
        match b {
            0x0D => print!("\\r"),
            0x0A => print!("\\n"),
            0x00 => print!("\\0"),
            0x09 => print!("\\t"),
            0x20..=0x7E => print!("{}", b as char),
            _ => print!("\\x{:02X}", b),
        }
    }
    println!("\"");
}

/// Validate that the variation number matches the data length
/// Per IEEE 1815-2012, g112vN and g113vN where N = octet length
pub fn validate_variation_length(variation: u8, data: &[u8]) -> bool {
    variation as usize == data.len()
}

/// Compare two byte slices and report differences
pub fn compare_data(expected: &[u8], received: &[u8]) -> Result<(), String> {
    if expected.len() != received.len() {
        return Err(format!(
            "Length mismatch: expected {} bytes, received {} bytes",
            expected.len(),
            received.len()
        ));
    }

    for (i, (e, r)) in expected.iter().zip(received.iter()).enumerate() {
        if e != r {
            return Err(format!(
                "Byte mismatch at offset {}: expected 0x{:02X}, received 0x{:02X}",
                i, e, r
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prng_deterministic() {
        let data1 = prng_data(12345, 10);
        let data2 = prng_data(12345, 10);
        assert_eq!(data1, data2);
    }

    #[test]
    fn test_all_byte_values() {
        let data = all_byte_values();
        assert_eq!(data.len(), 256);
        assert_eq!(data[0], 0);
        assert_eq!(data[255], 255);
    }

    #[test]
    fn test_all_byte_values_max_vt() {
        let data = all_byte_values_max_vt();
        assert_eq!(data.len(), 255);
        assert_eq!(data[0], 0);
        assert_eq!(data[254], 254);
    }

    #[test]
    fn test_variation_length_validation() {
        assert!(validate_variation_length(3, b"OK\r"));
        assert!(validate_variation_length(7, b"LOGOFF\r"));
        assert!(!validate_variation_length(5, b"OK\r"));
    }

    #[test]
    fn test_compare_data_equal() {
        let data = vec![0x01, 0x02, 0x03];
        assert!(compare_data(&data, &data).is_ok());
    }

    #[test]
    fn test_compare_data_length_mismatch() {
        let a = vec![0x01, 0x02];
        let b = vec![0x01, 0x02, 0x03];
        assert!(compare_data(&a, &b).is_err());
    }

    #[test]
    fn test_compare_data_content_mismatch() {
        let a = vec![0x01, 0x02, 0x03];
        let b = vec![0x01, 0xFF, 0x03];
        let result = compare_data(&a, &b);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("offset 1"));
    }

    #[test]
    fn test_special_byte_patterns_not_empty() {
        let patterns = special_byte_patterns();
        assert!(!patterns.is_empty());
        // Verify each pattern has a name and description
        for pattern in &patterns {
            assert!(!pattern.name.is_empty());
            assert!(!pattern.description.is_empty());
        }
    }

    #[test]
    fn test_size_boundary_patterns() {
        let patterns = size_boundary_patterns();
        assert!(!patterns.is_empty());
        // Verify size_255 is the max VT size
        let max_pattern = patterns.iter().find(|p| p.name == "size_255").unwrap();
        assert_eq!(max_pattern.data.len(), 255);
    }
}
