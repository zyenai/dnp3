//! Test data pattern generators for binary validation

/// Generate deterministic pseudo-random data
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

/// Generate all byte values 0x00-0xFF
pub fn all_byte_values() -> Vec<u8> {
    (0u8..=255u8).collect()
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

/// Hex dump utility for debugging
pub fn hex_dump(label: &str, data: &[u8]) {
    print!("{}: ", label);
    for (i, b) in data.iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            println!();
            print!("         ");
        }
        print!("{:02X} ", b);
    }
    println!();
}

/// ASCII dump with non-printable escaping
pub fn ascii_dump(label: &str, data: &[u8]) {
    print!("{}: \"", label);
    for &b in data {
        match b {
            0x0D => print!("\\r"),
            0x0A => print!("\\n"),
            0x00 => print!("\\0"),
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
    fn test_variation_length_validation() {
        assert!(validate_variation_length(3, b"OK\r"));
        assert!(validate_variation_length(7, b"LOGOFF\r"));
        assert!(!validate_variation_length(5, b"OK\r"));
    }
}
