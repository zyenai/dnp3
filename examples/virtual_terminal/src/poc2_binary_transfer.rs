//! PoC 2: Arbitrary Binary Data Transfer Validation
//!
//! Validates that VT objects correctly handle all byte values, edge cases,
//! and various sizes. Must pass before attempting SSH tunneling.
//!
//! Run with: cargo run -p example-virtual-terminal --bin vt_binary_test
//!
//! ## MITRE ATT&CK References
//! - T1071: Application Layer Protocol
//! - T1572: Protocol Tunneling (preparation)
//! - T0869: Standard Application Layer Protocol (ICS)

mod common;

use std::collections::HashMap;
use std::time::Instant;

use common::{
    all_byte_values_max_vt, ascii_dump, compare_data, hex_dump, prng_data, size_boundary_patterns,
    special_byte_patterns, TestPattern,
};

const VT_MAX_SIZE: usize = 255;

/// Test result tracking
struct TestResults {
    passed: usize,
    failed: usize,
    failures: Vec<String>,
}

impl TestResults {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            failures: Vec::new(),
        }
    }

    fn record_pass(&mut self, name: &str) {
        self.passed += 1;
        println!("  [PASS] {}", name);
    }

    fn record_fail(&mut self, name: &str, reason: &str) {
        self.failed += 1;
        self.failures.push(format!("{}: {}", name, reason));
        println!("  [FAIL] {} - {}", name, reason);
    }

    fn summary(&self) {
        println!();
        println!("================================================================");
        println!(
            "  Test Summary: {} passed, {} failed",
            self.passed, self.failed
        );
        println!("================================================================");

        if !self.failures.is_empty() {
            println!();
            println!("Failures:");
            for f in &self.failures {
                println!("  - {}", f);
            }
        }
    }

    fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// Simulates a virtual terminal echo channel
/// This represents the VT data path through DNP3 Groups 112/113
struct VirtualTerminalEchoChannel {
    /// Data buffers per virtual port (simulating multiple VT ports)
    port_buffers: HashMap<u16, Vec<u8>>,
    /// Statistics
    bytes_sent: usize,
    bytes_received: usize,
    roundtrips: usize,
}

impl VirtualTerminalEchoChannel {
    fn new() -> Self {
        Self {
            port_buffers: HashMap::new(),
            bytes_sent: 0,
            bytes_received: 0,
            roundtrips: 0,
        }
    }

    /// Simulate writing data via g112 (Master -> Outstation)
    /// Returns error if data exceeds VT max size
    fn write_g112(&mut self, port: u16, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Err("Empty data not allowed".to_string());
        }
        if data.len() > VT_MAX_SIZE {
            return Err(format!(
                "Data exceeds max VT size: {} > {}",
                data.len(),
                VT_MAX_SIZE
            ));
        }

        // Validate variation matches length (IEEE 1815-2012)
        let variation = data.len() as u8;
        if variation as usize != data.len() {
            return Err("Variation/length mismatch".to_string());
        }

        // Store data (echo it back)
        self.port_buffers.insert(port, data.to_vec());
        self.bytes_sent += data.len();

        Ok(())
    }

    /// Simulate reading data via g113 (Outstation -> Master)
    fn read_g113(&mut self, port: u16) -> Option<Vec<u8>> {
        if let Some(data) = self.port_buffers.remove(&port) {
            self.bytes_received += data.len();
            self.roundtrips += 1;
            Some(data)
        } else {
            None
        }
    }

    /// Full roundtrip: write then read
    fn roundtrip(&mut self, port: u16, data: &[u8]) -> Result<Vec<u8>, String> {
        self.write_g112(port, data)?;
        self.read_g113(port)
            .ok_or_else(|| "No data received".to_string())
    }

    fn stats(&self) -> (usize, usize, usize) {
        (self.bytes_sent, self.bytes_received, self.roundtrips)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("================================================================");
    println!("  PoC 2: Binary Data Transfer Validation");
    println!("  Stress Testing DNP3 Groups 112/113 Binary Transparency");
    println!("================================================================");
    println!();

    let mut channel = VirtualTerminalEchoChannel::new();
    let mut results = TestResults::new();

    // Test Category 1: All Byte Values
    println!("================================================================");
    println!("  Category 1: All Byte Values (0x00-0xFE)");
    println!("================================================================");
    println!();
    test_all_byte_values(&mut channel, &mut results)?;

    // Test Category 2: Special Byte Sequences
    println!();
    println!("================================================================");
    println!("  Category 2: Special Byte Sequences");
    println!("================================================================");
    println!();
    test_special_patterns(&mut channel, &mut results)?;

    // Test Category 3: Size Boundaries
    println!();
    println!("================================================================");
    println!("  Category 3: Size Boundaries");
    println!("================================================================");
    println!();
    test_size_boundaries(&mut channel, &mut results)?;

    // Test Category 4: Multiple Ports
    println!();
    println!("================================================================");
    println!("  Category 4: Multiple Virtual Ports");
    println!("================================================================");
    println!();
    test_multiple_ports(&mut channel, &mut results)?;

    // Test Category 5: Rapid Sequential Transfers
    println!();
    println!("================================================================");
    println!("  Category 5: Rapid Sequential Transfers");
    println!("================================================================");
    println!();
    test_rapid_transfers(&mut channel, &mut results)?;

    // Test Category 6: Performance Baseline
    println!();
    println!("================================================================");
    println!("  Category 6: Performance Baseline");
    println!("================================================================");
    println!();
    benchmark_throughput(&mut channel)?;

    // Summary
    results.summary();

    // Final stats
    let (sent, received, roundtrips) = channel.stats();
    println!();
    println!("Channel Statistics:");
    println!("  Total bytes sent:     {}", sent);
    println!("  Total bytes received: {}", received);
    println!("  Total roundtrips:     {}", roundtrips);

    if results.all_passed() {
        println!();
        println!("================================================================");
        println!("  [SUCCESS] All Binary Transfer Tests PASSED");
        println!("  Ready for PoC 3: SSH Tunneling");
        println!("================================================================");
        Ok(())
    } else {
        println!();
        println!("================================================================");
        println!("  [FAILURE] Some Binary Transfer Tests FAILED");
        println!("  Fix issues before proceeding to SSH tunneling");
        println!("================================================================");
        Err("Binary transfer tests failed".into())
    }
}

/// Test all byte values 0x00-0xFE in a single transfer
fn test_all_byte_values(
    channel: &mut VirtualTerminalEchoChannel,
    results: &mut TestResults,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing all 255 byte values (0x00-0xFE) in single transfer...");

    let test_data = all_byte_values_max_vt();
    hex_dump("Sending", &test_data);

    let response = channel.roundtrip(0, &test_data)?;
    hex_dump("Received", &response);

    match compare_data(&test_data, &response) {
        Ok(_) => results.record_pass("all_byte_values"),
        Err(e) => results.record_fail("all_byte_values", &e),
    }

    // Also test individual problematic bytes
    println!();
    println!("Testing individual byte values...");

    let problematic_bytes: [(u8, &str); 7] = [
        (0x00, "null"),
        (0x0A, "line feed"),
        (0x0D, "carriage return"),
        (0x1B, "escape"),
        (0x05, "DNP3 sync byte 1"),
        (0x64, "DNP3 sync byte 2"),
        (0xFF, "max byte value"),
    ];

    for (byte, desc) in &problematic_bytes {
        let data = vec![*byte];
        let response = channel.roundtrip(0, &data)?;

        let name = format!("byte_0x{:02X} ({})", byte, desc);
        match compare_data(&data, &response) {
            Ok(_) => results.record_pass(&name),
            Err(e) => results.record_fail(&name, &e),
        }
    }

    Ok(())
}

/// Test special byte sequences
fn test_special_patterns(
    channel: &mut VirtualTerminalEchoChannel,
    results: &mut TestResults,
) -> Result<(), Box<dyn std::error::Error>> {
    for pattern in special_byte_patterns() {
        println!("Testing: {}", pattern);

        // Skip empty patterns
        if pattern.data.is_empty() {
            println!("  (skipping empty data)");
            continue;
        }

        // Skip patterns that exceed VT max
        if pattern.data.len() > VT_MAX_SIZE {
            println!("  (skipping - exceeds VT max size)");
            continue;
        }

        let response = channel.roundtrip(0, &pattern.data)?;

        match compare_data(&pattern.data, &response) {
            Ok(_) => results.record_pass(pattern.name),
            Err(e) => results.record_fail(pattern.name, &e),
        }
    }

    Ok(())
}

/// Test size boundaries
fn test_size_boundaries(
    channel: &mut VirtualTerminalEchoChannel,
    results: &mut TestResults,
) -> Result<(), Box<dyn std::error::Error>> {
    for pattern in size_boundary_patterns() {
        println!("Testing: {}", pattern);

        // Skip empty for now if not supported
        if pattern.data.is_empty() {
            println!("  (skipping empty data test)");
            continue;
        }

        let response = channel.roundtrip(0, &pattern.data)?;

        match compare_data(&pattern.data, &response) {
            Ok(_) => results.record_pass(pattern.name),
            Err(e) => results.record_fail(pattern.name, &e),
        }
    }

    // Test oversized data handling
    println!();
    println!("Testing oversized data (256+ bytes)...");
    let oversized = prng_data(999, 300);
    let result = channel.write_g112(0, &oversized);

    match result {
        Ok(_) => {
            results.record_fail("oversized_rejection", "Should have rejected oversized data");
        }
        Err(e) => {
            println!("  Correctly rejected: {}", e);
            results.record_pass("oversized_rejection");
        }
    }

    Ok(())
}

/// Test multiple virtual terminal ports
fn test_multiple_ports(
    channel: &mut VirtualTerminalEchoChannel,
    results: &mut TestResults,
) -> Result<(), Box<dyn std::error::Error>> {
    let test_ports: [u16; 4] = [0, 1, 2, 100];

    // Send different data to each port
    for &port in &test_ports {
        let data = format!("PORT{}", port).into_bytes();
        println!(
            "Sending to port {}: {:?}",
            port,
            String::from_utf8_lossy(&data)
        );
        channel.write_g112(port, &data)?;
    }

    // Read back from each port and verify isolation
    for &port in &test_ports {
        let expected = format!("PORT{}", port).into_bytes();
        let response = channel
            .read_g113(port)
            .ok_or_else(|| format!("No data on port {}", port))?;

        let name = format!("port_{}_isolation", port);
        match compare_data(&expected, &response) {
            Ok(_) => results.record_pass(&name),
            Err(e) => results.record_fail(&name, &e),
        }
    }

    Ok(())
}

/// Test rapid sequential transfers
fn test_rapid_transfers(
    channel: &mut VirtualTerminalEchoChannel,
    results: &mut TestResults,
) -> Result<(), Box<dyn std::error::Error>> {
    let iterations = 100;
    let chunk_size = 100;

    println!(
        "Sending {} rapid transfers of {} bytes each...",
        iterations, chunk_size
    );

    let mut all_ok = true;

    for i in 0..iterations {
        let data = prng_data(i as u64, chunk_size);
        let response = channel.roundtrip(0, &data)?;

        if let Err(e) = compare_data(&data, &response) {
            println!("  Iteration {}: FAILED - {}", i, e);
            all_ok = false;
        }
    }

    if all_ok {
        println!("  All {} iterations completed successfully", iterations);
        results.record_pass("rapid_transfers");
    } else {
        results.record_fail("rapid_transfers", "Some iterations failed");
    }

    Ok(())
}

/// Benchmark VT throughput for SSH tunnel planning
fn benchmark_throughput(
    channel: &mut VirtualTerminalEchoChannel,
) -> Result<(), Box<dyn std::error::Error>> {
    let iterations = 1000;
    let chunk_size = 200; // Realistic for SSH packets

    println!(
        "Benchmarking {} roundtrips of {} bytes...",
        iterations, chunk_size
    );

    let start = Instant::now();

    for i in 0..iterations {
        let data = prng_data(i as u64, chunk_size);
        let _ = channel.roundtrip(0, &data)?;
    }

    let elapsed = start.elapsed();
    let total_bytes = chunk_size * iterations * 2; // Both directions
    let throughput = total_bytes as f64 / elapsed.as_secs_f64();
    let avg_rtt = elapsed.as_micros() as f64 / iterations as f64;

    println!();
    println!(
        "  Throughput: {:.2} bytes/sec ({:.2} MB/s)",
        throughput,
        throughput / 1_000_000.0
    );
    println!("  Average RTT: {:.2} microseconds", avg_rtt);
    println!("  Total time: {:.4} seconds", elapsed.as_secs_f64());
    println!();

    // Estimate SSH usability (note: this is simulation, real network will be slower)
    if avg_rtt < 1000.0 {
        println!("  -> Simulation shows excellent throughput");
        println!("  -> Real network latency will dominate SSH performance");
    }

    // Additional benchmark: varying sizes
    println!();
    println!("Size vs Throughput:");
    println!(
        "  {:>8} | {:>12} | {:>15}",
        "Size", "Time (us)", "Throughput"
    );
    println!("  ---------+--------------+-----------------");

    for size in [1, 10, 50, 100, 200, 255] {
        let bench_iterations = 1000;
        let start = Instant::now();

        for i in 0..bench_iterations {
            let data = prng_data(i as u64, size);
            let _ = channel.roundtrip(0, &data)?;
        }

        let elapsed = start.elapsed();
        let avg_time = elapsed.as_micros() as f64 / bench_iterations as f64;
        let throughput = (size * bench_iterations * 2) as f64 / elapsed.as_secs_f64();

        println!(
            "  {:>8} | {:>12.2} | {:>12.2} B/s",
            size, avg_time, throughput
        );
    }

    Ok(())
}

/// Additional validation: ensure binary transparency for specific protocol patterns
#[allow(dead_code)]
fn test_protocol_patterns(
    channel: &mut VirtualTerminalEchoChannel,
    results: &mut TestResults,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing protocol-specific patterns...");

    // SSH KEX_INIT-like pattern
    let ssh_kex_init = {
        let mut data = vec![20u8]; // SSH_MSG_KEXINIT
        data.extend(prng_data(0xCAFE, 16)); // Cookie
        data.extend(&[0, 0, 0, 10]); // name-list length
        data.extend(b"aes256-ctr"); // algorithm name
        data
    };

    if ssh_kex_init.len() <= VT_MAX_SIZE {
        println!(
            "  Testing SSH KEX_INIT-like pattern ({} bytes)",
            ssh_kex_init.len()
        );
        hex_dump("  Pattern", &ssh_kex_init);

        let response = channel.roundtrip(0, &ssh_kex_init)?;
        match compare_data(&ssh_kex_init, &response) {
            Ok(_) => results.record_pass("ssh_kex_init_pattern"),
            Err(e) => results.record_fail("ssh_kex_init_pattern", &e),
        }
    }

    // TLS record-like pattern
    let tls_record = {
        let mut data = vec![
            0x17, // Content type: Application Data
            0x03, 0x03, // TLS 1.2
            0x00, 0x20, // Length: 32
        ];
        data.extend(prng_data(0xBEEF, 32)); // Encrypted payload
        data
    };

    println!(
        "  Testing TLS record-like pattern ({} bytes)",
        tls_record.len()
    );
    hex_dump("  Pattern", &tls_record);

    let response = channel.roundtrip(0, &tls_record)?;
    match compare_data(&tls_record, &response) {
        Ok(_) => results.record_pass("tls_record_pattern"),
        Err(e) => results.record_fail("tls_record_pattern", &e),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_channel_basic() {
        let mut channel = VirtualTerminalEchoChannel::new();
        let data = vec![0x41, 0x42, 0x43];

        channel.write_g112(0, &data).unwrap();
        let response = channel.read_g113(0).unwrap();

        assert_eq!(data, response);
    }

    #[test]
    fn test_echo_channel_rejects_oversized() {
        let mut channel = VirtualTerminalEchoChannel::new();
        let data = vec![0x00; 300];

        assert!(channel.write_g112(0, &data).is_err());
    }

    #[test]
    fn test_echo_channel_rejects_empty() {
        let mut channel = VirtualTerminalEchoChannel::new();
        let data: Vec<u8> = vec![];

        assert!(channel.write_g112(0, &data).is_err());
    }

    #[test]
    fn test_echo_channel_port_isolation() {
        let mut channel = VirtualTerminalEchoChannel::new();

        channel.write_g112(0, &[0x01]).unwrap();
        channel.write_g112(1, &[0x02]).unwrap();

        assert_eq!(channel.read_g113(0), Some(vec![0x01]));
        assert_eq!(channel.read_g113(1), Some(vec![0x02]));
    }

    #[test]
    fn test_binary_transparency_all_bytes() {
        let mut channel = VirtualTerminalEchoChannel::new();

        // Test each individual byte value
        for byte in 0u8..=254u8 {
            let data = vec![byte];
            let response = channel.roundtrip(0, &data).unwrap();
            assert_eq!(data, response, "Failed for byte 0x{:02X}", byte);
        }
    }

    #[test]
    fn test_binary_transparency_max_size() {
        let mut channel = VirtualTerminalEchoChannel::new();
        let data = all_byte_values_max_vt();

        let response = channel.roundtrip(0, &data).unwrap();
        assert_eq!(data, response);
    }
}
