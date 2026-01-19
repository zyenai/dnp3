//! Tunnel protocol framing layer for SSH over DNP3 VT
//!
//! This module provides a simple framing protocol for tunneling arbitrary
//! binary data through DNP3 Virtual Terminal objects (Groups 112/113).
//!
//! ## Frame Format (max 255 bytes for DNP3 VT)
//!
//! ```text
//! +----------+-------+--------+------------------+
//! | Sequence | Flags | Length | Payload          |
//! | 1 byte   | 1 byte| 1 byte | 0-252 bytes      |
//! +----------+-------+--------+------------------+
//! ```
//!
//! ## MITRE ATT&CK References
//! - T1572: Protocol Tunneling
//! - T1071: Application Layer Protocol
//! - T0869: Standard Application Layer Protocol (ICS)

use std::fmt;

/// Maximum payload size per VT object (255 - 3 header bytes)
pub const MAX_PAYLOAD_SIZE: usize = 252;

/// Maximum VT object size per IEEE 1815-2012
pub const MAX_VT_SIZE: usize = 255;

/// Frame flags for tunnel protocol control
pub mod flags {
    /// Indicates more fragments follow for this message
    pub const MORE_FRAGMENTS: u8 = 0x01;
    /// Request acknowledgment for this frame
    pub const ACK_REQUEST: u8 = 0x02;
    /// This frame is an acknowledgment
    pub const ACK: u8 = 0x04;
    /// Reset the tunnel connection
    pub const RESET: u8 = 0x08;
    /// Keepalive frame
    pub const KEEPALIVE: u8 = 0x10;
    /// Close the tunnel connection
    pub const CLOSE: u8 = 0x20;
}

/// Errors that can occur during frame parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Frame data is too short (less than 3 bytes header)
    TooShort,
    /// Payload length exceeds maximum allowed
    PayloadTooLarge,
    /// Frame data is truncated (payload shorter than declared)
    PayloadTruncated,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "Frame too short (need at least 3 bytes)"),
            Self::PayloadTooLarge => write!(f, "Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
            Self::PayloadTruncated => write!(f, "Payload data truncated"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Errors that can occur during fragment reassembly
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyError {
    /// Received sequence number doesn't match expected
    SequenceMismatch {
        /// Expected sequence number
        expected: u8,
        /// Received sequence number
        received: u8,
    },
    /// Reassembly buffer would overflow
    BufferOverflow,
}

impl fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SequenceMismatch { expected, received } => {
                write!(f, "Sequence mismatch: expected {}, got {}", expected, received)
            }
            Self::BufferOverflow => write!(f, "Reassembly buffer overflow"),
        }
    }
}

impl std::error::Error for ReassemblyError {}

/// A tunnel protocol frame
///
/// Each frame contains a sequence number, control flags, and a payload.
/// Frames are designed to fit within DNP3 VT object size limits (255 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelFrame {
    /// Sequence number (wraps at 256)
    pub sequence: u8,
    /// Control flags
    pub flags: u8,
    /// Payload data (max 252 bytes)
    pub payload: Vec<u8>,
}

impl TunnelFrame {
    /// Create a new data frame with the given sequence and payload
    ///
    /// # Arguments
    /// * `sequence` - Frame sequence number
    /// * `payload` - Data payload (will be truncated if > MAX_PAYLOAD_SIZE)
    /// * `more_fragments` - Whether more fragments follow
    pub fn new_data(sequence: u8, payload: Vec<u8>, more_fragments: bool) -> Self {
        let flags = if more_fragments { flags::MORE_FRAGMENTS } else { 0 };
        Self { sequence, flags, payload }
    }

    /// Create an acknowledgment frame
    pub fn new_ack(ack_sequence: u8) -> Self {
        Self {
            sequence: ack_sequence,
            flags: flags::ACK,
            payload: Vec::new(),
        }
    }

    /// Create a reset frame to initialize/reset the tunnel
    pub fn new_reset() -> Self {
        Self {
            sequence: 0,
            flags: flags::RESET,
            payload: Vec::new(),
        }
    }

    /// Create a keepalive frame
    pub fn new_keepalive(sequence: u8) -> Self {
        Self {
            sequence,
            flags: flags::KEEPALIVE,
            payload: Vec::new(),
        }
    }

    /// Create a close frame to terminate the tunnel
    pub fn new_close(sequence: u8) -> Self {
        Self {
            sequence,
            flags: flags::CLOSE,
            payload: Vec::new(),
        }
    }

    /// Serialize the frame to bytes for transmission via DNP3 VT
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(3 + self.payload.len());
        bytes.push(self.sequence);
        bytes.push(self.flags);
        bytes.push(self.payload.len() as u8);
        bytes.extend(&self.payload);
        bytes
    }

    /// Parse a frame from raw bytes received via DNP3 VT
    pub fn from_bytes(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < 3 {
            return Err(FrameError::TooShort);
        }

        let sequence = data[0];
        let flags = data[1];
        let length = data[2] as usize;

        if length > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge);
        }

        if data.len() < 3 + length {
            return Err(FrameError::PayloadTruncated);
        }

        Ok(Self {
            sequence,
            flags,
            payload: data[3..3 + length].to_vec(),
        })
    }

    /// Check if this frame indicates more fragments follow
    pub fn is_more_fragments(&self) -> bool {
        self.flags & flags::MORE_FRAGMENTS != 0
    }

    /// Check if this frame is an acknowledgment
    pub fn is_ack(&self) -> bool {
        self.flags & flags::ACK != 0
    }

    /// Check if this frame is a reset request
    pub fn is_reset(&self) -> bool {
        self.flags & flags::RESET != 0
    }

    /// Check if this frame is a keepalive
    pub fn is_keepalive(&self) -> bool {
        self.flags & flags::KEEPALIVE != 0
    }

    /// Check if this frame is a close request
    pub fn is_close(&self) -> bool {
        self.flags & flags::CLOSE != 0
    }

    /// Check if this frame is a data frame (not a control frame)
    pub fn is_data(&self) -> bool {
        !self.is_ack() && !self.is_reset() && !self.is_keepalive() && !self.is_close()
    }
}

/// Fragment large data into multiple tunnel frames
///
/// SSH packets can exceed the 252-byte payload limit, so they must be
/// fragmented across multiple DNP3 VT objects.
///
/// # Arguments
/// * `data` - Data to fragment
/// * `start_sequence` - Starting sequence number
///
/// # Returns
/// Vector of frames covering all data. Empty data produces one empty frame.
pub fn fragment_data(data: &[u8], start_sequence: u8) -> Vec<TunnelFrame> {
    if data.is_empty() {
        return vec![TunnelFrame::new_data(start_sequence, Vec::new(), false)];
    }

    let mut frames = Vec::new();
    let mut seq = start_sequence;
    let chunks: Vec<&[u8]> = data.chunks(MAX_PAYLOAD_SIZE).collect();

    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i == chunks.len() - 1;
        frames.push(TunnelFrame::new_data(seq, chunk.to_vec(), !is_last));
        seq = seq.wrapping_add(1);
    }

    frames
}

/// Calculate the number of frames needed to send data of a given size
pub fn frames_needed(data_len: usize) -> usize {
    if data_len == 0 {
        1
    } else {
        (data_len + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE
    }
}

/// Reassembles fragmented frames into complete messages
///
/// Handles the case where large data spans multiple VT objects.
pub struct FragmentReassembler {
    /// Buffer for accumulating fragment data
    buffer: Vec<u8>,
    /// Expected next sequence number
    expected_sequence: u8,
    /// Maximum allowed buffer size
    max_size: usize,
}

impl FragmentReassembler {
    /// Create a new reassembler with default max size (64KB)
    pub fn new() -> Self {
        Self::with_max_size(64 * 1024)
    }

    /// Create a reassembler with custom max size
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            buffer: Vec::new(),
            expected_sequence: 0,
            max_size,
        }
    }

    /// Add a frame to the reassembly buffer
    ///
    /// # Returns
    /// * `Ok(Some(data))` - Complete message reassembled
    /// * `Ok(None)` - More fragments expected
    /// * `Err(_)` - Reassembly error (sequence mismatch, overflow)
    pub fn add_frame(&mut self, frame: TunnelFrame) -> Result<Option<Vec<u8>>, ReassemblyError> {
        // Sequence check
        if frame.sequence != self.expected_sequence {
            return Err(ReassemblyError::SequenceMismatch {
                expected: self.expected_sequence,
                received: frame.sequence,
            });
        }

        // Buffer overflow check
        if self.buffer.len() + frame.payload.len() > self.max_size {
            return Err(ReassemblyError::BufferOverflow);
        }

        // Add payload to buffer
        self.buffer.extend(&frame.payload);
        self.expected_sequence = self.expected_sequence.wrapping_add(1);

        // Check if message is complete
        if frame.is_more_fragments() {
            Ok(None)
        } else {
            Ok(Some(std::mem::take(&mut self.buffer)))
        }
    }

    /// Reset the reassembler state
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.expected_sequence = 0;
    }

    /// Reset with a specific starting sequence number
    pub fn reset_to(&mut self, sequence: u8) {
        self.buffer.clear();
        self.expected_sequence = sequence;
    }

    /// Get the expected next sequence number
    pub fn expected_sequence(&self) -> u8 {
        self.expected_sequence
    }

    /// Get the current buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let frame = TunnelFrame::new_data(42, vec![0x01, 0x02, 0x03], false);
        let bytes = frame.to_bytes();
        let parsed = TunnelFrame::from_bytes(&bytes).unwrap();
        assert_eq!(frame, parsed);
    }

    #[test]
    fn test_frame_flags() {
        let reset = TunnelFrame::new_reset();
        assert!(reset.is_reset());
        assert!(!reset.is_data());

        let ack = TunnelFrame::new_ack(5);
        assert!(ack.is_ack());
        assert!(!ack.is_data());

        let data = TunnelFrame::new_data(0, vec![1, 2, 3], true);
        assert!(data.is_data());
        assert!(data.is_more_fragments());
    }

    #[test]
    fn test_fragment_small_data() {
        let data = vec![0x01, 0x02, 0x03];
        let frames = fragment_data(&data, 0);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, data);
        assert!(!frames[0].is_more_fragments());
    }

    #[test]
    fn test_fragment_large_data() {
        let data: Vec<u8> = (0..600).map(|i| i as u8).collect();
        let frames = fragment_data(&data, 0);

        // 600 bytes = 3 frames (252 + 252 + 96)
        assert_eq!(frames.len(), 3);
        assert!(frames[0].is_more_fragments());
        assert!(frames[1].is_more_fragments());
        assert!(!frames[2].is_more_fragments());

        // Verify sequence numbers
        assert_eq!(frames[0].sequence, 0);
        assert_eq!(frames[1].sequence, 1);
        assert_eq!(frames[2].sequence, 2);
    }

    #[test]
    fn test_fragment_empty_data() {
        let frames = fragment_data(&[], 0);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].payload.is_empty());
    }

    #[test]
    fn test_reassembler_single_frame() {
        let mut reassembler = FragmentReassembler::new();
        let frame = TunnelFrame::new_data(0, vec![1, 2, 3], false);
        let result = reassembler.add_frame(frame).unwrap();
        assert_eq!(result, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_reassembler_multiple_frames() {
        let mut reassembler = FragmentReassembler::new();

        let frame1 = TunnelFrame::new_data(0, vec![1, 2], true);
        let frame2 = TunnelFrame::new_data(1, vec![3, 4], true);
        let frame3 = TunnelFrame::new_data(2, vec![5], false);

        assert!(reassembler.add_frame(frame1).unwrap().is_none());
        assert!(reassembler.add_frame(frame2).unwrap().is_none());

        let result = reassembler.add_frame(frame3).unwrap();
        assert_eq!(result, Some(vec![1, 2, 3, 4, 5]));
    }

    #[test]
    fn test_reassembler_sequence_mismatch() {
        let mut reassembler = FragmentReassembler::new();

        let frame1 = TunnelFrame::new_data(0, vec![1], true);
        let frame3 = TunnelFrame::new_data(2, vec![3], false); // Skip seq 1

        reassembler.add_frame(frame1).unwrap();
        let err = reassembler.add_frame(frame3).unwrap_err();

        assert!(matches!(err, ReassemblyError::SequenceMismatch { expected: 1, received: 2 }));
    }

    #[test]
    fn test_reassembler_reset() {
        let mut reassembler = FragmentReassembler::new();

        let frame = TunnelFrame::new_data(0, vec![1, 2, 3], true);
        reassembler.add_frame(frame).unwrap();
        assert_eq!(reassembler.buffer_size(), 3);

        reassembler.reset();
        assert_eq!(reassembler.buffer_size(), 0);
        assert_eq!(reassembler.expected_sequence(), 0);
    }

    #[test]
    fn test_frames_needed() {
        assert_eq!(frames_needed(0), 1);
        assert_eq!(frames_needed(1), 1);
        assert_eq!(frames_needed(252), 1);
        assert_eq!(frames_needed(253), 2);
        assert_eq!(frames_needed(504), 2);
        assert_eq!(frames_needed(505), 3);
    }

    #[test]
    fn test_frame_parse_errors() {
        // Too short
        assert!(matches!(TunnelFrame::from_bytes(&[0, 1]), Err(FrameError::TooShort)));

        // Payload too large
        let mut bad = vec![0, 0, 253]; // Length byte = 253 > MAX_PAYLOAD_SIZE
        bad.extend(vec![0; 253]);
        assert!(matches!(TunnelFrame::from_bytes(&bad), Err(FrameError::PayloadTooLarge)));

        // Truncated
        assert!(matches!(
            TunnelFrame::from_bytes(&[0, 0, 5, 1, 2]), // Says 5 bytes but only 2
            Err(FrameError::PayloadTruncated)
        ));
    }
}
