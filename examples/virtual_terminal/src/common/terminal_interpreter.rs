//! Test terminal command interpreter for PoC validation
//!
//! Implements the behavior shown in IEEE 1815-2012 Section 5.2.3

use std::collections::VecDeque;

/// Terminal interpreter state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalState {
    /// Waiting for initial command
    Idle,
    /// Ready to accept commands
    Ready,
    /// Session ended
    Ended,
}

/// A simple terminal command interpreter that simulates IEEE example behavior
pub struct TestTerminalInterpreter {
    /// Pending response data to be sent via g113
    response_queue: VecDeque<Vec<u8>>,
    /// Virtual port index this interpreter handles
    port_index: u16,
    /// Current state
    state: TerminalState,
    /// Number of polls received (for delayed response simulation)
    poll_count: usize,
}

impl TestTerminalInterpreter {
    /// Create a new interpreter for the specified virtual port
    pub fn new(port_index: u16) -> Self {
        Self {
            response_queue: VecDeque::new(),
            port_index,
            state: TerminalState::Idle,
            poll_count: 0,
        }
    }

    /// Get the port index this interpreter handles
    pub fn port_index(&self) -> u16 {
        self.port_index
    }

    /// Process incoming g112 data and queue appropriate g113 responses
    ///
    /// Implements IEEE 1815-2012 example behavior:
    /// - <CR> alone (0x0D) -> wakeup, queue "OK<CR>" after delay
    /// - "CLEAR<CR>" -> queue "OK<CR>"
    /// - "LOGOFF<CR>" -> queue "OK<CR>BYE<CR>"
    pub fn process_input(&mut self, data: &[u8]) {
        // Handle wakeup (single CR)
        if data == [0x0D] {
            self.state = TerminalState::Ready;
            // Queue response after simulated delay (will be returned after poll)
            self.response_queue.push_back(b"OK\r".to_vec());
            return;
        }

        // Handle CLEAR command
        if data == b"CLEAR\r" {
            self.response_queue.push_back(b"OK\r".to_vec());
            return;
        }

        // Handle LOGOFF command
        if data == b"LOGOFF\r" {
            // Combined response as shown in IEEE example step 10
            self.response_queue.push_back(b"OK\rBYE\r".to_vec());
            self.state = TerminalState::Ended;
            return;
        }

        // Unknown command - queue error response
        self.response_queue.push_back(b"ERROR\r".to_vec());
    }

    /// Called when master polls for g113 data
    /// Returns Some(data) if response is ready, None otherwise
    ///
    /// Simulates the delayed response behavior in the IEEE example
    /// where the first poll after wakeup returns nothing
    pub fn poll(&mut self) -> Option<Vec<u8>> {
        self.poll_count += 1;

        // Simulate delayed response for wakeup
        // First poll returns nothing, second poll returns "OK<CR>"
        if self.state == TerminalState::Ready && self.poll_count == 1 {
            return None;
        }

        self.response_queue.pop_front()
    }

    /// Get pending response without simulating poll delay
    /// Used for immediate response scenarios
    pub fn get_response(&mut self) -> Option<Vec<u8>> {
        self.response_queue.pop_front()
    }

    /// Check if there are pending responses
    pub fn has_pending_responses(&self) -> bool {
        !self.response_queue.is_empty()
    }

    /// Drain all pending responses into a single combined response
    /// Used when multiple commands are sent without polling between them
    pub fn drain_responses(&mut self) -> Vec<u8> {
        let mut combined = Vec::new();
        while let Some(resp) = self.response_queue.pop_front() {
            combined.extend_from_slice(&resp);
        }
        combined
    }

    /// Reset the interpreter state
    pub fn reset(&mut self) {
        self.response_queue.clear();
        self.state = TerminalState::Idle;
        self.poll_count = 0;
    }

    /// Get current state
    pub fn state(&self) -> &TerminalState {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wakeup_sequence() {
        let mut interp = TestTerminalInterpreter::new(0);

        // Send wakeup
        interp.process_input(&[0x0D]);

        // First poll returns nothing (simulated delay)
        assert!(interp.poll().is_none());

        // Second poll returns "OK<CR>"
        assert_eq!(interp.poll(), Some(b"OK\r".to_vec()));
    }

    #[test]
    fn test_clear_command() {
        let mut interp = TestTerminalInterpreter::new(0);
        interp.process_input(b"CLEAR\r");
        assert_eq!(interp.get_response(), Some(b"OK\r".to_vec()));
    }

    #[test]
    fn test_logoff_command() {
        let mut interp = TestTerminalInterpreter::new(0);
        interp.process_input(b"LOGOFF\r");
        assert_eq!(interp.get_response(), Some(b"OK\rBYE\r".to_vec()));
    }

    #[test]
    fn test_ieee_session_flow() {
        let mut interp = TestTerminalInterpreter::new(0);

        // Step 1: Wakeup
        interp.process_input(&[0x0D]);
        assert_eq!(*interp.state(), TerminalState::Ready);

        // Steps 3-4: First poll returns nothing
        assert!(interp.poll().is_none());

        // Steps 5-6: Second poll returns "OK<CR>"
        let response = interp.poll();
        assert_eq!(response, Some(b"OK\r".to_vec()));

        // Steps 7-8: CLEAR and LOGOFF without poll between
        interp.process_input(b"CLEAR\r");
        interp.process_input(b"LOGOFF\r");

        // Steps 9-10: Poll returns combined response
        let combined = interp.drain_responses();
        assert_eq!(combined, b"OK\rOK\rBYE\r".to_vec());
    }
}
