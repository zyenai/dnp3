//! Common utilities for Virtual Terminal examples

pub mod terminal_interpreter;
pub mod test_patterns;

pub use terminal_interpreter::TerminalState;
pub use terminal_interpreter::TestTerminalInterpreter;
pub use test_patterns::all_byte_values;
pub use test_patterns::all_byte_values_max_vt;
pub use test_patterns::ascii_dump;
pub use test_patterns::compare_data;
pub use test_patterns::dnp3_sync_pattern;
pub use test_patterns::hex_dump;
pub use test_patterns::null_embedded_pattern;
pub use test_patterns::prng_data;
pub use test_patterns::size_boundary_patterns;
pub use test_patterns::special_byte_patterns;
pub use test_patterns::ssh_banner;
pub use test_patterns::validate_variation_length;
pub use test_patterns::TestPattern;
