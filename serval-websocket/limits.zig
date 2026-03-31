//! Owner-local bounded WebSocket protocol limits.
//!
//! These are RFC or protocol-helper bounds owned by `serval-websocket`, not
//! deployment schema knobs.

/// Maximum allowed control-frame payload size per RFC 6455 Section 5.5.
pub const max_control_payload_size_bytes: u32 = 125;
