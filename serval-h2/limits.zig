//! Owner-local bounded HTTP/2 protocol limits.
//!
//! These are protocol/helper capacities owned by `serval-h2`, not deployment
//! schema knobs.

/// Maximum frames inspected while parsing the initial prior-knowledge request.
pub const max_initial_parse_frames: u32 = 16;

/// Maximum CONTINUATION frames accepted while assembling a single header block.
pub const max_continuation_frames: u8 = 16;

/// Maximum SETTINGS entries accepted in a single SETTINGS payload.
pub const max_settings_per_frame: u8 = 32;
