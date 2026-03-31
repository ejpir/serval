//! Owner-local bounded HTTP/2 protocol limits.
//!
//! These are protocol/helper capacities owned by `serval-h2`, not deployment
//! schema knobs.

/// Fixed compile-time frame payload capacity used by current h2 helpers.
/// Runtime `max_frame_size_bytes` must not exceed this until the framing layer
/// is fully parameterized.
pub const frame_payload_capacity_bytes: u32 = 16 * 1024;

/// Fixed compile-time header-block assembly/storage capacity used by current h2 helpers.
/// Runtime `max_header_block_size_bytes` must not exceed this until header
/// assembly storage is fully parameterized.
pub const header_block_capacity_bytes: u32 = 8 * 1024;

/// Maximum frames inspected while parsing the initial prior-knowledge request.
pub const max_initial_parse_frames: u32 = 16;

/// Maximum CONTINUATION frames accepted while assembling a single header block.
pub const max_continuation_frames: u8 = 16;

/// Maximum SETTINGS entries accepted in a single SETTINGS payload.
pub const max_settings_per_frame: u8 = 32;

comptime {
    if (frame_payload_capacity_bytes == 0) {
        @compileError("serval-h2.limits.frame_payload_capacity_bytes must be > 0");
    }
    if (header_block_capacity_bytes == 0) {
        @compileError("serval-h2.limits.header_block_capacity_bytes must be > 0");
    }
}
