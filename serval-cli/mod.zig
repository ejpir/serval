// lib/serval-cli/mod.zig
//! Serval CLI - Command-Line Interface Utilities
//!
//! Comptime-generic argument parsing for serval binaries.
//! Provides common options with binary-specific extensions.
//!
//! ## Usage
//!
//! ```zig
//! const cli = @import("serval-cli");
//!
//! const VERSION = "0.1.0";  // Each binary defines its own version
//!
//! const LbExtra = struct {
//!     backends: []const u8 = "127.0.0.1:8001,8002",
//!     algorithm: enum { round_robin, least_conn } = .round_robin,
//! };
//!
//! pub fn main() !void {
//!     var args = cli.Args(LbExtra).init("lb", VERSION);
//!     switch (args.parse()) {
//!         .ok => {},
//!         .help, .version => return,
//!         .err => {
//!             args.printError();
//!             return error.InvalidArgs;
//!         },
//!     }
//!
//!     std.debug.print("Port: {d}\n", .{args.port});
//!     std.debug.print("Backends: {s}\n", .{args.extra.backends});
//! }
//! ```
//!
//! TigerStyle: No runtime allocation, compile-time type safety.

/// Imported `args.zig` module namespace.
/// This module provides the CLI parser implementation and its public re-exports.
/// Use the names from this namespace when importing `serval-cli`.
pub const args = @import("args.zig");
/// Re-export of `args.Args`.
/// Instantiate this comptime generic with an `Extra` struct to build a parser type with the shared options and your binary-specific fields.
/// The resulting type owns only borrowed argument slices; it does not allocate.
pub const Args = args.Args;
/// Re-export of `args.NoExtra`.
/// This is an empty extra-options type for binaries that define no CLI-specific flags.
/// Pass it to `Args` when you only need the built-in options.
pub const NoExtra = args.NoExtra;
/// Re-export of `args.ParseResult`.
/// Use this enum to distinguish successful parsing from help, version, and parse-error exits.
/// Returned by `Args(...).parse()`.
pub const ParseResult = args.ParseResult;

test {
    _ = @import("args.zig");
}
