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

pub const args = @import("args.zig");
pub const Args = args.Args;
pub const NoExtra = args.NoExtra;
pub const ParseResult = args.ParseResult;

test {
    _ = @import("args.zig");
}
