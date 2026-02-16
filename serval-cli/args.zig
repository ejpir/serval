// lib/serval-cli/args.zig
//! CLI Argument Parsing
//!
//! Comptime-generic argument parser for serval binaries.
//! Provides common options (--port, --debug, --help, --version)
//! with binary-specific extensions via comptime generics.
//!
//! TigerStyle: No runtime allocation, compile-time type safety.

const std = @import("std");
const assert = std.debug.assert;

/// Result of argument parsing.
pub const ParseResult = enum {
    ok,
    help,
    version,
    err,
};

/// Create an Args type with common options plus binary-specific extras.
///
/// Usage:
/// ```zig
/// const LbExtra = struct {
///     backends: []const u8 = "127.0.0.1:8001",
///     algorithm: enum { round_robin, least_conn } = .round_robin,
/// };
///
/// var args = cli.Args(LbExtra).init("lb", "0.1.0", init.minimal.args);
/// switch (args.parse()) {
///     .ok => {},
///     .help => return,
///     .version => return,
///     .err => return error.InvalidArgs,
/// }
/// // Use args.port, args.debug, args.extra.backends
/// ```
pub fn Args(comptime Extra: type) type {
    return struct {
        const Self = @This();

        // =====================================================================
        // Common options (all binaries)
        // =====================================================================

        /// Listening port
        port: u16 = 8080,

        /// Enable debug logging
        debug: bool = false,

        /// Path to config file (optional)
        config_file: ?[]const u8 = null,

        // =====================================================================
        // Binary-specific options
        // =====================================================================

        /// Extra options defined by the binary
        extra: Extra = .{},

        // =====================================================================
        // Internal state
        // =====================================================================

        /// Binary name for help/version output
        binary_name: []const u8,

        /// Version string provided by the binary
        version: []const u8,

        /// Iterator over process args
        args_iter: std.process.Args.Iterator,

        /// Parse error message (if any)
        err_msg: ?[]const u8 = null,

        // =====================================================================
        // Public API
        // =====================================================================

        /// Initialize argument parser.
        /// TigerStyle: Requires non-empty binary_name and version.
        pub fn init(binary_name: []const u8, version: []const u8, process_args: std.process.Args) Self {
            assert(binary_name.len > 0);
            assert(version.len > 0);

            return .{
                .binary_name = binary_name,
                .version = version,
                .args_iter = process_args.iterate(),
            };
        }

        /// Parse command-line arguments.
        /// Returns .ok on success, .help/.version if those flags were passed,
        /// .err if parsing failed (check err_msg for details).
        pub fn parse(self: *Self) ParseResult {
            // Skip program name
            _ = self.args_iter.skip();

            // Bounded iteration - max 256 arguments
            var iterations: u16 = 0;
            const max_iterations: u16 = 256;

            while (iterations < max_iterations) : (iterations += 1) {
                const arg = self.args_iter.next() orelse break;

                // Common options
                if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
                    self.printHelp();
                    return .help;
                }
                if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
                    self.printVersion();
                    return .version;
                }
                if (std.mem.eql(u8, arg, "--debug")) {
                    self.debug = true;
                    continue;
                }
                if (std.mem.eql(u8, arg, "--port")) {
                    const value = self.args_iter.next() orelse {
                        self.err_msg = "--port requires a value";
                        return .err;
                    };
                    self.port = std.fmt.parseInt(u16, value, 10) catch {
                        self.err_msg = "--port must be a valid port number (1-65535)";
                        return .err;
                    };
                    continue;
                }
                if (std.mem.eql(u8, arg, "--config")) {
                    const value = self.args_iter.next() orelse {
                        self.err_msg = "--config requires a file path";
                        return .err;
                    };
                    self.config_file = value;
                    continue;
                }

                // Try to parse as binary-specific option
                if (!self.parseExtra(arg)) {
                    self.err_msg = arg;
                    return .err;
                }
            }

            return .ok;
        }

        /// Print error message to stderr.
        pub fn printError(self: *const Self) void {
            if (self.err_msg) |msg| {
                // Check if it looks like an unrecognized option
                if (msg.len > 0 and msg[0] == '-') {
                    std.debug.print("error: unrecognized option '{s}'\n", .{msg});
                } else {
                    std.debug.print("error: {s}\n", .{msg});
                }
                std.debug.print("Try '{s} --help' for more information.\n", .{self.binary_name});
            }
        }

        // =====================================================================
        // Help and version output
        // =====================================================================

        fn printVersion(self: *const Self) void {
            std.debug.print("{s} {s}\n", .{ self.binary_name, self.version });
        }

        fn printHelp(self: *const Self) void {
            std.debug.print(
                \\Usage: {s} [OPTIONS]
                \\
                \\Common options:
                \\  -h, --help          Show this help message
                \\  -v, --version       Show version
                \\  --port <PORT>       Listening port (default: 8080)
                \\  --debug             Enable debug logging
                \\  --config <FILE>     Load configuration from file
                \\
            , .{self.binary_name});

            // Print extra options if Extra type has any fields
            const extra_fields = @typeInfo(Extra).@"struct".fields;
            if (extra_fields.len > 0) {
                std.debug.print("Binary-specific options:\n", .{});
                inline for (extra_fields) |field| {
                    const default_str = self.formatDefault(field);
                    std.debug.print("  --{s: <16} (default: {s})\n", .{ field.name, default_str });
                }
                std.debug.print("\n", .{});
            }
        }

        fn formatDefault(self: *const Self, comptime field: std.builtin.Type.StructField) []const u8 {
            _ = self;
            const type_info = @typeInfo(field.type);

            // Handle optional types first (check type, not value)
            if (type_info == .optional) {
                return "none";
            }

            if (field.default_value_ptr) |ptr| {
                const typed_ptr: *const field.type = @ptrCast(@alignCast(ptr));
                const value = typed_ptr.*;
                return switch (type_info) {
                    .pointer => value,
                    .@"enum" => @tagName(value),
                    .int => std.fmt.comptimePrint("{d}", .{value}),
                    .bool => if (value) "true" else "false",
                    else => "?",
                };
            }
            return "required";
        }

        // =====================================================================
        // Extra field parsing (comptime-generated)
        // =====================================================================

        fn parseExtra(self: *Self, arg: []const u8) bool {
            // Must start with --
            if (arg.len < 3 or arg[0] != '-' or arg[1] != '-') {
                return false;
            }
            const name = arg[2..];

            // Check each field in Extra
            const fields = @typeInfo(Extra).@"struct".fields;
            inline for (fields) |field| {
                if (std.mem.eql(u8, name, field.name)) {
                    return self.parseExtraField(field);
                }
            }

            return false;
        }

        fn parseExtraField(self: *Self, comptime field: std.builtin.Type.StructField) bool {
            const FieldType = field.type;

            switch (@typeInfo(FieldType)) {
                .bool => {
                    // Boolean flags don't need a value
                    @field(self.extra, field.name) = true;
                    return true;
                },
                .int => {
                    const value = self.args_iter.next() orelse {
                        self.err_msg = "--" ++ field.name ++ " requires a value";
                        return true; // Return true to stop iteration, but set error
                    };
                    @field(self.extra, field.name) = std.fmt.parseInt(FieldType, value, 10) catch {
                        self.err_msg = "--" ++ field.name ++ " must be a valid number";
                        return true;
                    };
                    return true;
                },
                .pointer => |ptr| {
                    if (ptr.child == u8) {
                        // []const u8 - string value
                        const value = self.args_iter.next() orelse {
                            self.err_msg = "--" ++ field.name ++ " requires a value";
                            return true;
                        };
                        @field(self.extra, field.name) = value;
                        return true;
                    }
                    return false;
                },
                .optional => |opt| {
                    // Handle optional types like ?[]const u8
                    switch (@typeInfo(opt.child)) {
                        .pointer => |ptr| {
                            if (ptr.child == u8) {
                                // ?[]const u8 - optional string value
                                const value = self.args_iter.next() orelse {
                                    self.err_msg = "--" ++ field.name ++ " requires a value";
                                    return true;
                                };
                                @field(self.extra, field.name) = value;
                                return true;
                            }
                            return false;
                        },
                        else => return false,
                    }
                },
                .@"enum" => {
                    const value = self.args_iter.next() orelse {
                        self.err_msg = "--" ++ field.name ++ " requires a value";
                        return true;
                    };
                    @field(self.extra, field.name) = std.meta.stringToEnum(FieldType, value) orelse {
                        self.err_msg = "--" ++ field.name ++ " has invalid value";
                        return true;
                    };
                    return true;
                },
                else => return false,
            }
        }
    };
}

/// Empty struct for binaries with no extra options.
pub const NoExtra = struct {};

// =============================================================================
// Tests
// =============================================================================

test "Args with no extra fields" {
    const TestArgs = Args(NoExtra);
    const args = TestArgs.init("test", "1.0.0", std.process.Args{ .vector = &.{} });
    _ = args;
}

test "Args with extra fields compiles" {
    const Extra = struct {
        backends: []const u8 = "127.0.0.1:8001",
        timeout_ms: u32 = 5000,
        verbose: bool = false,
    };
    const TestArgs = Args(Extra);
    const args = TestArgs.init("test", "1.0.0", std.process.Args{ .vector = &.{} });
    _ = args;
}
