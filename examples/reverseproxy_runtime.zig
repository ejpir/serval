//! Thin CLI wrapper over serval-reverseproxy product runtime API.

const std = @import("std");
const serval = @import("serval");
const cli = @import("serval-cli");

const VERSION: []const u8 = "0.1.0";

const Extra = struct {
    @"config-file": []const u8 = "",
};

pub fn main(process_init: std.process.Init) !void {
    var args = cli.Args(Extra).init("reverseproxy_runtime", VERSION, process_init.minimal.args);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    if (args.extra.@"config-file".len == 0) return error.MissingConfigFile;

    var runtime = try serval.reverseproxy.load(.{ .config_file = args.extra.@"config-file" });
    defer runtime.deinit();

    try runtime.run(.{ .port = args.port });
}
