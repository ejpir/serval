// Custom test runner with verbose output
// Based on https://gist.github.com/karlseguin/c6bea5b35e4e8d26af6f81c22cb5d76b
// For Zig 0.15+

const std = @import("std");
const builtin = @import("builtin");

const BORDER = "=" ** 80;

pub fn main() !void {
    var pass: usize = 0;
    var fail: usize = 0;
    var skip: usize = 0;

    const total = builtin.test_functions.len;
    var test_num: usize = 0;

    for (builtin.test_functions) |t| {
        test_num += 1;
        std.testing.allocator_instance = .{};

        const friendly_name = extractTestName(t.name);

        // Print test name before running
        std.debug.print("{d}/{d} {s}...", .{ test_num, total, friendly_name });

        const result = t.func();

        if (std.testing.allocator_instance.deinit() == .leak) {
            std.debug.print("\x1b[31mLEAK\x1b[0m\n", .{});
            fail += 1;
            continue;
        }

        if (result) |_| {
            std.debug.print("\x1b[32mOK\x1b[0m\n", .{});
            pass += 1;
        } else |err| switch (err) {
            error.SkipZigTest => {
                std.debug.print("\x1b[33mSKIP\x1b[0m\n", .{});
                skip += 1;
            },
            else => {
                std.debug.print("\x1b[31mFAIL: {s}\x1b[0m\n", .{@errorName(err)});
                fail += 1;
                if (@errorReturnTrace()) |trace| {
                    std.debug.dumpStackTrace(trace);
                }
            },
        }
    }

    std.debug.print("\n{s}\n", .{BORDER});
    if (fail == 0) {
        std.debug.print("\x1b[32mAll {d} tests passed", .{pass});
    } else {
        std.debug.print("\x1b[31m{d} of {d} tests failed", .{ fail, pass + fail });
    }
    if (skip > 0) {
        std.debug.print(" ({d} skipped)", .{skip});
    }
    std.debug.print("\x1b[0m\n{s}\n", .{BORDER});

    std.process.exit(if (fail == 0) 0 else 1);
}

fn extractTestName(name: []const u8) []const u8 {
    // Extract friendly name from "module.test.actual test name"
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |value| {
        if (std.mem.eql(u8, value, "test")) {
            const rest = it.rest();
            return if (rest.len > 0) rest else name;
        }
    }
    return name;
}
