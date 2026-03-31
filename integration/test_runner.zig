// Custom test runner with verbose output
// Based on https://gist.github.com/karlseguin/c6bea5b35e4e8d26af6f81c22cb5d76b
// For Zig 0.15+

const std = @import("std");
const builtin = @import("builtin");

const BORDER = "=" ** 80;
const FailureRecord = struct {
    index: usize,
    name: []const u8,
    reason: []const u8,
};

/// Runs every function in `builtin.test_functions` and reports per-test progress, status, and a final summary.
/// Resets `std.testing.allocator_instance` before each test and treats a leak reported by `deinit()` as a failure.
/// A test that returns `error.SkipZigTest` is counted as skipped; any other error is counted as a failure and its stack trace is printed when available.
/// On success this function exits the process with status `0`; otherwise it exits with status `1`.
pub fn main() !void {
    std.debug.assert(builtin.test_functions.len > 0);

    var pass: usize = 0;
    var fail: usize = 0;
    var skip: usize = 0;
    var failures = std.ArrayList(FailureRecord).empty;
    defer failures.deinit(std.heap.page_allocator);

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
            try recordFailure(&failures, test_num, friendly_name, "LEAK");
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
                const error_name = @errorName(err);
                std.debug.print("\x1b[31mFAIL: {s}\x1b[0m\n", .{error_name});
                fail += 1;
                try recordFailure(&failures, test_num, friendly_name, error_name);
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

    if (failures.items.len > 0) {
        std.debug.print("Failed tests:\n", .{});
        for (failures.items) |failure| {
            std.debug.print("  {d}/{d} {s} [{s}]\n", .{
                failure.index,
                total,
                failure.name,
                failure.reason,
            });
        }
        std.debug.print("{s}\n", .{BORDER});
    }

    std.process.exit(if (fail == 0) 0 else 1);
}

fn recordFailure(
    failures: *std.ArrayList(FailureRecord),
    index: usize,
    name: []const u8,
    reason: []const u8,
) !void {
    std.debug.assert(index > 0);
    std.debug.assert(name.len > 0);
    std.debug.assert(reason.len > 0);

    try failures.append(std.heap.page_allocator, .{
        .index = index,
        .name = name,
        .reason = reason,
    });
}

fn extractTestName(name: []const u8) []const u8 {
    std.debug.assert(name.len > 0);

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
