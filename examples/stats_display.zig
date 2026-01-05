// examples/stats_display.zig
//! Terminal Stats Display
//!
//! Real-time statistics display with ANSI scroll regions for pinned header.
//! Background thread updates header every second while log lines scroll below.
//! TigerStyle: Bounded loop, explicit cleanup, atomic control.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;
const serval = @import("serval");
const serval_metrics = @import("serval-metrics");
const config = @import("serval-core").config;

const Upstream = serval.Upstream;
const SimplePool = serval.SimplePool;
const RealTimeMetrics = serval_metrics.RealTimeMetrics;
const StatsSnapshot = serval_metrics.StatsSnapshot;

// =============================================================================
// Constants
// =============================================================================

/// Number of header lines (pinned at top).
/// TigerStyle: Explicit constant, visible in scroll region setup.
const HEADER_LINES: u8 = 5;

/// Maximum upstreams to display in header.
/// TigerStyle: Fixed bound for header line length.
const MAX_DISPLAY_UPSTREAMS: u8 = 8;

/// Output buffer size for formatted header.
/// TigerStyle: Fixed size, no allocation.
const OUTPUT_BUFFER_SIZE: u32 = 2048;

// =============================================================================
// ANSI Escape Sequences
// =============================================================================

/// Save cursor position.
const ANSI_SAVE_CURSOR = "\x1b[s";

/// Restore cursor position.
const ANSI_RESTORE_CURSOR = "\x1b[u";

/// Move cursor to home (0,0).
const ANSI_HOME = "\x1b[H";

/// Clear line from cursor to end.
const ANSI_CLEAR_LINE = "\x1b[K";

/// Reset scroll region to full terminal.
const ANSI_RESET_SCROLL = "\x1b[r";

/// Bold cyan color (for title).
const ANSI_BOLD_CYAN = "\x1b[1;36m";

/// Reset all formatting.
const ANSI_RESET = "\x1b[0m";

/// Clear entire screen.
const ANSI_CLEAR_SCREEN = "\x1b[2J";

// =============================================================================
// Output Helpers
// =============================================================================

/// Write bytes to stdout using posix write.
/// TigerStyle: Simple, synchronous output for terminal control.
fn writeStdout(bytes: []const u8) void {
    _ = posix.write(posix.STDOUT_FILENO, bytes) catch |err| {
        // TigerStyle: Log errors in debug builds, don't crash for terminal I/O
        if (@import("builtin").mode == .Debug) {
            std.log.debug("stats_display: stdout write failed: {s}", .{@errorName(err)});
        }
    };
}

// =============================================================================
// StatsDisplay
// =============================================================================

/// Terminal stats display with pinned header and scrolling log region.
/// Background thread updates header at 1Hz while logs scroll below.
/// TigerStyle: Atomic running flag for clean shutdown.
pub const StatsDisplay = struct {
    metrics: *RealTimeMetrics,
    pool: *SimplePool,
    upstreams: []const Upstream,
    running: std.atomic.Value(bool),
    thread: ?std.Thread = null,

    /// Create new stats display.
    /// TigerStyle: Does not start thread - call start() explicitly.
    pub fn init(
        metrics: *RealTimeMetrics,
        pool: *SimplePool,
        upstreams: []const Upstream,
    ) StatsDisplay {
        assert(upstreams.len > 0);
        assert(upstreams.len <= 64); // MAX_UPSTREAMS from config

        return .{
            .metrics = metrics,
            .pool = pool,
            .upstreams = upstreams,
            .running = std.atomic.Value(bool).init(false),
            .thread = null,
        };
    }

    /// Start the display thread.
    /// Sets up scroll region and spawns background update thread.
    /// TigerStyle: Idempotent - safe to call multiple times.
    pub fn start(self: *StatsDisplay) !void {
        // Atomically set running from false to true
        // Returns null on success, previous value on failure
        if (self.running.cmpxchgStrong(false, true, .acq_rel, .acquire)) |_| {
            return; // Already running
        }

        self.setupScrollRegion();
        self.thread = try std.Thread.spawn(.{}, displayLoop, .{self});
    }

    /// Stop the display thread and restore terminal.
    /// TigerStyle: Idempotent - safe to call multiple times or if never started.
    pub fn stop(self: *StatsDisplay) void {
        // Signal thread to stop
        self.running.store(false, .release);

        // Wait for thread to exit
        // TigerStyle: Thread should exit within ~1 second (one sleep cycle).
        // If thread is stuck, this blocks - acceptable for graceful shutdown.
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }

        // Restore terminal state
        self.restoreTerminal();
    }

    /// Set up terminal scroll region.
    /// Pins header (lines 1-HEADER_LINES), logs scroll below.
    /// TigerStyle: Uses ANSI CSI to set scroll region.
    fn setupScrollRegion(self: *StatsDisplay) void {
        _ = self;

        // Clear screen and move to home
        writeStdout(ANSI_CLEAR_SCREEN);
        writeStdout(ANSI_HOME);

        // Set scroll region: line (HEADER_LINES+1) to bottom (999 = "to end")
        // Format: \x1b[{top};999r
        var buf: [32]u8 = undefined;
        const scroll_cmd = std.fmt.bufPrint(&buf, "\x1b[{d};999r", .{HEADER_LINES + 1}) catch return;
        writeStdout(scroll_cmd);

        // Move cursor to first scrollable line
        const move_cmd = std.fmt.bufPrint(&buf, "\x1b[{d};1H", .{HEADER_LINES + 1}) catch return;
        writeStdout(move_cmd);
    }

    /// Background thread main loop.
    /// Updates header every second while running.
    /// TigerStyle: Bounded loop controlled by atomic flag.
    fn displayLoop(self: *StatsDisplay) void {
        // TigerStyle: Bounded iterations - max ~10 years at 1Hz
        const max_iterations: u64 = 365 * 24 * 60 * 60 * 10;
        var iteration: u64 = 0;

        while (self.running.load(.acquire) and iteration < max_iterations) : (iteration += 1) {
            self.drawHeader();
            std.posix.nanosleep(1, 0);
        }
    }

    /// Draw the header section (5 lines).
    /// Saves cursor, draws header, restores cursor.
    /// TigerStyle: Atomic cursor save/restore for clean output.
    fn drawHeader(self: *StatsDisplay) void {
        // Get current stats snapshot
        const stats = self.metrics.snapshot();
        const pool_stats = self.pool.getStats();

        // Build header in buffer
        var buf: [OUTPUT_BUFFER_SIZE]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);

        // Save cursor position
        writer.writeAll(ANSI_SAVE_CURSOR) catch return;

        // Move to home position
        writer.writeAll(ANSI_HOME) catch return;

        // Line 1: Title
        writer.writeAll(ANSI_BOLD_CYAN) catch return;
        writer.writeAll("== SERVAL LOAD BALANCER ==") catch return;
        writer.writeAll(ANSI_RESET) catch return;
        writer.writeAll(ANSI_CLEAR_LINE) catch return;
        writer.writeAll("\n") catch return;

        // Lines 2-4: Stats lines
        writeRequestsLine(&writer, &stats);
        writeConnectionsLine(&writer, &stats, &pool_stats, self.upstreams.len);
        writeLatencyLine(&writer, &stats);

        // Line 5: Upstream status
        // Format: Upstreams: [0] 508/s .  [1] 502/s .  [2] 237/s x
        writer.writeAll("Upstreams: ") catch return;
        self.writeUpstreamStats(&writer, &stats);
        writer.writeAll(ANSI_CLEAR_LINE) catch return;
        writer.writeAll("\n") catch return;

        // Restore cursor position
        writer.writeAll(ANSI_RESTORE_CURSOR) catch return;

        // Write entire buffer to stdout atomically
        const written = writer.buffered();
        // TigerStyle: Postcondition - buffer didn't overflow
        assert(written.len < OUTPUT_BUFFER_SIZE);
        writeStdout(written);
    }

    /// Format line 2: request stats.
    /// Format: Requests: 15,234 total | 1,247/sec | Errors: 0.2%
    fn writeRequestsLine(writer: *std.Io.Writer, stats: *const StatsSnapshot) void {
        const error_pct: f64 = if (stats.requests_total > 0)
            @as(f64, @floatFromInt(stats.errors_total)) / @as(f64, @floatFromInt(stats.requests_total)) * 100.0
        else
            0.0;

        writer.print("Requests: {d} total | {d:.0}/sec | Errors: {d:.1}%", .{
            stats.requests_total,
            stats.requests_per_sec,
            error_pct,
        }) catch return;
        writer.writeAll(ANSI_CLEAR_LINE) catch return;
        writer.writeAll("\n") catch return;
    }

    /// Format line 3: connection stats.
    /// Format: Connections: 42 active | Pool: 12/64 used
    fn writeConnectionsLine(
        writer: *std.Io.Writer,
        stats: *const StatsSnapshot,
        pool_stats: *const SimplePool.PoolStats,
        upstreams_len: usize,
    ) void {
        const max_pool_size = @as(u32, @intCast(upstreams_len)) * config.MAX_CONNS_PER_UPSTREAM;
        writer.print("Connections: {d} active | Pool: {d}/{d} used", .{
            stats.connections_active,
            pool_stats.total_available + pool_stats.total_checked_out,
            max_pool_size,
        }) catch return;
        writer.writeAll(ANSI_CLEAR_LINE) catch return;
        writer.writeAll("\n") catch return;
    }

    /// Format line 4: latency percentiles.
    /// Format: Latency: p50=2ms p95=8ms p99=23ms
    fn writeLatencyLine(writer: *std.Io.Writer, stats: *const StatsSnapshot) void {
        writer.print("Latency: p50={d}ms p95={d}ms p99={d}ms", .{
            stats.latency_p50_ms,
            stats.latency_p95_ms,
            stats.latency_p99_ms,
        }) catch return;
        writer.writeAll(ANSI_CLEAR_LINE) catch return;
        writer.writeAll("\n") catch return;
    }

    /// Write per-upstream stats to buffer.
    /// Shows RPS and health indicator for each upstream.
    /// TigerStyle: Bounded iteration over upstreams.
    fn writeUpstreamStats(self: *StatsDisplay, writer: *std.Io.Writer, stats: *const StatsSnapshot) void {
        // TigerStyle: Precondition - upstreams slice is valid
        assert(self.upstreams.len > 0);

        const display_count = @min(self.upstreams.len, MAX_DISPLAY_UPSTREAMS);

        var i: u8 = 0;
        while (i < display_count) : (i += 1) {
            if (i > 0) {
                writer.writeAll("  ") catch return;
            }

            const upstream_stats = stats.upstream_stats[i];
            const health_icon: []const u8 = if (upstream_stats.healthy) "." else "x";

            writer.print("[{d}] {d:.0}/s {s}", .{
                i,
                upstream_stats.requests_per_sec,
                health_icon,
            }) catch return;
        }

        // Indicate if there are more upstreams
        if (self.upstreams.len > MAX_DISPLAY_UPSTREAMS) {
            writer.print(" +{d} more", .{self.upstreams.len - MAX_DISPLAY_UPSTREAMS}) catch return;
        }
    }

    /// Restore terminal to normal state.
    /// Resets scroll region and clears header area.
    /// TigerStyle: Clean terminal on exit.
    fn restoreTerminal(self: *StatsDisplay) void {
        _ = self;

        // Reset scroll region to full terminal
        writeStdout(ANSI_RESET_SCROLL);

        // Move cursor below header area
        var buf: [32]u8 = undefined;
        const move_cmd = std.fmt.bufPrint(&buf, "\x1b[{d};1H", .{HEADER_LINES + 1}) catch return;
        writeStdout(move_cmd);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "StatsDisplay init creates valid instance" {
    var metrics = RealTimeMetrics.init();
    var pool = SimplePool.init();
    const upstreams = [_]Upstream{
        .{ .host = "localhost", .port = 8001, .idx = 0 },
        .{ .host = "localhost", .port = 8002, .idx = 1 },
    };

    const display = StatsDisplay.init(&metrics, &pool, &upstreams);

    try std.testing.expect(!display.running.load(.acquire));
    try std.testing.expect(display.thread == null);
    try std.testing.expectEqual(@as(usize, 2), display.upstreams.len);
}

test "StatsDisplay stop is idempotent" {
    var metrics = RealTimeMetrics.init();
    var pool = SimplePool.init();
    const upstreams = [_]Upstream{
        .{ .host = "localhost", .port = 8001, .idx = 0 },
    };

    var display = StatsDisplay.init(&metrics, &pool, &upstreams);

    // Stop before ever starting - should not crash
    display.stop();
    display.stop();
    display.stop();

    try std.testing.expect(!display.running.load(.acquire));
}
