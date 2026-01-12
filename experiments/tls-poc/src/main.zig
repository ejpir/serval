const std = @import("std");
const log = @import("serval-core").log.scoped(.tls_experiment);
const ssl = @import("ssl.zig");
const posix = std.posix;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const host = "www.google.com";
    const port: u16 = 443;

    log.info("=== BoringSSL TLS POC ===", .{});
    log.info("Connecting to {s}:{d}...", .{ host, port });

    // Create Io instance
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // 1. Initialize BoringSSL
    ssl.init();

    // 2. Create SSL_CTX
    const ctx = try ssl.createClientCtx();
    defer ssl.SSL_CTX_free(ctx);
    log.info("SSL_CTX created", .{});

    // 3. Connect using HostName.connect (handles DNS + connect)
    const hostname = try std.Io.net.HostName.init(host);
    const stream = try hostname.connect(io, port, .{ .mode = .stream });
    defer stream.close(io);

    const sock: c_int = @intCast(stream.socket.handle);
    log.info("TCP connected, fd={d}", .{sock});

    // 6. Create SSL object
    const ssl_conn = try ssl.createSsl(ctx);
    defer ssl.SSL_free(ssl_conn);

    // 7. Set socket fd
    if (ssl.SSL_set_fd(ssl_conn, sock) != 1) {
        log.err("SSL_set_fd failed", .{});
        return error.SslSetFd;
    }

    // 8. Set SNI hostname
    const host_z = try allocator.dupeZ(u8, host);
    defer allocator.free(host_z);
    if (ssl.SSL_set_tlsext_host_name(ssl_conn, host_z) != 1) {
        log.err("SSL_set_tlsext_host_name failed", .{});
        return error.SslSetHostname;
    }

    // 9. Set client mode
    ssl.SSL_set_connect_state(ssl_conn);

    log.info("Starting TLS handshake...", .{});

    // 10. Do handshake
    const ret = ssl.SSL_connect(ssl_conn);
    if (ret != 1) {
        const err = ssl.SSL_get_error(ssl_conn, ret);
        log.err("SSL_connect failed: {d}", .{err});
        ssl.printErrors();
        return error.SslConnect;
    }

    log.info("TLS handshake complete!", .{});

    // Print connection info
    if (ssl.SSL_get_version(ssl_conn)) |v| {
        log.info("TLS version: {s}", .{std.mem.span(v)});
    }
    if (ssl.SSL_get_current_cipher(ssl_conn)) |cipher| {
        if (ssl.SSL_CIPHER_get_name(cipher)) |cn| {
            log.info("Cipher: {s}", .{std.mem.span(cn)});
        }
    }

    // 11. Send HTTP request
    const request = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    const written = ssl.SSL_write(ssl_conn, request.ptr, @intCast(request.len));
    if (written <= 0) {
        log.err("SSL_write failed", .{});
        return error.SslWrite;
    }
    log.info("Sent {d} bytes", .{written});

    // 12. Read response
    var buf: [4096]u8 = undefined;
    var total: usize = 0;

    while (true) {
        const n = ssl.SSL_read(ssl_conn, &buf, buf.len);
        if (n <= 0) {
            const err = ssl.SSL_get_error(ssl_conn, n);
            if (err == ssl.SSL_ERROR_ZERO_RETURN) {
                log.info("Connection closed cleanly", .{});
                break;
            }
            log.info("SSL_read returned {d}, error {d}", .{ n, err });
            break;
        }
        total += @intCast(n);

        // Print first chunk
        if (total <= 4096) {
            const chunk: usize = @intCast(n);
            std.debug.print("{s}", .{buf[0..chunk]});
        }
    }

    log.info("\nReceived {d} bytes total", .{total});

    // 13. Shutdown
    _ = ssl.SSL_shutdown(ssl_conn);
    log.info("Done!", .{});
}
