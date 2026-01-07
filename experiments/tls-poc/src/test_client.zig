const std = @import("std");
const ssl = @import("ssl.zig");
const posix = std.posix;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const host = "localhost";
    const port: u16 = 8443;

    std.log.info("=== TLS Test Client ===", .{});
    std.log.info("Connecting to {s}:{d}...", .{ host, port });

    // Create Io instance
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // 1. Initialize BoringSSL
    ssl.init();

    // 2. Create SSL_CTX
    const ctx = try ssl.createClientCtx();
    defer ssl.SSL_CTX_free(ctx);

    // Disable certificate verification for self-signed cert
    ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_NONE, null);
    std.log.info("SSL_CTX created (verification disabled)", .{});

    // 3. Connect to localhost:8443
    const addr = std.Io.net.IpAddress{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = port,
    } };

    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    const sock: c_int = @intCast(stream.socket.handle);
    std.log.info("TCP connected, fd={d}", .{sock});

    // 4. Create SSL object
    const ssl_conn = try ssl.createSsl(ctx);
    defer ssl.SSL_free(ssl_conn);

    // 5. Set socket fd
    if (ssl.SSL_set_fd(ssl_conn, sock) != 1) {
        std.log.err("SSL_set_fd failed", .{});
        return error.SslSetFd;
    }

    // 6. Set SNI hostname
    const host_z = try allocator.dupeZ(u8, host);
    defer allocator.free(host_z);
    if (ssl.SSL_set_tlsext_host_name(ssl_conn, host_z) != 1) {
        std.log.err("SSL_set_tlsext_host_name failed", .{});
        return error.SslSetHostname;
    }

    // 7. Set client mode
    ssl.SSL_set_connect_state(ssl_conn);

    std.log.info("Starting TLS handshake...", .{});

    // 8. Do handshake
    const ret = ssl.SSL_connect(ssl_conn);
    if (ret != 1) {
        const err = ssl.SSL_get_error(ssl_conn, ret);
        std.log.err("SSL_connect failed: {d}", .{err});
        ssl.printErrors();
        return error.SslConnect;
    }

    std.log.info("TLS handshake complete!", .{});

    // Print connection info
    if (ssl.SSL_get_version(ssl_conn)) |v| {
        std.log.info("TLS version: {s}", .{std.mem.span(v)});
    }
    if (ssl.SSL_get_current_cipher(ssl_conn)) |cipher| {
        if (ssl.SSL_CIPHER_get_name(cipher)) |cn| {
            std.log.info("Cipher: {s}", .{std.mem.span(cn)});
        }
    }

    // 9. Send HTTP request
    const request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const written = ssl.SSL_write(ssl_conn, request.ptr, @intCast(request.len));
    if (written <= 0) {
        std.log.err("SSL_write failed", .{});
        return error.SslWrite;
    }
    std.log.info("Sent {d} bytes", .{written});

    // 10. Read response
    var buf: [4096]u8 = undefined;
    const n = ssl.SSL_read(ssl_conn, &buf, buf.len);
    if (n <= 0) {
        const err = ssl.SSL_get_error(ssl_conn, n);
        std.log.err("SSL_read failed: {d}", .{err});
        return error.SslRead;
    }

    const bytes_read: usize = @intCast(n);
    std.log.info("Received {d} bytes:", .{bytes_read});
    std.debug.print("{s}\n", .{buf[0..bytes_read]});

    // 11. Shutdown
    _ = ssl.SSL_shutdown(ssl_conn);
    std.log.info("Done!", .{});
}
