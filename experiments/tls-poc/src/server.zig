const std = @import("std");
const ssl = @import("ssl.zig");
const posix = std.posix;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const port: u16 = 8443;

    std.log.info("=== BoringSSL TLS Server POC ===", .{});
    std.log.info("Starting server on port {d}...", .{port});

    // Create Io instance
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // 1. Initialize BoringSSL
    ssl.init();

    // 2. Create SSL_CTX for server
    const ctx = try ssl.createServerCtx();
    defer ssl.SSL_CTX_free(ctx);
    std.log.info("SSL_CTX created", .{});

    // 3. Load certificate and private key
    const cert_path = "cert.pem";
    const key_path = "key.pem";

    const cert_path_z = try allocator.dupeZ(u8, cert_path);
    defer allocator.free(cert_path_z);
    const key_path_z = try allocator.dupeZ(u8, key_path);
    defer allocator.free(key_path_z);

    if (ssl.SSL_CTX_use_certificate_chain_file(ctx, cert_path_z) != 1) {
        std.log.err("Failed to load certificate from {s}", .{cert_path});
        ssl.printErrors();
        return error.LoadCertFailed;
    }
    std.log.info("Loaded certificate from {s}", .{cert_path});

    if (ssl.SSL_CTX_use_PrivateKey_file(ctx, key_path_z, ssl.SSL_FILETYPE_PEM) != 1) {
        std.log.err("Failed to load private key from {s}", .{key_path});
        ssl.printErrors();
        return error.LoadKeyFailed;
    }
    std.log.info("Loaded private key from {s}", .{key_path});

    // 4. Listen on port using std.Io.net
    const listen_addr = std.Io.net.IpAddress{ .ip4 = .{
        .bytes = .{ 0, 0, 0, 0 }, // 0.0.0.0 - listen on all interfaces
        .port = port,
    } };

    var server = try listen_addr.listen(io, .{ .kernel_backlog = 128 });
    defer server.deinit(io);
    std.log.info("Listening on 0.0.0.0:{d}", .{port});

    // 5. Accept loop
    while (true) {
        std.log.info("Waiting for connection...", .{});

        const client_stream = try server.accept(io);
        defer client_stream.close(io);

        const client_fd: c_int = @intCast(client_stream.socket.handle);
        std.log.info("Accepted connection, fd={d}", .{client_fd});

        // 6. Create SSL object
        const ssl_conn = try ssl.createSsl(ctx);
        defer ssl.SSL_free(ssl_conn);

        // 7. Set socket fd
        if (ssl.SSL_set_fd(ssl_conn, client_fd) != 1) {
            std.log.err("SSL_set_fd failed", .{});
            continue;
        }

        // 8. Set server mode
        ssl.SSL_set_accept_state(ssl_conn);

        std.log.info("Starting TLS handshake...", .{});

        // 9. Do handshake
        const ret = ssl.SSL_accept(ssl_conn);
        if (ret != 1) {
            const err = ssl.SSL_get_error(ssl_conn, ret);
            std.log.err("SSL_accept failed: {d}", .{err});
            ssl.printErrors();
            continue;
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

        // 10. Read request
        var buf: [4096]u8 = undefined;
        const n = ssl.SSL_read(ssl_conn, &buf, buf.len);
        if (n <= 0) {
            const err = ssl.SSL_get_error(ssl_conn, n);
            std.log.err("SSL_read failed: {d}", .{err});
            continue;
        }

        const bytes_read: usize = @intCast(n);
        std.log.info("Received {d} bytes:", .{bytes_read});
        std.debug.print("{s}\n", .{buf[0..bytes_read]});

        // 11. Send HTTP response
        const response =
            \\HTTP/1.1 200 OK
            \\Content-Type: text/plain
            \\Content-Length: 23
            \\Connection: close
            \\
            \\Hello from Zig + BoringSSL!
        ;

        const written = ssl.SSL_write(ssl_conn, response.ptr, @intCast(response.len));
        if (written <= 0) {
            std.log.err("SSL_write failed", .{});
            continue;
        }
        std.log.info("Sent {d} bytes response", .{written});

        // 12. Shutdown
        _ = ssl.SSL_shutdown(ssl_conn);
        std.log.info("Connection closed\n", .{});
    }
}
