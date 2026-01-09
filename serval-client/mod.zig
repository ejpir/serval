// serval-client/mod.zig
//! Serval Client - HTTP/1.1 Client Library
//!
//! Zero-allocation HTTP/1.1 client for making requests to upstream servers.
//! TigerStyle: Fixed buffers, explicit sizes, bounded loops.
//!
//! Layer: 2 (Infrastructure) - alongside serval-pool, serval-prober, serval-health

// Client - unified HTTP client
pub const client = @import("client.zig");
pub const Client = client.Client;
pub const ClientError = client.ClientError;
pub const ConnectResult = client.ConnectResult;
pub const RequestResult = client.RequestResult;
pub const Connection = client.Connection;

// Request serialization
pub const request = @import("request.zig");
pub const sendRequest = request.sendRequest;
pub const buildRequestBuffer = request.buildRequestBuffer;

// Response parsing
pub const response = @import("response.zig");
pub const ResponseHeaders = response.ResponseHeaders;
pub const ResponseError = response.ResponseError;
pub const readResponseHeaders = response.readResponseHeaders;
pub const HeaderBytesResult = response.HeaderBytesResult;
pub const readHeaderBytes = response.readHeaderBytes;

test {
    _ = @import("client.zig");
    _ = @import("request.zig");
    _ = @import("response.zig");
}
