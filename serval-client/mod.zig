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

// HTTP/2 client primitives
pub const h2 = @import("h2/mod.zig");
pub const H2SessionState = h2.SessionState;
pub const H2SessionError = h2.SessionError;
pub const H2Runtime = h2.Runtime;
pub const H2RuntimeError = h2.RuntimeError;
pub const H2ReceiveAction = h2.ReceiveAction;
pub const H2RequestHeadersWrite = h2.RequestHeadersWrite;
pub const H2ClientConnection = h2.ClientConnection;
pub const H2ConnectionError = h2.ConnectionError;

pub const h2_upstream_pool = @import("h2/upstream_pool.zig");
pub const H2UpstreamSession = h2_upstream_pool.UpstreamSession;
pub const H2UpstreamSessionPool = h2_upstream_pool.UpstreamSessionPool;
pub const H2UpstreamSessionError = h2_upstream_pool.Error;
pub const H2UpstreamConnectStats = h2_upstream_pool.ConnectStats;
pub const H2UpstreamAcquireResult = h2_upstream_pool.AcquireResult;

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

// Body reading
pub const body = @import("body.zig");
pub const BodyReader = body.BodyReader;
pub const BodyError = body.BodyError;

test {
    _ = @import("client.zig");
    _ = @import("h2/mod.zig");
    _ = @import("h2/upstream_pool.zig");
    _ = @import("request.zig");
    _ = @import("response.zig");
    _ = @import("body.zig");
}
