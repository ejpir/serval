// lib/serval/mod.zig
//! Serval - HTTP/1.1 Server Library
//!
//! Complete server library composing all serval modules.
//! TigerStyle: Batteries included, explicit re-exports.
//!
//! ## Facade Pattern
//!
//! This module re-exports types from sub-modules for convenient single-import usage:
//!
//! ```zig
//! const serval = @import("serval");
//! var parser = serval.Parser.init();           // Flat access
//! var parser2 = serval.http.Parser.init();     // Explicit module access
//! ```
//!
//! **Maintenance**: When adding public types to sub-modules, add re-exports here.
//! See ARCHITECTURE.md for full guidelines.

const std = @import("std");

// =============================================================================
// Core Types (from serval-core)
// =============================================================================

pub const core = @import("serval-core");

// Types
pub const types = core.types;
pub const Request = core.Request;
pub const Response = core.Response;
pub const Upstream = core.Upstream;
pub const Action = core.Action;
pub const Method = core.Method;
pub const Version = core.Version;
pub const Header = core.Header;
pub const HeaderMap = core.HeaderMap;
pub const ConnectionInfo = core.ConnectionInfo;
pub const UpstreamConnectInfo = core.UpstreamConnectInfo;

// Config
pub const config = core.config;
pub const Config = core.Config;

// Time utilities
pub const time = core.time;

// Errors
pub const errors = core.errors;
pub const ParseError = core.ParseError;
pub const ConnectionError = core.ConnectionError;
pub const UpstreamError = core.UpstreamError;
pub const RequestError = core.RequestError;
pub const ErrorContext = core.ErrorContext;
pub const LogEntry = core.LogEntry;

// Context
pub const context = core.context;
pub const Context = core.Context;
pub const BodyReader = core.BodyReader;
pub const BodyReadError = core.BodyReadError;

// Handler hook verification
pub const hooks = core.hooks;
pub const verifyHandler = core.verifyHandler;
pub const hasHook = core.hasHook;

// =============================================================================
// Network Utilities (from serval-net)
// =============================================================================

pub const net = @import("serval-net");
pub const setTcpNoDelay = net.setTcpNoDelay;

// =============================================================================
// HTTP Parsing (from serval-http)
// =============================================================================

pub const http = @import("serval-http");
pub const Parser = http.Parser;

// =============================================================================
// Connection Pooling (from serval-pool)
// =============================================================================

pub const pool = @import("serval-pool");
pub const Connection = pool.Connection;
pub const NoPool = pool.NoPool;
pub const SimplePool = pool.SimplePool;
pub const verifyPool = pool.verifyPool;

// =============================================================================
// Upstream Forwarding (from serval-proxy)
// =============================================================================

pub const proxy = @import("serval-proxy");
pub const Forwarder = proxy.Forwarder;
pub const ForwardError = proxy.ForwardError;
pub const ForwardResult = proxy.ForwardResult;

// =============================================================================
// Metrics (from serval-metrics)
// =============================================================================

pub const metrics = @import("serval-metrics");
pub const NoopMetrics = metrics.NoopMetrics;
pub const PrometheusMetrics = metrics.PrometheusMetrics;
pub const verifyMetrics = metrics.verifyMetrics;

// =============================================================================
// Tracing (from serval-tracing)
// =============================================================================

pub const tracing = @import("serval-tracing");
pub const SpanHandle = tracing.SpanHandle;
pub const NoopTracer = tracing.NoopTracer;
pub const verifyTracer = tracing.verifyTracer;

// =============================================================================
// Server (from serval-server)
// =============================================================================

pub const server = @import("serval-server");
pub const Server = server.Server;
pub const MinimalServer = server.MinimalServer;

// =============================================================================
// Tests
// =============================================================================

test {
    // Import all modules to include their tests
    _ = @import("serval-core");
    _ = @import("serval-net");
    _ = @import("serval-http");
    _ = @import("serval-pool");
    _ = @import("serval-proxy");
    _ = @import("serval-metrics");
    _ = @import("serval-tracing");
    _ = @import("serval-otel");
    _ = @import("serval-server");
}
