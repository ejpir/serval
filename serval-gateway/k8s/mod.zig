//! Kubernetes API Integration
//!
//! HTTP client and resource watcher for Kubernetes API.

const client_mod = @import("client.zig");
pub const Client = client_mod.Client;
pub const SA_TOKEN_PATH = client_mod.SA_TOKEN_PATH;
pub const SA_CA_PATH = client_mod.SA_CA_PATH;
pub const SA_NAMESPACE_PATH = client_mod.SA_NAMESPACE_PATH;
pub const DEFAULT_API_SERVER = client_mod.DEFAULT_API_SERVER;

const watcher_mod = @import("watcher.zig");
pub const Watcher = watcher_mod.Watcher;
pub const EventType = watcher_mod.EventType;
pub const WatchEvent = watcher_mod.WatchEvent;

test {
    @import("std").testing.refAllDecls(@This());
    _ = client_mod;
    _ = watcher_mod;
}
