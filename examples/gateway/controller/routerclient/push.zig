//! Router Client Push Logic
//!
//! Multi-endpoint push and endpoint tracking for RouterClient.
//!
//! TigerStyle: Bounded loops, explicit tracking, ~2 assertions per function.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const mod = @import("mod.zig");
const RouterClientError = mod.RouterClientError;
const MAX_JSON_SIZE_BYTES = mod.MAX_JSON_SIZE_BYTES;
const PushResult = @import("types.zig").PushResult;

const k8s_client_mod = @import("../../k8s_client/mod.zig");
const RouterEndpoint = k8s_client_mod.RouterEndpoint;
const RouterEndpoints = k8s_client_mod.RouterEndpoints;
const MAX_ROUTER_ENDPOINTS = k8s_client_mod.MAX_ROUTER_ENDPOINTS;
const MAX_POD_NAME_LEN = k8s_client_mod.MAX_POD_NAME_LEN;

// ============================================================================
// Endpoint Tracking Functions
// ============================================================================

/// Check if pod names in new endpoints differ from current endpoints.
///
/// Returns true if any pod name changed, even if IPs are the same.
/// TigerStyle S3: Bounded loops.
pub fn havePodNamesChanged(
    current_endpoints: *const RouterEndpoints,
    new_endpoints: *const RouterEndpoints,
) bool {
    // Different count means changed
    if (new_endpoints.count != current_endpoints.count) {
        return true;
    }

    // Check each new endpoint's pod name exists in current list
    var new_idx: u8 = 0;
    while (new_idx < new_endpoints.count) : (new_idx += 1) {
        const new_ep = &new_endpoints.endpoints[new_idx];
        const new_pod = new_ep.getPodName();
        if (new_pod.len == 0) continue; // Skip if pod name unknown

        var found = false;
        var cur_idx: u8 = 0;
        while (cur_idx < current_endpoints.count) : (cur_idx += 1) {
            const cur_ep = &current_endpoints.endpoints[cur_idx];
            if (std.mem.eql(u8, new_pod, cur_ep.getPodName())) {
                found = true;
                break;
            }
        }
        if (!found) {
            return true;
        }
    }

    return false;
}

/// Check if an endpoint pod name is in the synced list.
///
/// TigerStyle S3: Bounded loop.
pub fn isEndpointSynced(
    synced_pod_names: *const [MAX_ROUTER_ENDPOINTS][MAX_POD_NAME_LEN]u8,
    synced_pod_name_lens: *const [MAX_ROUTER_ENDPOINTS]u8,
    synced_endpoint_count: u8,
    pod_name: []const u8,
) bool {
    if (pod_name.len == 0) return false; // Unknown pod name, treat as not synced

    var idx: u8 = 0;
    while (idx < synced_endpoint_count) : (idx += 1) {
        const synced_len = synced_pod_name_lens[idx];
        if (synced_len == pod_name.len) {
            if (std.mem.eql(u8, synced_pod_names[idx][0..synced_len], pod_name)) {
                return true;
            }
        }
    }
    return false;
}

/// Add an endpoint pod name to the synced list.
///
/// TigerStyle S1: Precondition - pod name fits in buffer.
pub fn addSyncedEndpoint(
    synced_pod_names: *[MAX_ROUTER_ENDPOINTS][MAX_POD_NAME_LEN]u8,
    synced_pod_name_lens: *[MAX_ROUTER_ENDPOINTS]u8,
    synced_endpoint_count: *u8,
    pod_name: []const u8,
) void {
    if (pod_name.len == 0) return; // Skip unknown pod names

    assert(pod_name.len <= MAX_POD_NAME_LEN); // S1: precondition

    if (synced_endpoint_count.* >= MAX_ROUTER_ENDPOINTS) {
        std.log.warn("router_client: synced endpoint list full, cannot add {s}", .{pod_name});
        return;
    }

    const idx = synced_endpoint_count.*;
    @memcpy(synced_pod_names[idx][0..pod_name.len], pod_name);
    synced_pod_name_lens[idx] = @intCast(pod_name.len);
    synced_endpoint_count.* += 1;
}

/// Clear the synced endpoint list.
///
/// Call this when config changes to ensure all endpoints get the new config.
pub fn clearSyncedEndpoints(
    synced_pod_name_lens: *[MAX_ROUTER_ENDPOINTS]u8,
    synced_endpoint_count: *u8,
) void {
    synced_endpoint_count.* = 0;
    synced_pod_name_lens.* = std.mem.zeroes([MAX_ROUTER_ENDPOINTS]u8);
}

/// Prune stale entries from synced list.
///
/// Removes pod names that are no longer in the current endpoint list.
/// Call this after refreshing endpoints to prevent stale tracking.
///
/// TigerStyle S3: Bounded loops.
pub fn pruneStaleSyncedEndpoints(
    synced_pod_names: *[MAX_ROUTER_ENDPOINTS][MAX_POD_NAME_LEN]u8,
    synced_pod_name_lens: *[MAX_ROUTER_ENDPOINTS]u8,
    synced_endpoint_count: *u8,
    router_endpoints: *const RouterEndpoints,
) void {
    // Build new synced list containing only pods still in current endpoints
    var new_synced_names: [MAX_ROUTER_ENDPOINTS][MAX_POD_NAME_LEN]u8 = undefined;
    var new_synced_lens: [MAX_ROUTER_ENDPOINTS]u8 = std.mem.zeroes([MAX_ROUTER_ENDPOINTS]u8);
    var new_count: u8 = 0;

    // S3: Bounded loop over synced list
    var synced_idx: u8 = 0;
    while (synced_idx < synced_endpoint_count.*) : (synced_idx += 1) {
        const synced_len = synced_pod_name_lens[synced_idx];
        if (synced_len == 0) continue;

        const synced_name = synced_pod_names[synced_idx][0..synced_len];

        // Check if this pod is still in current endpoints
        var still_exists = false;
        var ep_idx: u8 = 0;
        while (ep_idx < router_endpoints.count) : (ep_idx += 1) {
            const ep = &router_endpoints.endpoints[ep_idx];
            if (std.mem.eql(u8, synced_name, ep.getPodName())) {
                still_exists = true;
                break;
            }
        }

        // Keep if still exists
        if (still_exists and new_count < MAX_ROUTER_ENDPOINTS) {
            @memcpy(new_synced_names[new_count][0..synced_len], synced_name);
            new_synced_lens[new_count] = synced_len;
            new_count += 1;
        }
    }

    // Replace synced list with pruned version
    const pruned = synced_endpoint_count.* - new_count;
    if (pruned > 0) {
        std.log.debug("router_client: pruned {d} stale endpoints from synced list", .{pruned});
    }

    synced_pod_names.* = new_synced_names;
    synced_pod_name_lens.* = new_synced_lens;
    synced_endpoint_count.* = new_count;
}
