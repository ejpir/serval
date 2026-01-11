// examples/router/json/writer.zig
//! JSON Streaming Writer for Router Config
//!
//! Uses std.json.Stringify for direct buffer output.
//! TigerStyle: Zero allocations, streams directly to fixed buffer.

const std = @import("std");
const serval_router = @import("serval-router");

const Router = serval_router.Router;
const Route = serval_router.Route;
const Upstream = serval_router.Upstream;

/// Stream router configuration as JSON directly to buffer.
/// TigerStyle: No intermediate structs, no allocator, bounded buffer.
pub fn streamRouterConfig(router: *Router, generation: u64, buf: []u8) ![]const u8 {
    var writer = std.Io.Writer.fixed(buf);
    var w: std.json.Stringify = .{ .writer = &writer };

    try w.beginObject();

    try w.objectField("generation");
    try w.write(generation);

    try w.objectField("allowed_hosts");
    try w.beginArray();
    for (router.allowed_hosts) |host| {
        try w.write(host);
    }
    try w.endArray();

    try w.objectField("routes");
    try w.beginArray();
    for (router.routes) |route| {
        try writeRoute(&w, route);
    }
    try w.endArray();

    try w.objectField("pools");
    try w.beginArray();
    for (router.pools) |*pool| {
        try writePool(&w, pool);
    }
    try w.endArray();

    try w.endObject();

    return writer.buffered();
}

fn writeRoute(w: *std.json.Stringify, route: Route) !void {
    try w.beginObject();

    try w.objectField("name");
    try w.write(route.name);

    switch (route.matcher.path) {
        .prefix => |p| {
            try w.objectField("path_prefix");
            try w.write(p);
        },
        .exact => |e| {
            try w.objectField("path_exact");
            try w.write(e);
        },
    }

    try w.objectField("pool_idx");
    try w.write(route.pool_idx);

    try w.objectField("strip_prefix");
    try w.write(route.strip_prefix);

    if (route.matcher.host) |host| {
        try w.objectField("host");
        try w.write(host);
    }

    try w.endObject();
}

fn writePool(w: *std.json.Stringify, pool: *const Router.Pool) !void {
    try w.beginObject();

    try w.objectField("name");
    try w.write(pool.name);

    try w.objectField("upstreams");
    try w.beginArray();
    for (pool.lb_handler.upstreams) |upstream| {
        try writeUpstream(w, upstream);
    }
    try w.endArray();

    try w.endObject();
}

fn writeUpstream(w: *std.json.Stringify, upstream: Upstream) !void {
    try w.beginObject();
    try w.objectField("host");
    try w.write(upstream.host);
    try w.objectField("port");
    try w.write(upstream.port);
    try w.objectField("idx");
    try w.write(upstream.idx);
    try w.objectField("tls");
    try w.write(upstream.tls);
    try w.endObject();
}
