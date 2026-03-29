//! Runtime-loaded filter binding and hook execution for reverseproxy chains.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const sdk = @import("serval-filter-sdk");
const ir = @import("ir.zig");
const request_stream = @import("stream_request.zig");

/// Maximum number of loaded filters the registry can store.
/// This is tied to `config.MAX_ROUTES` so the filter registry capacity tracks the configured route limit.
/// Use this constant when sizing registry-backed storage or validating plugin registration limits.
pub const MAX_LOADED_FILTERS: usize = config.MAX_ROUTES;

/// Errors returned by filter registry setup and route hook execution.
/// `TooManyLoadedFilters` and `DuplicatePluginBinding` report registry binding failures.
/// `MissingRoute`, `MissingChain`, and `MissingFilterImplementation` report lookup failures during route execution.
pub const RuntimeError = error{
    TooManyLoadedFilters,
    DuplicatePluginBinding,
    MissingRoute,
    MissingChain,
    MissingFilterImplementation,
};

/// Counts how many times each request and response hook was invoked during execution.
/// All counters start at `0` and are incremented by `executeRouteHooks` after each dispatch.
/// `init` returns a zero-initialized observation record for a fresh run.
pub const HookObservation = struct {
    request_headers_calls: u32 = 0,
    request_chunk_calls: u32 = 0,
    request_end_calls: u32 = 0,
    response_headers_calls: u32 = 0,
    response_chunk_calls: u32 = 0,
    response_end_calls: u32 = 0,

    /// Returns a zero-initialized `HookObservation`.
    /// The struct starts with all hook counters set to `0`.
    /// Use this when you need to collect per-hook invocation counts during runtime execution.
    pub fn init() HookObservation {
        return .{};
    }
};

/// Function pointers used by `FilterRegistry` to invoke filter hooks at runtime.
/// Each callback receives the stored filter state as `*anyopaque` and the current request context.
/// Use `forType` to build a table for a concrete filter type; the registry calls these hooks in chain order.
pub const FilterVTable = struct {
    on_request_headers: *const fn (state: *anyopaque, ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision,
    on_request_chunk: *const fn (state: *anyopaque, ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision,
    on_request_end: *const fn (state: *anyopaque, ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision,
    on_response_headers: *const fn (state: *anyopaque, ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision,
    on_response_chunk: *const fn (state: *anyopaque, ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision,
    on_response_end: *const fn (state: *anyopaque, ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision,

    /// Builds a `FilterVTable` for `Filter` by wiring each supported hook to the matching method.
    /// `sdk.verifyFilter(Filter)` is enforced at comptime before the table is produced.
    /// Falls back to the default no-op hook implementations when `Filter` does not declare a given hook.
    pub fn forType(comptime Filter: type) FilterVTable {
        comptime sdk.verifyFilter(Filter);

        return .{
            .on_request_headers = if (@hasDecl(Filter, "onRequestHeadersWrite")) struct {
                fn call(state: *anyopaque, ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
                    const typed: *Filter = @ptrCast(@alignCast(state));
                    return typed.onRequestHeadersWrite(ctx, headers);
                }
            }.call else if (@hasDecl(Filter, "onRequestHeaders")) struct {
                fn call(state: *anyopaque, ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
                    const typed: *Filter = @ptrCast(@alignCast(state));
                    return typed.onRequestHeaders(ctx, headers.asReadOnly());
                }
            }.call else defaultRequestHeaders,
            .on_request_chunk = if (@hasDecl(Filter, "onRequestChunk")) struct {
                fn call(state: *anyopaque, ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
                    const typed: *Filter = @ptrCast(@alignCast(state));
                    return typed.onRequestChunk(ctx, chunk, emit);
                }
            }.call else defaultRequestChunk,
            .on_request_end = if (@hasDecl(Filter, "onRequestEnd")) struct {
                fn call(state: *anyopaque, ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
                    const typed: *Filter = @ptrCast(@alignCast(state));
                    return typed.onRequestEnd(ctx, emit);
                }
            }.call else defaultRequestEnd,
            .on_response_headers = if (@hasDecl(Filter, "onResponseHeadersWrite")) struct {
                fn call(state: *anyopaque, ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
                    const typed: *Filter = @ptrCast(@alignCast(state));
                    return typed.onResponseHeadersWrite(ctx, headers);
                }
            }.call else if (@hasDecl(Filter, "onResponseHeaders")) struct {
                fn call(state: *anyopaque, ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
                    const typed: *Filter = @ptrCast(@alignCast(state));
                    return typed.onResponseHeaders(ctx, headers.asReadOnly());
                }
            }.call else defaultResponseHeaders,
            .on_response_chunk = if (@hasDecl(Filter, "onResponseChunk")) struct {
                fn call(state: *anyopaque, ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
                    const typed: *Filter = @ptrCast(@alignCast(state));
                    return typed.onResponseChunk(ctx, chunk, emit);
                }
            }.call else defaultResponseChunk,
            .on_response_end = if (@hasDecl(Filter, "onResponseEnd")) struct {
                fn call(state: *anyopaque, ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
                    const typed: *Filter = @ptrCast(@alignCast(state));
                    return typed.onResponseEnd(ctx, emit);
                }
            }.call else defaultResponseEnd,
        };
    }
};

const LoadedFilter = struct {
    plugin_id: []const u8,
    state: *anyopaque,
    vtable: FilterVTable,
};

/// Stores runtime-loaded filter bindings and dispatches route hooks through generated vtables.
/// Loaded filter pointers are borrowed; the registry does not manage their lifetime.
/// Use `init` to create an empty registry and `registerTyped` to bind plugin IDs to typed filter state.
pub const FilterRegistry = struct {
    loaded: [MAX_LOADED_FILTERS]LoadedFilter = undefined,
    loaded_count: u32 = 0,

    /// Returns an empty `FilterRegistry` with no loaded filters.
    /// The returned registry can be populated with `registerTyped` before executing routes.
    /// No allocation or external initialization is performed.
    pub fn init() FilterRegistry {
        return .{};
    }

    /// Registers a typed filter instance under `plugin_id` without taking ownership of the state pointer.
    /// `state` must be a pointer to `Filter`, and the registry stores that pointer together with the generated vtable.
    /// Returns `error.TooManyLoadedFilters` when the registry is full and `error.DuplicatePluginBinding` when the plugin is already registered.
    pub fn registerTyped(self: *FilterRegistry, plugin_id: []const u8, state: anytype, comptime Filter: type) RuntimeError!void {
        assert(@intFromPtr(self) != 0);
        assert(plugin_id.len > 0);

        const state_ptr = state;
        assert(@TypeOf(state_ptr) == *Filter);

        if (self.loaded_count >= self.loaded.len) return error.TooManyLoadedFilters;
        if (self.findLoaded(plugin_id) != null) return error.DuplicatePluginBinding;

        self.loaded[self.loaded_count] = .{
            .plugin_id = plugin_id,
            .state = state_ptr,
            .vtable = FilterVTable.forType(Filter),
        };
        self.loaded_count += 1;
    }

    /// Executes the loaded filter chain for the resolved route and returns the final decision.
    /// Looks up the route and chain by ID, then runs each registered plugin in chain order.
    /// Propagates `RuntimeError` and stream backpressure errors; returns `.reject` immediately if any hook rejects.
    pub fn executeRouteHooks(
        self: *FilterRegistry,
        candidate: *const ir.CanonicalIr,
        route_id: []const u8,
        filter_ctx: *sdk.FilterContext,
        request_headers: *sdk.HeaderWriteView,
        response_headers: *sdk.HeaderWriteView,
        request_chunks: []const []const u8,
        response_chunks: []const []const u8,
        emit: *sdk.EmitWriter,
        backpressure: request_stream.BackpressureController,
        observation: *HookObservation,
    ) (RuntimeError || request_stream.StreamError)!sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(candidate) != 0);
        assert(route_id.len > 0);
        assert(@intFromPtr(filter_ctx) != 0);
        assert(@intFromPtr(request_headers) != 0);
        assert(@intFromPtr(response_headers) != 0);
        assert(@intFromPtr(emit) != 0);
        assert(@intFromPtr(observation) != 0);

        const route = findRoute(candidate.routes, route_id) orelse return error.MissingRoute;
        const chain = findChain(candidate.chains, route.chain_id) orelse return error.MissingChain;

        var entry_index: usize = 0;
        while (entry_index < chain.entries.len) : (entry_index += 1) {
            const entry = chain.entries[entry_index];
            const loaded = self.findLoaded(entry.plugin_id) orelse return error.MissingFilterImplementation;
            filter_ctx.plugin_id = entry.plugin_id;

            const req_headers_decision = loaded.vtable.on_request_headers(loaded.state, filter_ctx, request_headers.*);
            observation.request_headers_calls += 1;
            switch (req_headers_decision) {
                .continue_filtering, .bypass_plugin => {},
                .reject => |rej| return .{ .reject = rej },
            }

            var req_chunk_index: usize = 0;
            while (req_chunk_index < request_chunks.len) : (req_chunk_index += 1) {
                try backpressure.waitWritable();
                const is_last = req_chunk_index + 1 == request_chunks.len;
                const req_chunk = sdk.ChunkView{ .bytes = request_chunks[req_chunk_index], .is_last = is_last };
                const req_decision = loaded.vtable.on_request_chunk(loaded.state, filter_ctx, req_chunk, emit);
                observation.request_chunk_calls += 1;
                switch (req_decision) {
                    .continue_filtering, .bypass_plugin => {},
                    .reject => |rej| return .{ .reject = rej },
                }
            }

            try backpressure.waitWritable();
            const req_end_decision = loaded.vtable.on_request_end(loaded.state, filter_ctx, emit);
            observation.request_end_calls += 1;
            switch (req_end_decision) {
                .continue_filtering, .bypass_plugin => {},
                .reject => |rej| return .{ .reject = rej },
            }

            const res_headers_decision = loaded.vtable.on_response_headers(loaded.state, filter_ctx, response_headers.*);
            observation.response_headers_calls += 1;
            switch (res_headers_decision) {
                .continue_filtering, .bypass_plugin => {},
                .reject => |rej| return .{ .reject = rej },
            }

            var res_chunk_index: usize = 0;
            while (res_chunk_index < response_chunks.len) : (res_chunk_index += 1) {
                try backpressure.waitWritable();
                const is_last_res = res_chunk_index + 1 == response_chunks.len;
                const res_chunk = sdk.ChunkView{ .bytes = response_chunks[res_chunk_index], .is_last = is_last_res };
                const res_decision = loaded.vtable.on_response_chunk(loaded.state, filter_ctx, res_chunk, emit);
                observation.response_chunk_calls += 1;
                switch (res_decision) {
                    .continue_filtering, .bypass_plugin => {},
                    .reject => |rej| return .{ .reject = rej },
                }
            }

            try backpressure.waitWritable();
            const res_end_decision = loaded.vtable.on_response_end(loaded.state, filter_ctx, emit);
            observation.response_end_calls += 1;
            switch (res_end_decision) {
                .continue_filtering, .bypass_plugin => {},
                .reject => |rej| return .{ .reject = rej },
            }
        }

        return .continue_filtering;
    }

    fn findLoaded(self: *const FilterRegistry, plugin_id: []const u8) ?LoadedFilter {
        assert(plugin_id.len > 0);

        var index: usize = 0;
        while (index < self.loaded_count) : (index += 1) {
            if (std.mem.eql(u8, self.loaded[index].plugin_id, plugin_id)) return self.loaded[index];
        }
        return null;
    }
};

fn findRoute(routes: []const ir.Route, route_id: []const u8) ?ir.Route {
    assert(route_id.len > 0);

    var index: usize = 0;
    while (index < routes.len) : (index += 1) {
        if (std.mem.eql(u8, routes[index].id, route_id)) return routes[index];
    }
    return null;
}

fn findChain(chains: []const ir.ChainPlan, chain_id: []const u8) ?ir.ChainPlan {
    assert(chain_id.len > 0);

    var index: usize = 0;
    while (index < chains.len) : (index += 1) {
        if (std.mem.eql(u8, chains[index].id, chain_id)) return chains[index];
    }
    return null;
}

fn defaultRequestHeaders(state: *anyopaque, ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
    _ = state;
    _ = ctx;
    _ = headers;
    return .continue_filtering;
}

fn defaultRequestChunk(state: *anyopaque, ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
    _ = state;
    _ = ctx;
    _ = chunk;
    _ = emit;
    return .continue_filtering;
}

fn defaultRequestEnd(state: *anyopaque, ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
    _ = state;
    _ = ctx;
    _ = emit;
    return .continue_filtering;
}

fn defaultResponseHeaders(state: *anyopaque, ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
    _ = state;
    _ = ctx;
    _ = headers;
    return .continue_filtering;
}

fn defaultResponseChunk(state: *anyopaque, ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
    _ = state;
    _ = ctx;
    _ = chunk;
    _ = emit;
    return .continue_filtering;
}

fn defaultResponseEnd(state: *anyopaque, ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
    _ = state;
    _ = ctx;
    _ = emit;
    return .continue_filtering;
}

test "filter runtime executes loaded custom filter hooks across lifecycle" {
    const TestFilter = struct {
        request_headers_calls: u32 = 0,
        request_chunk_calls: u32 = 0,
        request_end_calls: u32 = 0,
        response_headers_calls: u32 = 0,
        response_chunk_calls: u32 = 0,
        response_end_calls: u32 = 0,

        /// Records that request headers were observed for this filter instance.
        /// `headers` is accepted for the hook contract but is not used here.
        /// Increments the `request_headers` counter on `ctx` and then returns `.continue_filtering`.
        pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = headers;
            self.request_headers_calls += 1;
            ctx.incrementCounter("request_headers", 1);
            return .continue_filtering;
        }

        /// Records a request chunk hook invocation and forwards the chunk bytes to `emit`.
        /// `ctx` is accepted for the hook contract but is not used here.
        /// If emission fails, returns a reject decision with status `500` and reason `"req emit"`; otherwise continues filtering.
        pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            self.request_chunk_calls += 1;
            emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "req emit" } };
            return .continue_filtering;
        }

        /// Records that request end was observed for this filter instance.
        /// `ctx` and `emit` are accepted for the hook contract but are not used here.
        /// Always returns `.continue_filtering` after incrementing `request_end_calls`.
        pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            _ = emit;
            self.request_end_calls += 1;
            return .continue_filtering;
        }

        /// Records that response headers were observed for this filter instance.
        /// `headers` is accepted for the hook contract but is not used here.
        /// Sets the `phase` tag to `"response_headers"` on `ctx` and then returns `.continue_filtering`.
        pub fn onResponseHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = headers;
            self.response_headers_calls += 1;
            ctx.setTag("phase", "response_headers");
            return .continue_filtering;
        }

        /// Records a response chunk hook invocation and forwards the chunk bytes to `emit`.
        /// `ctx` is accepted for the hook contract but is not used here.
        /// If emission fails, returns a reject decision with status `500` and reason `"res emit"`; otherwise continues filtering.
        pub fn onResponseChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            self.response_chunk_calls += 1;
            emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "res emit" } };
            return .continue_filtering;
        }

        /// Records that response end was observed for this filter instance.
        /// `ctx` and `emit` are accepted for the hook contract but are not used here.
        /// Always returns `.continue_filtering` after incrementing `response_end_calls`.
        pub fn onResponseEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            _ = emit;
            self.response_end_calls += 1;
            return .continue_filtering;
        }
    };

    const Observe = struct {
        tags: u32 = 0,
        counters: u32 = 0,

        fn setTag(ctx: *anyopaque, key: []const u8, value: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = key;
            _ = value;
            self.tags += 1;
        }

        fn incr(ctx: *anyopaque, key: []const u8, delta: u64) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = key;
            _ = delta;
            self.counters += 1;
        }
    };

    const Sink = struct {
        bytes: u64 = 0,

        fn write(ctx: *anyopaque, bytes: []const u8) sdk.EmitError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.bytes += bytes.len;
        }
    };

    const Wait = struct {
        fn wait(ctx: *anyopaque, timeout_ns: u64) bool {
            _ = ctx;
            _ = timeout_ns;
            return true;
        }
    };

    const source =
        \\listener l1 0.0.0.0:443
        \\pool p1
        \\plugin plugin-a fail_policy=fail_closed
        \\chain c1 plugin=plugin-a
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const parsed = try @import("dsl.zig").parse(source);
    const candidate = parsed.toCanonicalIr();

    var registry = FilterRegistry.init();
    var filter = TestFilter{};
    try registry.registerTyped("plugin-a", &filter, TestFilter);

    var observe = Observe{};
    var filter_ctx = sdk.FilterContext{
        .route_id = "r1",
        .chain_id = "c1",
        .plugin_id = "",
        .request_id = 7,
        .stream_id = 3,
        .set_tag_fn = Observe.setTag,
        .incr_counter_fn = Observe.incr,
        .observe_ctx = &observe,
    };

    var request_header_storage: [@import("serval-core").config.MAX_HEADERS]@import("serval-core").Header = undefined;
    var response_header_storage: [@import("serval-core").config.MAX_HEADERS]@import("serval-core").Header = undefined;
    var request_header_count: u32 = 0;
    var response_header_count: u32 = 0;
    var request_headers = sdk.HeaderWriteView.init(request_header_storage[0..], &request_header_count);
    var response_headers = sdk.HeaderWriteView.init(response_header_storage[0..], &response_header_count);

    var sink = Sink{};
    var emit = sdk.EmitWriter.init(&sink, Sink.write, 64);
    var hook_obs = HookObservation.init();

    const decision = try registry.executeRouteHooks(
        &candidate,
        "r1",
        &filter_ctx,
        &request_headers,
        &response_headers,
        &[_][]const u8{ "ab", "cd" },
        &[_][]const u8{"ef"},
        &emit,
        .{ .ctx = &sink, .wait_writable_fn = Wait.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
        &hook_obs,
    );

    switch (decision) {
        .continue_filtering => {},
        .reject, .bypass_plugin => return error.TestExpectedEqual,
    }

    try std.testing.expectEqual(@as(u32, 1), filter.request_headers_calls);
    try std.testing.expectEqual(@as(u32, 2), filter.request_chunk_calls);
    try std.testing.expectEqual(@as(u32, 1), filter.request_end_calls);
    try std.testing.expectEqual(@as(u32, 1), filter.response_headers_calls);
    try std.testing.expectEqual(@as(u32, 1), filter.response_chunk_calls);
    try std.testing.expectEqual(@as(u32, 1), filter.response_end_calls);
    try std.testing.expectEqual(@as(u64, 6), sink.bytes);
    try std.testing.expectEqual(@as(u32, 1), observe.tags);
    try std.testing.expectEqual(@as(u32, 1), observe.counters);
    try std.testing.expectEqual(@as(u32, 1), hook_obs.request_headers_calls);
    try std.testing.expectEqual(@as(u32, 2), hook_obs.request_chunk_calls);
    try std.testing.expectEqual(@as(u32, 1), hook_obs.response_chunk_calls);
}
