//! Cross-component integration tests for serval-reverseproxy runtime flows.

const std = @import("std");
const testing = std.testing;
const core = @import("serval-core");
const sdk = @import("serval-filter-sdk");
const ir = @import("ir.zig");
const dsl = @import("dsl.zig");
const policy = @import("policy.zig");
const filter_runtime = @import("filter_runtime.zig");
const request_stream = @import("stream_request.zig");
const response_stream = @import("stream_response.zig");
const orchestrator_mod = @import("orchestrator.zig");
const failure = @import("failure.zig");
const guard_window = @import("guard_window.zig");

const MAX_DIAGNOSTICS: u32 = ir.MAX_VALIDATION_DIAGNOSTICS;

const IntegrationFilter = struct {
    request_headers_calls: u32 = 0,
    request_chunk_calls: u32 = 0,
    request_end_calls: u32 = 0,
    response_headers_calls: u32 = 0,
    response_chunk_calls: u32 = 0,
    response_end_calls: u32 = 0,

    /// Handles request headers by counting the callback.
    /// The `ctx` and `headers` parameters are accepted for interface compatibility and are not modified.
    /// Always returns `.continue_filtering`.
    pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
        _ = ctx;
        _ = headers;
        self.request_headers_calls += 1;
        return .continue_filtering;
    }

    /// Handles a request body chunk by counting the callback and forwarding the chunk bytes to `emit`.
    /// Returns `.continue_filtering` after a successful write.
    /// If emitting fails, rejects the request with HTTP 500 and reason `"emit request"`.
    pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        _ = ctx;
        self.request_chunk_calls += 1;
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "emit request" } };
        return .continue_filtering;
    }

    /// Records that the request stream has ended.
    /// `ctx` and `emit` are accepted for callback compatibility and are not used here.
    /// Always returns `.continue_filtering`.
    pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        _ = ctx;
        _ = emit;
        self.request_end_calls += 1;
        return .continue_filtering;
    }

    /// Handles response headers by counting the callback.
    /// The `ctx` and `headers` parameters are accepted for interface compatibility and are not modified.
    /// Always returns `.continue_filtering`.
    pub fn onResponseHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
        _ = ctx;
        _ = headers;
        self.response_headers_calls += 1;
        return .continue_filtering;
    }

    /// Handles a response body chunk by counting the callback and forwarding the chunk bytes to `emit`.
    /// Returns `.continue_filtering` after a successful write.
    /// If emitting fails, rejects the response with HTTP 500 and reason `"emit response"`.
    pub fn onResponseChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        _ = ctx;
        self.response_chunk_calls += 1;
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "emit response" } };
        return .continue_filtering;
    }

    /// Records that the response stream has ended.
    /// `ctx` and `emit` are accepted for callback compatibility and are not used here.
    /// Always returns `.continue_filtering`.
    pub fn onResponseEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        _ = ctx;
        _ = emit;
        self.response_end_calls += 1;
        return .continue_filtering;
    }
};

const CountingSink = struct {
    bytes: u64 = 0,

    fn write(ctx: *anyopaque, out: []const u8) sdk.EmitError!void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.bytes += out.len;
    }
};

const AlwaysWritable = struct {
    fn wait(ctx: *anyopaque, timeout_ns: u64) bool {
        _ = ctx;
        _ = timeout_ns;
        return true;
    }
};

fn validateCandidate(candidate: *const ir.CanonicalIr) !void {
    var diagnostics: [MAX_DIAGNOSTICS]ir.ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;
    try ir.validateCanonicalIr(candidate, &diagnostics, &diagnostics_count);
    try testing.expectEqual(@as(u32, 0), diagnostics_count);
}

test "integration: reverseproxy dsl admission plus policy and streaming lifecycle" {
    const source =
        \\listener l1 0.0.0.0:443
        \\pool pool-1
        \\plugin plugin-1 fail_policy=fail_closed mandatory=true
        \\chain chain-1 plugin=plugin-1
        \\route route-1 listener=l1 host=example.com path=/api pool=pool-1 chain=chain-1
    ;

    const parsed = try dsl.parse(source);
    var candidate = parsed.toCanonicalIr();
    try validateCandidate(&candidate);

    var orchestrator = orchestrator_mod.Orchestrator.init(1_000_000);
    var snapshot = orchestrator_mod.RuntimeSnapshot.fromCanonicalIr(&candidate, 1, 100);
    try orchestrator.admitAndActivate(&candidate, &snapshot, 110);

    var filter_ctx = sdk.FilterContext{
        .route_id = "route-1",
        .chain_id = "chain-1",
        .plugin_id = "plugin-1",
        .request_id = 77,
        .stream_id = 9,
    };

    var filter = IntegrationFilter{};
    var phase_filters = [_]IntegrationFilter{filter};
    var policy_obs = policy.PolicyObservation.init();

    const header_result = policy.executeHeaderPhases(
        IntegrationFilter,
        phase_filters[0..],
        phase_filters[0..],
        &filter_ctx,
        .{ .headers = &[_]core.Header{} },
        .{ .headers = &[_]core.Header{} },
        &policy_obs,
    );
    switch (header_result) {
        .continue_forwarding => {},
        .reject => return error.TestExpectedEqual,
    }

    var sink = CountingSink{};
    var emit = sdk.EmitWriter.init(&sink, CountingSink.write, 64);
    var request_obs = request_stream.StreamObservation.init();
    const request_chunks = [_][]const u8{ "abc", "def" };
    const request_decision = try request_stream.executeRequestStream(
        IntegrationFilter,
        &filter,
        &filter_ctx,
        .{ .headers = &[_]core.Header{} },
        request_chunks[0..],
        &emit,
        .{ .ctx = &sink, .wait_writable_fn = AlwaysWritable.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
        &request_obs,
    );
    switch (request_decision) {
        .continue_filtering => {},
        .reject, .bypass_plugin => return error.TestExpectedEqual,
    }

    var response_obs = response_stream.ResponseObservation.init();
    const response_chunks = [_][]const u8{"ghi"};
    const response_decision = try response_stream.executeResponseStream(
        IntegrationFilter,
        &filter,
        &filter_ctx,
        .{ .headers = &[_]core.Header{} },
        response_chunks[0..],
        &emit,
        .{ .ctx = &sink, .wait_writable_fn = AlwaysWritable.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
        &response_obs,
    );
    switch (response_decision) {
        .continue_filtering => {},
        .reject, .bypass_plugin => return error.TestExpectedEqual,
    }

    const framing = response_stream.planResponseFraming(.h1, true, false);
    try testing.expectEqual(response_stream.ResponseFramingPlan.h1_chunked, framing);
    try testing.expect(!response_stream.shouldEmitContentLength(framing));

    try testing.expectEqual(@as(u32, 1), policy_obs.request_phase_invocations);
    try testing.expectEqual(@as(u32, 1), policy_obs.response_phase_invocations);
    try testing.expectEqual(@as(u64, 9), sink.bytes);
    try testing.expectEqual(@as(u32, 1), request_obs.request_headers_calls);
    try testing.expectEqual(@as(u32, 2), request_obs.request_chunk_calls);
    try testing.expectEqual(@as(u32, 1), response_obs.response_chunk_calls);
}

test "integration: reverseproxy loads custom filter and executes all hooks" {
    const source =
        \\listener l1 0.0.0.0:443
        \\pool pool-1
        \\plugin plugin-1 fail_policy=fail_closed
        \\chain chain-1 plugin=plugin-1
        \\route route-1 listener=l1 host=example.com path=/ pool=pool-1 chain=chain-1
    ;

    const LoadedFilter = struct {
        req_headers: u32 = 0,
        req_chunks: u32 = 0,
        req_end: u32 = 0,
        res_headers: u32 = 0,
        res_chunks: u32 = 0,
        res_end: u32 = 0,

        /// Handles request headers by counting the callback and incrementing the `req_headers` counter in `ctx`.
        /// The `headers` view is observed for interface compatibility but not modified.
        /// Always returns `.continue_filtering`.
        pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = headers;
            self.req_headers += 1;
            ctx.incrementCounter("req_headers", 1);
            return .continue_filtering;
        }

        /// Handles a request body chunk by counting the callback and forwarding the chunk bytes to `emit`.
        /// Returns `.continue_filtering` after a successful write.
        /// If emitting fails, rejects the request with HTTP 500 and reason `"request emit"`.
        pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            self.req_chunks += 1;
            emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "request emit" } };
            return .continue_filtering;
        }

        /// Records that the request has ended.
        ///
        /// `ctx` and `emit` are not used by this hook.
        /// Returns `.continue_filtering` after incrementing the request-end counter.
        pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            _ = emit;
            self.req_end += 1;
            return .continue_filtering;
        }

        /// Records that response headers have been seen.
        ///
        /// `headers` are not inspected by this hook.
        /// Sets the filter-context tag `phase=response` and then returns `.continue_filtering`.
        pub fn onResponseHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = headers;
            self.res_headers += 1;
            ctx.setTag("phase", "response");
            return .continue_filtering;
        }

        /// Records a response body chunk and forwards its bytes to `emit`.
        ///
        /// `ctx` is not used by this hook. `chunk.bytes` must remain valid for the duration of the call.
        /// If `emit.emit` fails, returns `.reject` with status `500` and reason `"response emit"`; otherwise returns `.continue_filtering`.
        pub fn onResponseChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            self.res_chunks += 1;
            emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "response emit" } };
            return .continue_filtering;
        }

        /// Records that the response has ended.
        ///
        /// `ctx` and `emit` are not used by this hook.
        /// Returns `.continue_filtering` after incrementing the response-end counter.
        pub fn onResponseEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            _ = emit;
            self.res_end += 1;
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

        fn incrCounter(ctx: *anyopaque, key: []const u8, delta: u64) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = key;
            _ = delta;
            self.counters += 1;
        }
    };

    const parsed = try dsl.parse(source);
    const candidate = parsed.toCanonicalIr();

    var registry = filter_runtime.FilterRegistry.init();
    var loaded = LoadedFilter{};
    try registry.registerTyped("plugin-1", &loaded, LoadedFilter);

    var observe = Observe{};
    var filter_ctx = sdk.FilterContext{
        .route_id = "route-1",
        .chain_id = "chain-1",
        .plugin_id = "",
        .request_id = 11,
        .stream_id = 1,
        .set_tag_fn = Observe.setTag,
        .incr_counter_fn = Observe.incrCounter,
        .observe_ctx = &observe,
    };

    var request_header_storage: [core.config.MAX_HEADERS]core.Header = undefined;
    var response_header_storage: [core.config.MAX_HEADERS]core.Header = undefined;
    var request_header_count: u32 = 0;
    var response_header_count: u32 = 0;
    var request_headers = sdk.HeaderWriteView.init(request_header_storage[0..], &request_header_count);
    var response_headers = sdk.HeaderWriteView.init(response_header_storage[0..], &response_header_count);

    var sink = CountingSink{};
    var emit = sdk.EmitWriter.init(&sink, CountingSink.write, 64);
    var hooks_obs = filter_runtime.HookObservation.init();

    const decision = try registry.executeRouteHooks(
        &candidate,
        "route-1",
        &filter_ctx,
        &request_headers,
        &response_headers,
        &[_][]const u8{ "abc", "def" },
        &[_][]const u8{"ghi"},
        &emit,
        .{ .ctx = &sink, .wait_writable_fn = AlwaysWritable.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
        &hooks_obs,
    );
    switch (decision) {
        .continue_filtering => {},
        .reject, .bypass_plugin => return error.TestExpectedEqual,
    }

    try testing.expectEqual(@as(u32, 1), loaded.req_headers);
    try testing.expectEqual(@as(u32, 2), loaded.req_chunks);
    try testing.expectEqual(@as(u32, 1), loaded.req_end);
    try testing.expectEqual(@as(u32, 1), loaded.res_headers);
    try testing.expectEqual(@as(u32, 1), loaded.res_chunks);
    try testing.expectEqual(@as(u32, 1), loaded.res_end);
    try testing.expectEqual(@as(u64, 9), sink.bytes);
    try testing.expectEqual(@as(u32, 1), observe.tags);
    try testing.expectEqual(@as(u32, 1), observe.counters);
    try testing.expectEqual(@as(u32, 1), hooks_obs.request_headers_calls);
    try testing.expectEqual(@as(u32, 2), hooks_obs.request_chunk_calls);
    try testing.expectEqual(@as(u32, 1), hooks_obs.response_chunk_calls);
}

test "integration: reverseproxy guard-window rollback plus failure semantics" {
    const source =
        \\listener l1 0.0.0.0:443
        \\pool pool-1
        \\plugin plugin-1 fail_policy=fail_open
        \\chain chain-1 plugin=plugin-1
        \\route route-1 listener=l1 host=example.com path=/ pool=pool-1 chain=chain-1
    ;

    const parsed = try dsl.parse(source);
    var candidate = parsed.toCanonicalIr();
    try validateCandidate(&candidate);

    var orchestrator = orchestrator_mod.Orchestrator.init(1_000_000);
    var snapshot_v1 = orchestrator_mod.RuntimeSnapshot.fromCanonicalIr(&candidate, 1, 10);
    try orchestrator.admitAndActivate(&candidate, &snapshot_v1, 20);

    var snapshot_v2 = orchestrator_mod.RuntimeSnapshot.fromCanonicalIr(&candidate, 2, 30);
    try orchestrator.admitAndActivate(&candidate, &snapshot_v2, 40);

    var monitor = guard_window.GuardWindowMonitor.init(
        &orchestrator,
        .{ .guard_window_ns = 1000, .max_error_rate_milli = 10, .max_fail_closed_count = 1 },
        2,
        40,
    );

    const guard_decision = monitor.evaluate(
        .{ .request_count = 100, .error_count = 50, .fail_closed_count = 0 },
        50,
    );
    try testing.expectEqual(guard_window.GuardDecision.auto_rollback, guard_decision);

    const active = orchestrator.getActiveSnapshot().?;
    try testing.expectEqual(@as(u64, 1), active.generation_id);

    const plugin_failure = failure.classifyFailure(
        .h1,
        .request_headers,
        .plugin_error,
        .fail_open,
        false,
    );
    try testing.expectEqual(failure.TerminalAction.sticky_bypass_plugin, plugin_failure.action);
    try testing.expect(plugin_failure.sticky_bypass_active);

    const transport_failure = failure.classifyFailure(
        .h2,
        .response_body,
        .downstream_write_error,
        .fail_closed,
        true,
    );
    try testing.expectEqual(failure.TerminalAction.reset_h2_stream, transport_failure.action);
}
