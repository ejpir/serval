//! Header-phase policy plugin execution path.

const std = @import("std");
const assert = std.debug.assert;
const sdk = @import("serval-filter-sdk");

/// Maximum number of policy filters accepted by the execution helpers.
/// Callers must keep request and response filter slices at or below this bound.
pub const MAX_POLICY_FILTERS: usize = 64;

/// Identifies which header phase is being executed.
/// `request_headers` runs before upstream forwarding; `response_headers` runs after a response is available.
pub const PolicyPhase = enum(u8) {
    request_headers,
    response_headers,
};

/// Classifies the last policy error that was observed.
/// `.none` means no policy error has been recorded; `.rejected_by_policy` marks a filter rejection.
pub const PolicyErrorClass = enum(u8) {
    none,
    rejected_by_policy,
};

/// Tracks per-policy execution counts and the most recent error class.
/// `request_phase_invocations` and `response_phase_invocations` count filter calls by phase.
/// `rejects` and `bypasses` count terminal and skip decisions, while `last_error_class` records the latest class seen.
/// Use `init()` to construct a zeroed observation.
pub const PolicyObservation = struct {
    request_phase_invocations: u32,
    response_phase_invocations: u32,
    rejects: u32,
    bypasses: u32,
    last_error_class: PolicyErrorClass,

    /// Creates a zeroed `PolicyObservation` with no recorded invocations, rejections, or bypasses.
    /// The returned value sets `last_error_class` to `.none`.
    pub fn init() PolicyObservation {
        return .{
            .request_phase_invocations = 0,
            .response_phase_invocations = 0,
            .rejects = 0,
            .bypasses = 0,
            .last_error_class = .none,
        };
    }
};

/// Result of running a policy phase.
/// `continue_forwarding` means processing may continue, while `reject` carries the reject response to return upstream.
pub const PolicyExecutionResult = union(enum) {
    continue_forwarding,
    reject: sdk.RejectResponse,
};

/// Executes all request-header filters in order and records observation data for each decision.
/// `filter_ctx` and `observation` must be non-null pointers, and `filters.len` must not exceed `MAX_POLICY_FILTERS`.
/// A rejection stops iteration immediately; bypass decisions are counted and processing continues.
pub fn executeRequestHeaders(
    comptime Filter: type,
    filters: []Filter,
    filter_ctx: *sdk.FilterContext,
    headers: sdk.HeaderSliceView,
    observation: *PolicyObservation,
) PolicyExecutionResult {
    assert(@intFromPtr(filter_ctx) != 0);
    assert(@intFromPtr(observation) != 0);
    assert(filters.len <= MAX_POLICY_FILTERS);

    var index: usize = 0;
    while (index < filters.len) : (index += 1) {
        observation.request_phase_invocations += 1;

        const decision = filters[index].onRequestHeaders(filter_ctx, headers);
        switch (decision) {
            .continue_filtering => {},
            .bypass_plugin => {
                observation.bypasses += 1;
            },
            .reject => |rej| {
                observation.rejects += 1;
                observation.last_error_class = .rejected_by_policy;
                return .{ .reject = rej };
            },
        }
    }

    return .continue_forwarding;
}

/// Executes all response-header filters in order and records observation data for each decision.
/// `filter_ctx` and `observation` must be non-null pointers, and `filters.len` must not exceed `MAX_POLICY_FILTERS`.
/// A rejection stops iteration immediately; bypass decisions are counted and processing continues.
pub fn executeResponseHeaders(
    comptime Filter: type,
    filters: []Filter,
    filter_ctx: *sdk.FilterContext,
    headers: sdk.HeaderSliceView,
    observation: *PolicyObservation,
) PolicyExecutionResult {
    assert(@intFromPtr(filter_ctx) != 0);
    assert(@intFromPtr(observation) != 0);
    assert(filters.len <= MAX_POLICY_FILTERS);

    var index: usize = 0;
    while (index < filters.len) : (index += 1) {
        observation.response_phase_invocations += 1;

        const decision = filters[index].onResponseHeaders(filter_ctx, headers);
        switch (decision) {
            .continue_filtering => {},
            .bypass_plugin => {
                observation.bypasses += 1;
            },
            .reject => |rej| {
                observation.rejects += 1;
                observation.last_error_class = .rejected_by_policy;
                return .{ .reject = rej };
            },
        }
    }

    return .continue_forwarding;
}

/// Executes request-header filters first, then response-header filters if no request filter rejects.
/// Both filter slices must contain at most `MAX_POLICY_FILTERS` entries.
/// Returns the first rejection immediately and leaves `observation` updated with the work that ran.
pub fn executeHeaderPhases(
    comptime Filter: type,
    request_filters: []Filter,
    response_filters: []Filter,
    filter_ctx: *sdk.FilterContext,
    request_headers: sdk.HeaderSliceView,
    response_headers: sdk.HeaderSliceView,
    observation: *PolicyObservation,
) PolicyExecutionResult {
    assert(request_filters.len <= MAX_POLICY_FILTERS);
    assert(response_filters.len <= MAX_POLICY_FILTERS);

    const request_result = executeRequestHeaders(Filter, request_filters, filter_ctx, request_headers, observation);
    switch (request_result) {
        .continue_forwarding => {},
        .reject => |rej| return .{ .reject = rej },
    }

    return executeResponseHeaders(Filter, response_filters, filter_ctx, response_headers, observation);
}

test "request header reject short-circuits response phase" {
    const Filter = struct {
        reject_request: bool,

        /// Handles request headers and rejects only when this filter is configured to do so.
        /// `ctx` and `headers` are currently ignored by this implementation.
        /// Returns a 403 `blocked` rejection when `self.reject_request` is set; otherwise continues filtering.
        pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = ctx;
            _ = headers;
            return if (self.reject_request)
                .{ .reject = .{ .status = 403, .reason = "blocked" } }
            else
                .continue_filtering;
        }

        /// Handles response headers for a policy filter that does not alter the stream.
        /// The `self`, `ctx`, and `headers` arguments are ignored.
        /// Always returns `.continue_filtering` so later filters may still run.
        pub fn onResponseHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = self;
            _ = ctx;
            _ = headers;
            return .continue_filtering;
        }
    };

    var filters = [_]Filter{.{ .reject_request = true }};
    var observation = PolicyObservation.init();
    var ctx = sdk.FilterContext{
        .route_id = "route-a",
        .chain_id = "chain-a",
        .plugin_id = "plugin-a",
        .request_id = 1,
        .stream_id = 1,
    };

    const result = executeHeaderPhases(
        Filter,
        filters[0..],
        filters[0..],
        &ctx,
        .{ .headers = &[_]@import("serval-core").Header{} },
        .{ .headers = &[_]@import("serval-core").Header{} },
        &observation,
    );

    switch (result) {
        .continue_forwarding => return error.TestExpectedEqual,
        .reject => |rej| {
            try std.testing.expectEqual(@as(u16, 403), rej.status);
        },
    }

    try std.testing.expectEqual(@as(u32, 1), observation.request_phase_invocations);
    try std.testing.expectEqual(@as(u32, 0), observation.response_phase_invocations);
}

test "policy execution tracks bypass and continue decisions" {
    const Filter = struct {
        /// Handles request headers for a policy filter that does not alter the stream.
        /// The `self`, `ctx`, and `headers` arguments are ignored.
        /// Always returns `.bypass_plugin`, which skips further work in the current plugin chain.
        pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = self;
            _ = ctx;
            _ = headers;
            return .bypass_plugin;
        }

        /// Handles response headers for a policy filter that does not alter the stream.
        /// The `self`, `ctx`, and `headers` arguments are ignored.
        /// Always returns `.continue_filtering` so later filters may still run.
        pub fn onResponseHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = self;
            _ = ctx;
            _ = headers;
            return .continue_filtering;
        }
    };

    var filters = [_]Filter{.{}};
    var observation = PolicyObservation.init();
    var ctx = sdk.FilterContext{
        .route_id = "route-a",
        .chain_id = "chain-a",
        .plugin_id = "plugin-a",
        .request_id = 1,
        .stream_id = 1,
    };

    const result = executeHeaderPhases(
        Filter,
        filters[0..],
        filters[0..],
        &ctx,
        .{ .headers = &[_]@import("serval-core").Header{} },
        .{ .headers = &[_]@import("serval-core").Header{} },
        &observation,
    );

    switch (result) {
        .continue_forwarding => {},
        .reject => return error.TestExpectedEqual,
    }

    try std.testing.expectEqual(@as(u32, 1), observation.request_phase_invocations);
    try std.testing.expectEqual(@as(u32, 1), observation.response_phase_invocations);
    try std.testing.expectEqual(@as(u32, 1), observation.bypasses);
    try std.testing.expectEqual(PolicyErrorClass.none, observation.last_error_class);
}
