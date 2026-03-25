//! Header-phase policy plugin execution path.

const std = @import("std");
const assert = std.debug.assert;
const sdk = @import("serval-filter-sdk");

pub const MAX_POLICY_FILTERS: usize = 64;

pub const PolicyPhase = enum(u8) {
    request_headers,
    response_headers,
};

pub const PolicyErrorClass = enum(u8) {
    none,
    rejected_by_policy,
};

pub const PolicyObservation = struct {
    request_phase_invocations: u32,
    response_phase_invocations: u32,
    rejects: u32,
    bypasses: u32,
    last_error_class: PolicyErrorClass,

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

pub const PolicyExecutionResult = union(enum) {
    continue_forwarding,
    reject: sdk.RejectResponse,
};

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

        pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = ctx;
            _ = headers;
            return if (self.reject_request)
                .{ .reject = .{ .status = 403, .reason = "blocked" } }
            else
                .continue_filtering;
        }

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
        pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = self;
            _ = ctx;
            _ = headers;
            return .bypass_plugin;
        }

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
