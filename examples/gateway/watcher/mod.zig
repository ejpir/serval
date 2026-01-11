//! Kubernetes Resource Watcher
//!
//! Watches Gateway API resources and related K8s resources for changes.
//! Parses newline-delimited JSON watch event stream from K8s watch API
//! and triggers reconciliation when resources change.
//!
//! TigerStyle: Parallel watch threads, bounded buffers, reconnection with backoff.
//! Each resource type (GatewayClass, Gateway, HTTPRoute, Service, Endpoints, Secret)
//! is watched in a separate thread to avoid blocking on long-running watch streams.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;
const Io = std.Io;

const gateway = @import("serval-k8s-gateway");
const gw_config = gateway.config;
const k8s_client_mod = @import("../k8s_client/mod.zig");
const Client = k8s_client_mod.Client;
const k8s_json = @import("../k8s_client/json_types.zig");
const Resolver = @import("../resolver/mod.zig").Resolver;

// Re-export all types from types.zig
pub const watcher_types = @import("types.zig");

// Import parsing functions from parsing.zig
const parsing = @import("parsing.zig");
pub const parseEvent = parsing.parseEvent;
pub const extractResourceMeta = parsing.extractResourceMeta;
pub const parseGatewayJson = parsing.parseGatewayJson;
pub const parseGatewayClassJson = parsing.parseGatewayClassJson;
pub const parseHTTPRouteJson = parsing.parseHTTPRouteJson;
pub const parseFilterFromJson = parsing.parseFilterFromJson;
const types = watcher_types;

// Local aliases for convenience
const WatcherError = types.WatcherError;
const EventType = types.EventType;
const WatchEvent = types.WatchEvent;
const ResourceMeta = types.ResourceMeta;
const TrackedResource = types.TrackedResource;
const ResourceStore = types.ResourceStore;
const StoredGateway = types.StoredGateway;
const StoredGatewayClass = types.StoredGatewayClass;
const StoredHTTPRoute = types.StoredHTTPRoute;
const ControllerNameStorage = types.ControllerNameStorage;
const StoredListener = types.StoredListener;
const StoredHTTPRouteRule = types.StoredHTTPRouteRule;
const StoredHTTPRouteMatch = types.StoredHTTPRouteMatch;
const StoredHTTPRouteFilter = types.StoredHTTPRouteFilter;
const StoredBackendRef = types.StoredBackendRef;
const NameStorage = types.NameStorage;
const HostnameStorage = types.HostnameStorage;
const PathStorage = types.PathStorage;
const StoredPathMatch = types.StoredPathMatch;
const StoredPathRewrite = types.StoredPathRewrite;

// Import constants
const GATEWAY_CLASS_PATH = types.GATEWAY_CLASS_PATH;
const GATEWAY_PATH = types.GATEWAY_PATH;
const HTTP_ROUTE_PATH = types.HTTP_ROUTE_PATH;
const SERVICES_PATH = types.SERVICES_PATH;
const ENDPOINTS_PATH = types.ENDPOINTS_PATH;
const SECRETS_PATH = types.SECRETS_PATH;
const MAX_LINE_SIZE_BYTES = types.MAX_LINE_SIZE_BYTES;
const MAX_EVENTS_PER_ITERATION = types.MAX_EVENTS_PER_ITERATION;
const MAX_RECONNECT_ATTEMPTS = types.MAX_RECONNECT_ATTEMPTS;
const MAX_GATEWAYS = types.MAX_GATEWAYS;
const MAX_GATEWAY_CLASSES = types.MAX_GATEWAY_CLASSES;
const MAX_HTTP_ROUTES = types.MAX_HTTP_ROUTES;
const MAX_SERVICES = types.MAX_SERVICES;
const MAX_ENDPOINTS = types.MAX_ENDPOINTS;
const MAX_SECRETS = types.MAX_SECRETS;
const MAX_CONTROLLER_NAME_LEN = types.MAX_CONTROLLER_NAME_LEN;
const MAX_NAME_LEN = types.MAX_NAME_LEN;
const MAX_HOSTNAME_LEN = types.MAX_HOSTNAME_LEN;
const MAX_PATH_VALUE_LEN = types.MAX_PATH_VALUE_LEN;
const INITIAL_BACKOFF_MS = types.INITIAL_BACKOFF_MS;
const MAX_BACKOFF_MS = types.MAX_BACKOFF_MS;
const BACKOFF_MULTIPLIER = types.BACKOFF_MULTIPLIER;

/// Number of resource types to watch in parallel.
/// TigerStyle: Explicit constant for bounded thread count.
const RESOURCE_TYPE_COUNT: u8 = 6;

/// Buffer sizes for different resource types (heap-allocated).
/// Secrets need large buffers for TLS certificates.
/// TigerStyle: Explicit bounds, sized for expected data.
const SMALL_BUFFER_SIZE: u32 = 16 * 1024; // 16KB for most resources
const LARGE_BUFFER_SIZE: u32 = 1024 * 1024; // 1MB for Secrets

// =============================================================================
// Resource Type
// =============================================================================

/// Resource type enum for dispatch.
/// Defined at module level for use in WatchThreadContext.
pub const ResourceType = enum(u8) {
    gateway_class = 0,
    gateway = 1,
    http_route = 2,
    service = 3,
    endpoints = 4,
    secret = 5,

    /// Get the K8s API path for this resource type.
    pub fn getPath(self: ResourceType) []const u8 {
        return switch (self) {
            .gateway_class => GATEWAY_CLASS_PATH,
            .gateway => GATEWAY_PATH,
            .http_route => HTTP_ROUTE_PATH,
            .service => SERVICES_PATH,
            .endpoints => ENDPOINTS_PATH,
            .secret => SECRETS_PATH,
        };
    }

    /// Get the resource type name for logging.
    pub fn getName(self: ResourceType) []const u8 {
        return switch (self) {
            .gateway_class => "GatewayClass",
            .gateway => "Gateway",
            .http_route => "HTTPRoute",
            .service => "Service",
            .endpoints => "Endpoints",
            .secret => "Secret",
        };
    }
};

// =============================================================================
// Watcher
// =============================================================================

/// Kubernetes resource watcher.
/// Watches Gateway API resources and triggers reconciliation on changes.
pub const Watcher = struct {
    /// K8s API client.
    client: *Client,
    /// Allocator for dynamic allocations.
    allocator: std.mem.Allocator,
    /// Atomic flag for graceful shutdown.
    running: std.atomic.Value(bool),
    /// Callback invoked when configuration changes.
    /// Args: user context, new config, Io runtime for async operations.
    on_config_change: *const fn (?*anyopaque, *gw_config.GatewayConfig, Io) void,
    /// User context passed to callback.
    callback_context: ?*anyopaque,
    /// Controller name we manage (e.g., "serval.dev/gateway-controller").
    /// Only Gateways referencing GatewayClasses with this controllerName are included.
    controller_name: ControllerNameStorage,
    /// Resolver for updating endpoint data when Endpoints resources change.
    /// TigerStyle: Borrowed reference, watcher does not own resolver lifecycle.
    resolver: *Resolver,

    /// Resource stores for each watched type.
    /// Secrets use large buffers for TLS certificates; others use small buffers.
    gateway_classes: ResourceStore(MAX_GATEWAY_CLASSES, SMALL_BUFFER_SIZE),
    gateways: ResourceStore(MAX_GATEWAYS, SMALL_BUFFER_SIZE),
    http_routes: ResourceStore(MAX_HTTP_ROUTES, SMALL_BUFFER_SIZE),
    services: ResourceStore(MAX_SERVICES, SMALL_BUFFER_SIZE),
    endpoints: ResourceStore(MAX_ENDPOINTS, SMALL_BUFFER_SIZE),
    secrets: ResourceStore(MAX_SECRETS, LARGE_BUFFER_SIZE),

    /// Parsed GatewayClass storage (populated by reconcile).
    parsed_gateway_classes: [MAX_GATEWAY_CLASSES]StoredGatewayClass,
    parsed_gateway_classes_count: u8,

    /// Parsed Gateway storage (populated by reconcile).
    parsed_gateways: [MAX_GATEWAYS]StoredGateway,
    parsed_gateways_count: u8,

    /// Parsed HTTPRoute storage (populated by reconcile).
    parsed_http_routes: [MAX_HTTP_ROUTES]StoredHTTPRoute,
    parsed_http_routes_count: u8,

    /// Temporary slices for building GatewayConfig return value.
    /// These point into parsed_* storage and are valid until next reconcile().
    temp_gateways: [MAX_GATEWAYS]gw_config.Gateway,
    temp_http_routes: [MAX_HTTP_ROUTES]gw_config.HTTPRoute,

    /// Storage for temporary hostname slices per route.
    temp_hostnames: [MAX_HTTP_ROUTES][gw_config.MAX_HOSTNAMES][]const u8,
    /// Storage for temporary rules slices per route.
    temp_rules: [MAX_HTTP_ROUTES][gw_config.MAX_RULES]gw_config.HTTPRouteRule,
    /// Storage for temporary matches slices per rule.
    temp_matches: [MAX_HTTP_ROUTES][gw_config.MAX_RULES][gw_config.MAX_MATCHES]gw_config.HTTPRouteMatch,
    /// Storage for temporary filters slices per rule.
    temp_filters: [MAX_HTTP_ROUTES][gw_config.MAX_RULES][gw_config.MAX_FILTERS]gw_config.HTTPRouteFilter,
    /// Storage for temporary backend_refs slices per rule.
    temp_backend_refs: [MAX_HTTP_ROUTES][gw_config.MAX_RULES][gw_config.MAX_BACKEND_REFS]gw_config.BackendRef,
    /// Storage for temporary listeners slices per gateway.
    temp_listeners: [MAX_GATEWAYS][gw_config.MAX_LISTENERS]gw_config.Listener,

    /// Line buffers for parsing watch events (one per watch thread).
    /// TigerStyle: Pre-allocated, bounded buffers.
    line_buffers: [RESOURCE_TYPE_COUNT][]u8,

    /// Current backoff duration in milliseconds (per resource type).
    current_backoff_ms: [RESOURCE_TYPE_COUNT]u32,

    /// Mutex for protecting shared state during reconciliation.
    /// TigerStyle: Explicit synchronization for thread safety.
    mutex: std.Thread.Mutex,

    /// Watch thread handles (one per resource type).
    /// Stored for clean shutdown via join().
    watch_threads: [RESOURCE_TYPE_COUNT]?std.Thread,

    /// Number of active watch threads.
    active_thread_count: std.atomic.Value(u8),

    const Self = @This();

    /// Initialize watcher with client, callback, resolver, and controller name.
    ///
    /// Preconditions:
    /// - client must be initialized and valid
    /// - on_config_change must be a valid function pointer
    /// - resolver must be valid (for updating endpoint data)
    /// - controller_name must be non-empty and within bounds
    ///
    /// The callback receives:
    /// - user context pointer
    /// - new GatewayConfig
    /// - Io runtime from watcher thread (for async operations like status updates)
    pub fn init(
        allocator: std.mem.Allocator,
        client: *Client,
        on_config_change: *const fn (?*anyopaque, *gw_config.GatewayConfig, Io) void,
        callback_context: ?*anyopaque,
        resolver: *Resolver,
        controller_name: []const u8,
    ) WatcherError!*Self {
        assert(@intFromPtr(client) != 0); // S1: precondition - valid client pointer
        assert(@intFromPtr(on_config_change) != 0); // S1: precondition - valid callback
        assert(@intFromPtr(resolver) != 0); // S1: precondition - valid resolver pointer
        assert(controller_name.len > 0); // S1: precondition - non-empty controller name
        assert(controller_name.len <= MAX_CONTROLLER_NAME_LEN); // S1: precondition - controller name fits

        const self = allocator.create(Self) catch return WatcherError.OutOfMemory;
        errdefer allocator.destroy(self);

        // Allocate line buffers for each watch thread.
        // TigerStyle: Pre-allocate all buffers at init, no allocation after init.
        var line_buffers: [RESOURCE_TYPE_COUNT][]u8 = undefined;
        var allocated_count: u8 = 0;
        errdefer {
            // Clean up any buffers allocated before failure.
            var cleanup_idx: u8 = 0;
            while (cleanup_idx < allocated_count) : (cleanup_idx += 1) {
                allocator.free(line_buffers[cleanup_idx]);
            }
        }

        while (allocated_count < RESOURCE_TYPE_COUNT) : (allocated_count += 1) {
            line_buffers[allocated_count] = allocator.alloc(u8, MAX_LINE_SIZE_BYTES) catch {
                return WatcherError.OutOfMemory;
            };
        }

        // Initialize controller_name storage.
        var ctrl_name_storage = ControllerNameStorage.init();
        ctrl_name_storage.set(controller_name);

        // Initialize backoff values for each resource type.
        var initial_backoffs: [RESOURCE_TYPE_COUNT]u32 = undefined;
        var backoff_idx: u8 = 0;
        while (backoff_idx < RESOURCE_TYPE_COUNT) : (backoff_idx += 1) {
            initial_backoffs[backoff_idx] = INITIAL_BACKOFF_MS;
        }

        // Initialize thread handles to null.
        var initial_threads: [RESOURCE_TYPE_COUNT]?std.Thread = undefined;
        var thread_idx: u8 = 0;
        while (thread_idx < RESOURCE_TYPE_COUNT) : (thread_idx += 1) {
            initial_threads[thread_idx] = null;
        }

        // Initialize resource stores with heap-allocated buffers.
        // TigerStyle: All allocation at init, errdefer for cleanup.
        var gateway_classes_store = ResourceStore(MAX_GATEWAY_CLASSES, SMALL_BUFFER_SIZE).init(allocator) catch {
            return WatcherError.OutOfMemory;
        };
        errdefer gateway_classes_store.deinit();

        var gateways_store = ResourceStore(MAX_GATEWAYS, SMALL_BUFFER_SIZE).init(allocator) catch {
            return WatcherError.OutOfMemory;
        };
        errdefer gateways_store.deinit();

        var http_routes_store = ResourceStore(MAX_HTTP_ROUTES, SMALL_BUFFER_SIZE).init(allocator) catch {
            return WatcherError.OutOfMemory;
        };
        errdefer http_routes_store.deinit();

        var services_store = ResourceStore(MAX_SERVICES, SMALL_BUFFER_SIZE).init(allocator) catch {
            return WatcherError.OutOfMemory;
        };
        errdefer services_store.deinit();

        var endpoints_store = ResourceStore(MAX_ENDPOINTS, SMALL_BUFFER_SIZE).init(allocator) catch {
            return WatcherError.OutOfMemory;
        };
        errdefer endpoints_store.deinit();

        var secrets_store = ResourceStore(MAX_SECRETS, LARGE_BUFFER_SIZE).init(allocator) catch {
            return WatcherError.OutOfMemory;
        };
        errdefer secrets_store.deinit();

        self.* = .{
            .client = client,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(false),
            .on_config_change = on_config_change,
            .callback_context = callback_context,
            .controller_name = ctrl_name_storage,
            .resolver = resolver,
            .gateway_classes = gateway_classes_store,
            .gateways = gateways_store,
            .http_routes = http_routes_store,
            .services = services_store,
            .endpoints = endpoints_store,
            .secrets = secrets_store,
            .parsed_gateway_classes = undefined,
            .parsed_gateway_classes_count = 0,
            .parsed_gateways = undefined,
            .parsed_gateways_count = 0,
            .parsed_http_routes = undefined,
            .parsed_http_routes_count = 0,
            .temp_gateways = undefined,
            .temp_http_routes = undefined,
            .temp_hostnames = undefined,
            .temp_rules = undefined,
            .temp_matches = undefined,
            .temp_filters = undefined,
            .temp_backend_refs = undefined,
            .temp_listeners = undefined,
            .line_buffers = line_buffers,
            .current_backoff_ms = initial_backoffs,
            .mutex = .{},
            .watch_threads = initial_threads,
            .active_thread_count = std.atomic.Value(u8).init(0),
        };

        // Initialize parsed storage arrays.
        for (&self.parsed_gateway_classes) |*gc| gc.* = StoredGatewayClass.init();
        for (&self.parsed_gateways) |*gw| gw.* = StoredGateway.init();
        for (&self.parsed_http_routes) |*route| route.* = StoredHTTPRoute.init();

        // S1: Postconditions
        assert(self.line_buffers[0].len == MAX_LINE_SIZE_BYTES); // buffer allocated
        assert(!self.running.load(.acquire)); // not running initially
        assert(self.controller_name.len > 0); // controller name set
        assert(self.active_thread_count.load(.acquire) == 0); // no threads running
        return self;
    }

    /// Clean up all allocated resources.
    /// TigerStyle: Explicit cleanup of all allocated resources.
    pub fn deinit(self: *Self) void {
        assert(@intFromPtr(self) != 0); // S1: precondition - valid self pointer
        assert(self.line_buffers[0].len > 0); // S1: precondition - buffers were allocated

        // Free resource store buffers.
        self.gateway_classes.deinit();
        self.gateways.deinit();
        self.http_routes.deinit();
        self.services.deinit();
        self.endpoints.deinit();
        self.secrets.deinit();

        // Free all line buffers.
        var buf_idx: u8 = 0;
        while (buf_idx < RESOURCE_TYPE_COUNT) : (buf_idx += 1) {
            self.allocator.free(self.line_buffers[buf_idx]);
        }
        self.allocator.destroy(self);
    }

    /// Start watching resources in parallel threads.
    /// Spawns one thread per resource type for concurrent watching.
    /// TigerStyle: Bounded thread count (RESOURCE_TYPE_COUNT), explicit error handling.
    pub fn start(self: *Self) !void {
        assert(@intFromPtr(self.client) != 0); // S1: precondition - client initialized
        assert(!self.running.load(.acquire)); // S1: precondition - not already running

        self.running.store(true, .release);

        std.log.debug("watcher: starting {d} watch threads", .{RESOURCE_TYPE_COUNT});

        // Spawn a thread for each resource type.
        // TigerStyle: Bounded loop, explicit iteration.
        const resource_types = [_]ResourceType{
            .gateway_class,
            .gateway,
            .http_route,
            .service,
            .endpoints,
            .secret,
        };

        var spawned_count: u8 = 0;
        errdefer {
            // On error, stop and wait for any threads that were spawned.
            self.running.store(false, .release);
            var cleanup_idx: u8 = 0;
            while (cleanup_idx < spawned_count) : (cleanup_idx += 1) {
                if (self.watch_threads[cleanup_idx]) |thread| {
                    thread.join();
                    self.watch_threads[cleanup_idx] = null;
                }
            }
        }

        while (spawned_count < RESOURCE_TYPE_COUNT) : (spawned_count += 1) {
            const resource_type = resource_types[spawned_count];
            const thread_idx = spawned_count;

            std.log.debug("watcher: spawning thread for {s}", .{resource_type.getName()});

            self.watch_threads[thread_idx] = std.Thread.spawn(
                .{},
                watchThreadLoop,
                .{ self, resource_type, thread_idx },
            ) catch |err| {
                std.log.err("watcher: failed to spawn thread for {s}: {s}", .{
                    resource_type.getName(),
                    @errorName(err),
                });
                return err;
            };

            _ = self.active_thread_count.fetchAdd(1, .acq_rel);
            std.log.info("watcher: thread {d} spawned for {s}", .{ thread_idx, resource_type.getName() });
        }

        // S1: Postconditions
        assert(self.running.load(.acquire)); // running flag set
        assert(self.active_thread_count.load(.acquire) == RESOURCE_TYPE_COUNT); // all threads spawned
        std.log.debug("watcher: all {d} watch threads started", .{RESOURCE_TYPE_COUNT});
    }

    /// Stop watching gracefully and wait for all threads to finish.
    /// TigerStyle: Explicit cleanup, bounded wait for threads.
    pub fn stop(self: *Self) void {
        std.log.debug("watcher: stopping, signaling threads to exit", .{});
        self.running.store(false, .release);

        // Wait for all watch threads to finish.
        // TigerStyle: Bounded loop, explicit join for each thread.
        var thread_idx: u8 = 0;
        while (thread_idx < RESOURCE_TYPE_COUNT) : (thread_idx += 1) {
            if (self.watch_threads[thread_idx]) |thread| {
                std.log.debug("watcher: joining thread {d}", .{thread_idx});
                thread.join();
                self.watch_threads[thread_idx] = null;
                _ = self.active_thread_count.fetchSub(1, .acq_rel);
            }
        }

        // S1: Postconditions
        assert(!self.running.load(.acquire)); // running flag cleared
        assert(self.active_thread_count.load(.acquire) == 0); // all threads stopped
        std.log.debug("watcher: all threads stopped", .{});
    }

    /// Per-thread watch loop for a single resource type.
    /// Each thread watches one resource type continuously with reconnection.
    /// TigerStyle: Bounded reconnect attempts, explicit backoff per thread.
    fn watchThreadLoop(self: *Self, resource_type: ResourceType, thread_idx: u8) void {
        assert(thread_idx < RESOURCE_TYPE_COUNT); // S1: precondition - valid thread index
        assert(self.running.load(.acquire)); // S1: precondition - watcher is running

        const resource_name = resource_type.getName();
        std.log.info("watcher: thread {d} STARTING for {s}", .{ thread_idx, resource_name });

        // Initialize Io runtime for this thread's HTTP client operations.
        // TigerStyle: One-time initialization at thread start.
        std.log.info("watcher: thread {d} initializing Io runtime...", .{thread_idx});
        var io_runtime = Io.Threaded.init(self.allocator, .{});
        defer io_runtime.deinit();
        const io = io_runtime.io();
        std.log.info("watcher: thread {d} Io runtime ready", .{thread_idx});

        var reconnect_attempts: u32 = 0;

        // Watch loop with reconnection.
        // TigerStyle: Bounded reconnect attempts, explicit backoff.
        while (self.running.load(.acquire) and reconnect_attempts < MAX_RECONNECT_ATTEMPTS) {
            std.log.debug("watcher: thread {d} watch iteration, attempt={d}", .{ thread_idx, reconnect_attempts });

            const watch_success = self.watchResourceType(resource_type, thread_idx, io);

            if (watch_success) {
                // Reset backoff on success.
                self.current_backoff_ms[thread_idx] = INITIAL_BACKOFF_MS;
                reconnect_attempts = 0;
            } else if (self.running.load(.acquire)) {
                // Apply exponential backoff on failure (only if still running).
                reconnect_attempts += 1;
                self.applyBackoff(thread_idx);
            }
        }

        if (reconnect_attempts >= MAX_RECONNECT_ATTEMPTS) {
            std.log.err("watcher: thread {d} ({s}) max reconnection attempts ({d}) exceeded", .{
                thread_idx,
                resource_name,
                MAX_RECONNECT_ATTEMPTS,
            });
        }

        std.log.debug("watcher: thread {d} ({s}) exiting", .{ thread_idx, resource_name });
    }

    /// Watch a single resource type using its dedicated thread buffer.
    /// Returns true if watch completed without error.
    /// TigerStyle: Uses thread-specific line buffer, explicit error handling.
    fn watchResourceType(self: *Self, resource_type: ResourceType, thread_idx: u8, io: Io) bool {
        assert(thread_idx < RESOURCE_TYPE_COUNT); // S1: precondition - valid thread index

        const path = resource_type.getPath();
        const resource_name = resource_type.getName();
        const line_buffer = self.line_buffers[thread_idx];

        assert(path.len > 0); // S1: precondition - non-empty path
        assert(path.len < 256); // S1: precondition - path fits in URL buffer
        assert(line_buffer.len == MAX_LINE_SIZE_BYTES); // S1: precondition - buffer allocated

        // Build watch URL with resourceVersion for resumption.
        var url_buffer: [512]u8 = undefined;
        const rv = switch (resource_type) {
            .gateway_class => self.gateway_classes.getLatestResourceVersion(),
            .gateway => self.gateways.getLatestResourceVersion(),
            .http_route => self.http_routes.getLatestResourceVersion(),
            .service => self.services.getLatestResourceVersion(),
            .endpoints => self.endpoints.getLatestResourceVersion(),
            .secret => self.secrets.getLatestResourceVersion(),
        };

        std.log.debug("watcher: thread {d} watchResourceType {s} rv={s}", .{
            thread_idx,
            resource_name,
            if (rv.len > 0) rv else "(none)",
        });

        const watch_url = if (rv.len > 0)
            std.fmt.bufPrint(&url_buffer, "{s}?watch=true&resourceVersion={s}", .{ path, rv }) catch {
                std.log.err("watcher: URL buffer overflow for {s}", .{path});
                return false;
            }
        else
            std.fmt.bufPrint(&url_buffer, "{s}?watch=true", .{path}) catch {
                std.log.err("watcher: URL buffer overflow for {s}", .{path});
                return false;
            };

        std.log.debug("watcher: thread {d} starting watch stream URL={s}", .{ thread_idx, watch_url });

        // Start watch stream.
        var stream = self.client.watch(watch_url);
        defer stream.close(); // TigerStyle: Explicit cleanup paired with creation.

        std.log.debug("watcher: thread {d} watch stream created, reading events...", .{thread_idx});

        // Process events until stream ends or error.
        // TigerStyle: Bounded loop with explicit iteration limit.
        var events_processed: u32 = 0;
        while (events_processed < MAX_EVENTS_PER_ITERATION and self.running.load(.acquire)) {
            std.log.debug("watcher: thread {d} iteration {d}, calling readEvent...", .{ thread_idx, events_processed });

            // Read next event line using thread-specific buffer.
            const event_data = stream.readEvent(line_buffer, io) catch |err| {
                std.log.debug("watcher: thread {d} read error for {s}: {s}", .{
                    thread_idx,
                    resource_name,
                    @errorName(err),
                });
                return false;
            };

            if (event_data) |data| {
                std.log.debug("watcher: thread {d} received event data len={d}", .{ thread_idx, data.len });
                // Parse and handle event (with mutex protection for shared state).
                self.handleEvent(data, resource_type, io) catch |err| {
                    std.log.debug("watcher: thread {d} event handling error: {s}", .{
                        thread_idx,
                        @errorName(err),
                    });
                    // Continue processing despite parse errors.
                };
                events_processed += 1;
            } else {
                // Stream ended normally (server closed connection).
                std.log.debug("watcher: thread {d} stream ended normally for {s}, events={d}", .{
                    thread_idx,
                    resource_name,
                    events_processed,
                });
                break;
            }
        }

        std.log.debug("watcher: thread {d} watchResourceType done, processed {d} events", .{
            thread_idx,
            events_processed,
        });
        return true;
    }

    /// Handle a single watch event.
    /// TigerStyle: Mutex protection for thread-safe access to shared state.
    fn handleEvent(self: *Self, data: []const u8, resource_type: ResourceType, io: Io) WatcherError!void {
        assert(data.len > 0); // S1: precondition - non-empty event data

        const event = try parseEvent(data);

        std.log.debug("watcher: handleEvent type={s} resource={s}", .{ @tagName(event.event_type), @tagName(resource_type) });

        // Acquire mutex for thread-safe access to shared ResourceStores.
        // TigerStyle: Explicit synchronization, mutex held during store modification.
        self.mutex.lock();
        defer self.mutex.unlock();

        // Handle based on event type.
        switch (event.event_type) {
            .ADDED, .MODIFIED => {
                std.log.debug("watcher: extracting meta from raw_object len={d}", .{event.raw_object.len});
                const meta = parsing.extractResourceMeta(event.raw_object) catch |err| {
                    std.log.err("watcher: extractResourceMeta failed: {s}", .{@errorName(err)});
                    return err;
                };
                std.log.debug("watcher: {s} {s}/{s}", .{ @tagName(event.event_type), meta.namespace, meta.name });
                switch (resource_type) {
                    .gateway_class => try self.gateway_classes.upsert(meta, event.raw_object),
                    .gateway => try self.gateways.upsert(meta, event.raw_object),
                    .http_route => try self.http_routes.upsert(meta, event.raw_object),
                    .service => try self.services.upsert(meta, event.raw_object),
                    .endpoints => {
                        std.log.debug("watcher: upserting endpoints for {s}/{s}", .{ meta.namespace, meta.name });
                        try self.endpoints.upsert(meta, event.raw_object);
                        // Update resolver with endpoint data for backend resolution.
                        // TigerStyle: Resolver.updateService parses the JSON internally.
                        std.log.debug("watcher: calling resolver.updateService for {s}/{s}", .{ meta.namespace, meta.name });
                        self.resolver.updateService(meta.name, meta.namespace, event.raw_object) catch |err| {
                            std.log.warn("watcher: failed to update resolver for {s}/{s}: {s}", .{
                                meta.namespace,
                                meta.name,
                                @errorName(err),
                            });
                            // Continue - store update succeeded, resolver update is best-effort.
                        };
                        std.log.debug("watcher: resolver now has {d} services", .{self.resolver.serviceCount()});
                    },
                    .secret => try self.secrets.upsert(meta, event.raw_object),
                }
                // Trigger reconciliation (still under mutex lock).
                std.log.debug("watcher: triggering reconciliation", .{});
                self.triggerReconciliationLocked(io);
            },
            .DELETED => {
                const meta = try parsing.extractResourceMeta(event.raw_object);
                const removed = switch (resource_type) {
                    .gateway_class => self.gateway_classes.remove(meta.name, meta.namespace),
                    .gateway => self.gateways.remove(meta.name, meta.namespace),
                    .http_route => self.http_routes.remove(meta.name, meta.namespace),
                    .service => self.services.remove(meta.name, meta.namespace),
                    .endpoints => blk: {
                        const r = self.endpoints.remove(meta.name, meta.namespace);
                        // Also remove from resolver.
                        self.resolver.removeService(meta.name, meta.namespace);
                        break :blk r;
                    },
                    .secret => self.secrets.remove(meta.name, meta.namespace),
                };
                if (removed) {
                    self.triggerReconciliationLocked(io);
                }
            },
            .BOOKMARK => {
                // Bookmark events just update resource version, no reconciliation needed.
                const meta = try parsing.extractResourceMeta(event.raw_object);
                switch (resource_type) {
                    .gateway_class => self.gateway_classes.updateResourceVersion(meta.resource_version),
                    .gateway => self.gateways.updateResourceVersion(meta.resource_version),
                    .http_route => self.http_routes.updateResourceVersion(meta.resource_version),
                    .service => self.services.updateResourceVersion(meta.resource_version),
                    .endpoints => self.endpoints.updateResourceVersion(meta.resource_version),
                    .secret => self.secrets.updateResourceVersion(meta.resource_version),
                }
            },
            .ERROR => {
                // ERROR events indicate watch needs restart.
                // Most commonly caused by expired resourceVersion (410 Gone).
                // Reset resourceVersion to empty so next watch starts fresh with a LIST.
                std.log.warn("watcher: received ERROR event, resetting resourceVersion", .{});
                switch (resource_type) {
                    .gateway_class => self.gateway_classes.resetResourceVersion(),
                    .gateway => self.gateways.resetResourceVersion(),
                    .http_route => self.http_routes.resetResourceVersion(),
                    .service => self.services.resetResourceVersion(),
                    .endpoints => self.endpoints.resetResourceVersion(),
                    .secret => self.secrets.resetResourceVersion(),
                }
            },
        }
    }

    /// Trigger reconciliation by building config and calling callback.
    /// Must be called with mutex already held.
    /// Passes Io to callback for async operations (e.g., K8s status updates).
    /// TigerStyle: Caller must hold mutex, explicit in function name.
    fn triggerReconciliationLocked(self: *Self, io: Io) void {
        assert(@intFromPtr(self.on_config_change) != 0); // S1: precondition - callback set

        std.log.debug("watcher: triggerReconciliation starting", .{});

        // Build GatewayConfig from stored resources.
        var gateway_config = self.reconcile() catch |err| {
            std.log.err("watcher: reconciliation failed: {s}", .{@errorName(err)});
            return;
        };

        std.log.debug("watcher: reconcile complete, gateways={d} routes={d}", .{
            gateway_config.gateways.len,
            gateway_config.http_routes.len,
        });

        // Invoke callback with context, new config, and Io for async operations.
        std.log.debug("watcher: invoking on_config_change callback", .{});
        self.on_config_change(self.callback_context, &gateway_config, io);
        std.log.debug("watcher: on_config_change callback returned", .{});
    }

    /// Reconcile stored resources into a GatewayConfig.
    /// Parses raw JSON from ResourceStores into typed config structs.
    /// Only includes Gateways that reference GatewayClasses with our controller_name.
    ///
    /// TigerStyle:
    /// - S1: Preconditions checked on entry
    /// - S2: Postconditions verified on exit
    /// - S3: All loops bounded by MAX_* constants
    /// - No allocation after init (uses pre-allocated storage arrays)
    pub fn reconcile(self: *Self) WatcherError!gw_config.GatewayConfig {
        std.log.debug("watcher: reconcile starting", .{});

        // Reset parsed counts.
        self.parsed_gateway_classes_count = 0;
        self.parsed_gateways_count = 0;
        self.parsed_http_routes_count = 0;

        // Phase 1: Parse GatewayClasses first (needed for filtering).
        try self.parseStoredGatewayClasses();
        std.log.debug("watcher: parsed {d} GatewayClasses", .{self.parsed_gateway_classes_count});

        // Phase 2: Find GatewayClass names that match our controller_name.
        var matching_class_names: [MAX_GATEWAY_CLASSES][]const u8 = undefined;
        const matching_count = self.findMatchingGatewayClasses(&matching_class_names);
        std.log.debug("watcher: {d} GatewayClasses match our controller", .{matching_count});

        // Phase 3: Parse Gateways and filter by matching GatewayClasses.
        std.log.debug("watcher: parsing Gateways...", .{});
        self.parseStoredGatewaysFiltered(matching_class_names[0..matching_count]) catch |err| {
            std.log.err("watcher: parseStoredGatewaysFiltered failed: {s}", .{@errorName(err)});
            return err;
        };
        std.log.debug("watcher: parsed {d} Gateways after filtering", .{self.parsed_gateways_count});
        std.log.debug("watcher: parsing HTTPRoutes...", .{});
        self.parseStoredHTTPRoutes() catch |err| {
            std.log.err("watcher: parseStoredHTTPRoutes failed: {s}", .{@errorName(err)});
            return err;
        };
        std.log.debug("watcher: parsed {d} HTTPRoutes", .{self.parsed_http_routes_count});

        // Phase 4: Build config slices from parsed storage.
        self.buildGatewayConfigs();
        self.buildHTTPRouteConfigs();

        // S2: Postconditions
        assert(self.parsed_gateway_classes_count <= MAX_GATEWAY_CLASSES);
        assert(self.parsed_gateways_count <= MAX_GATEWAYS);
        assert(self.parsed_http_routes_count <= MAX_HTTP_ROUTES);

        std.log.debug("watcher: reconcile done", .{});
        return gw_config.GatewayConfig{
            .gateways = self.temp_gateways[0..self.parsed_gateways_count],
            .http_routes = self.temp_http_routes[0..self.parsed_http_routes_count],
        };
    }

    /// Parse GatewayClass resources from ResourceStore into typed storage.
    /// TigerStyle: Bounded loop, explicit error handling.
    fn parseStoredGatewayClasses(self: *Self) WatcherError!void {
        var iteration: u32 = 0;
        const items = self.gateway_classes.items;

        while (iteration < MAX_GATEWAY_CLASSES) : (iteration += 1) {
            if (!items[iteration].active) continue;

            const raw_json = items[iteration].rawJson();
            if (raw_json.len == 0) continue;

            if (self.parsed_gateway_classes_count >= MAX_GATEWAY_CLASSES) {
                return WatcherError.BufferOverflow;
            }

            const idx = self.parsed_gateway_classes_count;
            try parseGatewayClassJson(raw_json, &self.parsed_gateway_classes[idx]);
            self.parsed_gateway_classes[idx].active = true;
            self.parsed_gateway_classes_count += 1;
        }

        // S2: Postcondition
        assert(self.parsed_gateway_classes_count <= MAX_GATEWAY_CLASSES);
    }

    /// Find GatewayClass names where spec.controllerName matches our controller_name.
    /// Returns the count of matching class names.
    /// TigerStyle: Bounded loop, returns count not slice to avoid allocation.
    fn findMatchingGatewayClasses(self: *Self, out_names: *[MAX_GATEWAY_CLASSES][]const u8) u8 {
        assert(self.controller_name.len > 0); // S1: precondition - controller name set

        std.log.debug("watcher: findMatchingGatewayClasses, our_controller={s}", .{self.controller_name.slice()});

        var match_count: u8 = 0;
        var idx: u8 = 0;

        while (idx < self.parsed_gateway_classes_count) : (idx += 1) {
            const gc = &self.parsed_gateway_classes[idx];
            if (!gc.active) continue;

            std.log.debug("watcher: checking GatewayClass name={s} controllerName={s}", .{
                gc.name.slice(),
                gc.controller_name.slice(),
            });

            // Check if controllerName matches our controller_name.
            if (std.mem.eql(u8, gc.controller_name.slice(), self.controller_name.slice())) {
                std.log.debug("watcher: GatewayClass {s} MATCHES", .{gc.name.slice()});
                if (match_count < MAX_GATEWAY_CLASSES) {
                    out_names[match_count] = gc.name.slice();
                    match_count += 1;
                }
            } else {
                std.log.debug("watcher: GatewayClass {s} does not match", .{gc.name.slice()});
            }
        }

        assert(match_count <= MAX_GATEWAY_CLASSES); // S2: postcondition - count within bounds
        return match_count;
    }

    /// Check if a Gateway's gatewayClassName is in our list of matching classes.
    /// TigerStyle: Bounded loop, explicit comparison.
    fn gatewayClassMatches(gateway_class_name: []const u8, our_classes: []const []const u8) bool {
        if (gateway_class_name.len == 0) return false;

        var idx: u32 = 0;
        while (idx < our_classes.len) : (idx += 1) {
            if (std.mem.eql(u8, gateway_class_name, our_classes[idx])) {
                return true;
            }
        }
        return false;
    }

    /// Parse Gateway resources, filtering by matching GatewayClasses.
    /// Only Gateways referencing one of our_classes are included.
    /// TigerStyle: Bounded loop, explicit error handling.
    fn parseStoredGatewaysFiltered(self: *Self, our_classes: []const []const u8) WatcherError!void {
        var iteration: u32 = 0;
        const items = self.gateways.items;

        std.log.debug("watcher: parseStoredGatewaysFiltered checking {d} slots", .{MAX_GATEWAYS});

        while (iteration < MAX_GATEWAYS) : (iteration += 1) {
            if (!items[iteration].active) continue;

            const raw_json = items[iteration].rawJson();
            if (raw_json.len == 0) continue;

            std.log.debug("watcher: parsing Gateway slot {d}, json_len={d}", .{ iteration, raw_json.len });

            if (self.parsed_gateways_count >= MAX_GATEWAYS) {
                return WatcherError.BufferOverflow;
            }

            // Parse into temporary storage first.
            var temp_gateway = StoredGateway.init();
            parseGatewayJson(raw_json, &temp_gateway) catch |err| {
                std.log.err("watcher: parseGatewayJson failed for slot {d}: {s}", .{ iteration, @errorName(err) });
                std.log.err("watcher: raw_json preview: {s}", .{raw_json[0..@min(200, raw_json.len)]});
                return err;
            };

            // Check if this Gateway's gatewayClassName matches one of our classes.
            if (!gatewayClassMatches(temp_gateway.gateway_class_name.slice(), our_classes)) {
                // Skip this Gateway - it doesn't belong to us.
                continue;
            }

            // Include this Gateway.
            const idx = self.parsed_gateways_count;
            self.parsed_gateways[idx] = temp_gateway;
            self.parsed_gateways[idx].active = true;
            self.parsed_gateways_count += 1;
        }

        // S2: Postcondition
        assert(self.parsed_gateways_count <= MAX_GATEWAYS);
    }

    /// Parse HTTPRoute resources from ResourceStore into typed storage.
    /// TigerStyle: Bounded loop, explicit error handling.
    fn parseStoredHTTPRoutes(self: *Self) WatcherError!void {
        var iteration: u32 = 0;
        const items = self.http_routes.items;

        while (iteration < MAX_HTTP_ROUTES) : (iteration += 1) {
            if (!items[iteration].active) continue;

            const raw_json = items[iteration].rawJson();
            if (raw_json.len == 0) continue;

            if (self.parsed_http_routes_count >= MAX_HTTP_ROUTES) {
                return WatcherError.BufferOverflow;
            }

            const idx = self.parsed_http_routes_count;
            try parseHTTPRouteJson(raw_json, &self.parsed_http_routes[idx]);
            self.parsed_http_routes[idx].active = true;
            self.parsed_http_routes_count += 1;
        }

        // S2: Postcondition
        assert(self.parsed_http_routes_count <= MAX_HTTP_ROUTES);
    }

    /// Build gw_config.Gateway slices from parsed storage.
    /// TigerStyle: Bounded loops, no allocation.
    fn buildGatewayConfigs(self: *Self) void {
        assert(self.parsed_gateways_count <= MAX_GATEWAYS); // S1: precondition - valid count

        var gw_idx: u8 = 0;

        while (gw_idx < self.parsed_gateways_count) : (gw_idx += 1) {
            const stored = &self.parsed_gateways[gw_idx];

            // Build listeners slice for this gateway.
            var listener_idx: u8 = 0;
            while (listener_idx < stored.listeners_count) : (listener_idx += 1) {
                const stored_listener = &stored.listeners[listener_idx];
                self.temp_listeners[gw_idx][listener_idx] = gw_config.Listener{
                    .name = stored_listener.name.slice(),
                    .port = stored_listener.port,
                    .protocol = stored_listener.protocol,
                    .hostname = if (stored_listener.has_hostname) stored_listener.hostname.slice() else null,
                    .tls = null, // TLS config parsing not implemented yet
                };
            }

            self.temp_gateways[gw_idx] = gw_config.Gateway{
                .name = stored.name.slice(),
                .namespace = stored.namespace.slice(),
                .listeners = self.temp_listeners[gw_idx][0..stored.listeners_count],
            };
        }
    }

    /// Build gw_config.HTTPRoute slices from parsed storage.
    /// TigerStyle: Bounded loops, no allocation.
    fn buildHTTPRouteConfigs(self: *Self) void {
        assert(self.parsed_http_routes_count <= MAX_HTTP_ROUTES); // S1: precondition - valid count

        var route_idx: u8 = 0;

        while (route_idx < self.parsed_http_routes_count) : (route_idx += 1) {
            const stored = &self.parsed_http_routes[route_idx];

            // Build hostnames slice.
            var hostname_idx: u8 = 0;
            while (hostname_idx < stored.hostnames_count) : (hostname_idx += 1) {
                self.temp_hostnames[route_idx][hostname_idx] = stored.hostnames[hostname_idx].slice();
            }

            // Build rules slice.
            var rule_idx: u8 = 0;
            while (rule_idx < stored.rules_count) : (rule_idx += 1) {
                self.buildRuleConfig(route_idx, rule_idx, &stored.rules[rule_idx]);
            }

            self.temp_http_routes[route_idx] = gw_config.HTTPRoute{
                .name = stored.name.slice(),
                .namespace = stored.namespace.slice(),
                .hostnames = self.temp_hostnames[route_idx][0..stored.hostnames_count],
                .rules = self.temp_rules[route_idx][0..stored.rules_count],
            };
        }
    }

    /// Build a single HTTPRouteRule config from stored rule.
    /// TigerStyle: Helper to keep buildHTTPRouteConfigs under 70 lines.
    fn buildRuleConfig(self: *Self, route_idx: u8, rule_idx: u8, stored_rule: *const StoredHTTPRouteRule) void {
        // S1: Preconditions
        assert(route_idx < gw_config.MAX_HTTP_ROUTES);
        assert(rule_idx < gw_config.MAX_RULES);

        // Build matches slice.
        var match_idx: u8 = 0;
        while (match_idx < stored_rule.matches_count) : (match_idx += 1) {
            const stored_match = &stored_rule.matches[match_idx];
            self.temp_matches[route_idx][rule_idx][match_idx] = gw_config.HTTPRouteMatch{
                .path = if (stored_match.has_path) stored_match.path.toPathMatch() else null,
            };
        }

        // Build filters slice.
        var filter_idx: u8 = 0;
        while (filter_idx < stored_rule.filters_count) : (filter_idx += 1) {
            const stored_filter = &stored_rule.filters[filter_idx];
            const url_rewrite: ?gw_config.URLRewrite = if (stored_filter.url_rewrite.has_path)
                gw_config.URLRewrite{ .path = stored_filter.url_rewrite.path.toPathRewrite() }
            else
                null;

            self.temp_filters[route_idx][rule_idx][filter_idx] = gw_config.HTTPRouteFilter{
                .type = stored_filter.filter_type,
                .url_rewrite = url_rewrite,
            };
        }

        // Build backend_refs slice.
        var backend_idx: u8 = 0;
        while (backend_idx < stored_rule.backend_refs_count) : (backend_idx += 1) {
            const stored_backend = &stored_rule.backend_refs[backend_idx];
            self.temp_backend_refs[route_idx][rule_idx][backend_idx] = gw_config.BackendRef{
                .name = stored_backend.name.slice(),
                .namespace = stored_backend.namespace.slice(),
                .port = stored_backend.port,
                .weight = stored_backend.weight,
            };
        }

        self.temp_rules[route_idx][rule_idx] = gw_config.HTTPRouteRule{
            .matches = self.temp_matches[route_idx][rule_idx][0..stored_rule.matches_count],
            .filters = self.temp_filters[route_idx][rule_idx][0..stored_rule.filters_count],
            .backend_refs = self.temp_backend_refs[route_idx][rule_idx][0..stored_rule.backend_refs_count],
        };
    }

    /// Apply backoff delay with exponential increase for a specific thread.
    /// TigerStyle: Per-thread backoff prevents one failing resource from affecting others.
    fn applyBackoff(self: *Self, thread_idx: u8) void {
        assert(thread_idx < RESOURCE_TYPE_COUNT); // S1: precondition - valid thread index
        assert(self.current_backoff_ms[thread_idx] >= INITIAL_BACKOFF_MS); // S1: precondition - valid backoff
        assert(self.current_backoff_ms[thread_idx] <= MAX_BACKOFF_MS); // S1: precondition - within bounds

        const current_ms = self.current_backoff_ms[thread_idx];

        // Sleep for current backoff duration.
        const backoff_s: u64 = current_ms / 1000;
        const backoff_ns: u64 = (@as(u64, current_ms) % 1000) * 1_000_000;
        posix.nanosleep(backoff_s, backoff_ns);

        // Increase backoff for next attempt (capped at MAX_BACKOFF_MS).
        const new_backoff = current_ms * BACKOFF_MULTIPLIER;
        self.current_backoff_ms[thread_idx] = @min(new_backoff, MAX_BACKOFF_MS);

        assert(self.current_backoff_ms[thread_idx] <= MAX_BACKOFF_MS); // S1: postcondition - still within bounds
    }
};

// =============================================================================
// Unit Tests
// =============================================================================

test "EventType.fromString - valid types" {
    try std.testing.expectEqual(EventType.ADDED, EventType.fromString("ADDED").?);
    try std.testing.expectEqual(EventType.MODIFIED, EventType.fromString("MODIFIED").?);
    try std.testing.expectEqual(EventType.DELETED, EventType.fromString("DELETED").?);
    try std.testing.expectEqual(EventType.BOOKMARK, EventType.fromString("BOOKMARK").?);
    try std.testing.expectEqual(EventType.ERROR, EventType.fromString("ERROR").?);
}

test "EventType.fromString - invalid types" {
    try std.testing.expect(EventType.fromString("UNKNOWN") == null);
    try std.testing.expect(EventType.fromString("added") == null); // Case sensitive
    try std.testing.expect(EventType.fromString("") == null);
}

test "EventType.toString" {
    try std.testing.expectEqualStrings("ADDED", EventType.ADDED.toString());
    try std.testing.expectEqualStrings("MODIFIED", EventType.MODIFIED.toString());
    try std.testing.expectEqualStrings("DELETED", EventType.DELETED.toString());
    try std.testing.expectEqualStrings("BOOKMARK", EventType.BOOKMARK.toString());
    try std.testing.expectEqualStrings("ERROR", EventType.ERROR.toString());
}

test "ResourceStore - init" {
    const store = ResourceStore(16).init();
    try std.testing.expectEqual(@as(u32, 0), store.count);
    try std.testing.expectEqual(@as(usize, 0), store.getLatestResourceVersion().len);
}

test "ResourceStore - upsert and getActive" {
    var store = ResourceStore(16).init();

    // Add first resource.
    try store.upsert(.{
        .name = "gateway1",
        .namespace = "default",
        .resource_version = "100",
    }, "{}");
    try std.testing.expectEqual(@as(u32, 1), store.count);

    // Add second resource.
    try store.upsert(.{
        .name = "gateway2",
        .namespace = "default",
        .resource_version = "101",
    }, "{}");
    try std.testing.expectEqual(@as(u32, 2), store.count);

    // Update first resource (upsert).
    try store.upsert(.{
        .name = "gateway1",
        .namespace = "default",
        .resource_version = "102",
    }, "{\"updated\":true}");
    try std.testing.expectEqual(@as(u32, 2), store.count);

    // Verify latest resource version.
    try std.testing.expectEqualStrings("102", store.getLatestResourceVersion());
}

test "ResourceStore - remove" {
    var store = ResourceStore(16).init();

    // Add resources.
    try store.upsert(.{ .name = "gw1", .namespace = "ns1", .resource_version = "1" }, "{}");
    try store.upsert(.{ .name = "gw2", .namespace = "ns1", .resource_version = "2" }, "{}");
    try std.testing.expectEqual(@as(u32, 2), store.count);

    // Remove existing.
    try std.testing.expect(store.remove("gw1", "ns1"));
    try std.testing.expectEqual(@as(u32, 1), store.count);

    // Remove non-existing.
    try std.testing.expect(!store.remove("gw3", "ns1"));
    try std.testing.expectEqual(@as(u32, 1), store.count);

    // Remove with wrong namespace.
    try std.testing.expect(!store.remove("gw2", "ns2"));
    try std.testing.expectEqual(@as(u32, 1), store.count);
}

test "ResourceStore - buffer overflow" {
    var store = ResourceStore(2).init();

    // Fill store.
    try store.upsert(.{ .name = "gw1", .namespace = "ns", .resource_version = "1" }, "{}");
    try store.upsert(.{ .name = "gw2", .namespace = "ns", .resource_version = "2" }, "{}");

    // Third insert should fail.
    const result = store.upsert(.{ .name = "gw3", .namespace = "ns", .resource_version = "3" }, "{}");
    try std.testing.expectError(WatcherError.BufferOverflow, result);
}

test "ResourceStore - upsert reuses slot" {
    var store = ResourceStore(2).init();

    // Fill store.
    try store.upsert(.{ .name = "gw1", .namespace = "ns", .resource_version = "1" }, "{}");
    try store.upsert(.{ .name = "gw2", .namespace = "ns", .resource_version = "2" }, "{}");

    // Upsert existing should succeed (reuses slot).
    try store.upsert(.{ .name = "gw1", .namespace = "ns", .resource_version = "3" }, "{\"v\":3}");
    try std.testing.expectEqual(@as(u32, 2), store.count);
}

test "backoff calculation" {
    // Test the backoff multiplier calculation.
    var backoff: u32 = INITIAL_BACKOFF_MS;

    // First backoff: 1000ms
    try std.testing.expectEqual(@as(u32, 1000), backoff);

    // Second backoff: 2000ms
    backoff = @min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_MS);
    try std.testing.expectEqual(@as(u32, 2000), backoff);

    // Third backoff: 4000ms
    backoff = @min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_MS);
    try std.testing.expectEqual(@as(u32, 4000), backoff);

    // Eventually caps at MAX_BACKOFF_MS.
    var iteration: u32 = 0;
    while (iteration < 10) : (iteration += 1) {
        backoff = @min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_MS);
    }
    try std.testing.expectEqual(MAX_BACKOFF_MS, backoff);
}

test "constants are sensible" {
    // Verify constants are within expected ranges.
    try std.testing.expect(MAX_LINE_SIZE_BYTES >= 16 * 1024); // At least 16KB
    try std.testing.expect(MAX_LINE_SIZE_BYTES <= 256 * 1024); // Not more than 256KB
    try std.testing.expect(MAX_EVENTS_PER_ITERATION >= 100);
    try std.testing.expect(MAX_RECONNECT_ATTEMPTS >= 10);
    try std.testing.expect(INITIAL_BACKOFF_MS >= 100);
    try std.testing.expect(MAX_BACKOFF_MS >= INITIAL_BACKOFF_MS);
    try std.testing.expect(BACKOFF_MULTIPLIER >= 2);
}

test "K8s API paths are correct" {
    // Verify paths match K8s Gateway API conventions.
    try std.testing.expect(std.mem.startsWith(u8, GATEWAY_CLASS_PATH, "/apis/gateway.networking.k8s.io/"));
    try std.testing.expect(std.mem.startsWith(u8, GATEWAY_PATH, "/apis/gateway.networking.k8s.io/"));
    try std.testing.expect(std.mem.startsWith(u8, HTTP_ROUTE_PATH, "/apis/gateway.networking.k8s.io/"));
    try std.testing.expect(std.mem.startsWith(u8, SERVICES_PATH, "/api/v1/"));
    try std.testing.expect(std.mem.startsWith(u8, ENDPOINTS_PATH, "/api/v1/"));
    try std.testing.expect(std.mem.startsWith(u8, SECRETS_PATH, "/api/v1/"));
}

test "ResourceType.getPath returns correct paths" {
    try std.testing.expectEqualStrings(GATEWAY_CLASS_PATH, ResourceType.gateway_class.getPath());
    try std.testing.expectEqualStrings(GATEWAY_PATH, ResourceType.gateway.getPath());
    try std.testing.expectEqualStrings(HTTP_ROUTE_PATH, ResourceType.http_route.getPath());
    try std.testing.expectEqualStrings(SERVICES_PATH, ResourceType.service.getPath());
    try std.testing.expectEqualStrings(ENDPOINTS_PATH, ResourceType.endpoints.getPath());
    try std.testing.expectEqualStrings(SECRETS_PATH, ResourceType.secret.getPath());
}

test "ResourceType.getName returns correct names" {
    try std.testing.expectEqualStrings("GatewayClass", ResourceType.gateway_class.getName());
    try std.testing.expectEqualStrings("Gateway", ResourceType.gateway.getName());
    try std.testing.expectEqualStrings("HTTPRoute", ResourceType.http_route.getName());
    try std.testing.expectEqualStrings("Service", ResourceType.service.getName());
    try std.testing.expectEqualStrings("Endpoints", ResourceType.endpoints.getName());
    try std.testing.expectEqualStrings("Secret", ResourceType.secret.getName());
}

test "RESOURCE_TYPE_COUNT matches number of ResourceType variants" {
    // TigerStyle: Explicit test that constant matches enum count.
    const resource_types = [_]ResourceType{
        .gateway_class,
        .gateway,
        .http_route,
        .service,
        .endpoints,
        .secret,
    };
    try std.testing.expectEqual(RESOURCE_TYPE_COUNT, resource_types.len);
}

test "NameStorage - basic operations" {
    var storage = NameStorage.init();
    try std.testing.expectEqual(@as(u8, 0), storage.len);

    storage.set("test-name");
    try std.testing.expectEqual(@as(u8, 9), storage.len);
    try std.testing.expectEqualStrings("test-name", storage.slice());

    storage.set("another");
    try std.testing.expectEqualStrings("another", storage.slice());
}

test "PathStorage - basic operations" {
    var storage = PathStorage.init();
    try std.testing.expectEqual(@as(u16, 0), storage.len);

    storage.set("/api/v1/users");
    try std.testing.expectEqualStrings("/api/v1/users", storage.slice());
}

test "StoredPathMatch - toPathMatch" {
    var stored = StoredPathMatch.init();
    stored.match_type = .Exact;
    stored.value.set("/exact/path");
    stored.active = true;

    const path_match = stored.toPathMatch();
    try std.testing.expectEqual(gw_config.PathMatch.Type.Exact, path_match.type);
    try std.testing.expectEqualStrings("/exact/path", path_match.value);
}

test "StoredHTTPRouteRule init" {
    const rule = StoredHTTPRouteRule.init();
    try std.testing.expectEqual(@as(u8, 0), rule.matches_count);
    try std.testing.expectEqual(@as(u8, 0), rule.filters_count);
    try std.testing.expectEqual(@as(u8, 0), rule.backend_refs_count);
    try std.testing.expect(!rule.active);
}

test "StoredGateway init" {
    const gw = StoredGateway.init();
    try std.testing.expectEqual(@as(u8, 0), gw.name.len);
    try std.testing.expectEqual(@as(u8, 0), gw.gateway_class_name.len);
    try std.testing.expectEqual(@as(u8, 0), gw.listeners_count);
    try std.testing.expect(!gw.active);
}

test "StoredGateway gateway_class_name field" {
    var gw = StoredGateway.init();
    gw.gateway_class_name.set("serval");
    try std.testing.expectEqualStrings("serval", gw.gateway_class_name.slice());
}

// =============================================================================
// Gateway Filtering Tests
// =============================================================================

test "gatewayClassMatches - matching class" {
    const our_classes = [_][]const u8{ "serval", "nginx" };
    try std.testing.expect(Watcher.gatewayClassMatches("serval", &our_classes));
    try std.testing.expect(Watcher.gatewayClassMatches("nginx", &our_classes));
}

test "gatewayClassMatches - non-matching class" {
    const our_classes = [_][]const u8{ "serval", "nginx" };
    try std.testing.expect(!Watcher.gatewayClassMatches("istio", &our_classes));
    try std.testing.expect(!Watcher.gatewayClassMatches("contour", &our_classes));
}

test "gatewayClassMatches - empty class name" {
    const our_classes = [_][]const u8{ "serval", "nginx" };
    try std.testing.expect(!Watcher.gatewayClassMatches("", &our_classes));
}

test "gatewayClassMatches - empty our_classes" {
    const empty_classes: []const []const u8 = &.{};
    try std.testing.expect(!Watcher.gatewayClassMatches("serval", empty_classes));
}

test "parseGatewayJson - extracts gatewayClassName" {
    const json =
        \\{
        \\  "metadata": {"name": "my-gateway", "namespace": "default"},
        \\  "spec": {
        \\    "gatewayClassName": "serval",
        \\    "listeners": [
        \\      {"name": "http", "port": 80, "protocol": "HTTP"}
        \\    ]
        \\  }
        \\}
    ;

    var gw = StoredGateway.init();
    try parseGatewayJson(json, &gw);

    try std.testing.expectEqualStrings("my-gateway", gw.name.slice());
    try std.testing.expectEqualStrings("default", gw.namespace.slice());
    try std.testing.expectEqualStrings("serval", gw.gateway_class_name.slice());
}

test "parseGatewayJson - missing gatewayClassName" {
    const json =
        \\{
        \\  "metadata": {"name": "my-gateway", "namespace": "default"},
        \\  "spec": {
        \\    "listeners": [
        \\      {"name": "http", "port": 80, "protocol": "HTTP"}
        \\    ]
        \\  }
        \\}
    ;

    var gw = StoredGateway.init();
    try parseGatewayJson(json, &gw);

    // gatewayClassName should be empty if not present
    try std.testing.expectEqual(@as(u8, 0), gw.gateway_class_name.len);
}

test "StoredGatewayClass - basic operations" {
    var gc = StoredGatewayClass.init();
    gc.name.set("serval");
    gc.controller_name.set("serval.dev/gateway-controller");
    gc.active = true;

    try std.testing.expectEqualStrings("serval", gc.name.slice());
    try std.testing.expectEqualStrings("serval.dev/gateway-controller", gc.controller_name.slice());
    try std.testing.expect(gc.active);
}

test "parseGatewayClassJson - full example" {
    const json =
        \\{
        \\  "metadata": {"name": "serval", "resourceVersion": "12345"},
        \\  "spec": {"controllerName": "serval.dev/gateway-controller"}
        \\}
    ;

    var gc = StoredGatewayClass.init();
    try parseGatewayClassJson(json, &gc);

    try std.testing.expectEqualStrings("serval", gc.name.slice());
    try std.testing.expectEqualStrings("serval.dev/gateway-controller", gc.controller_name.slice());
    try std.testing.expect(gc.active);
}
