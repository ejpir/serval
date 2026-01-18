# Serval Gateway Controller Architecture

This document describes the architecture of the serval Kubernetes Gateway API controller system, which consists of two main components: the **Gateway Controller** (control plane) and the **Router** (data plane).

## Component Overview

```
+------------------------------------------------------------------+
|                     KUBERNETES CLUSTER                            |
|  +--------------------+              +-------------------------+  |
|  |  Gateway Controller|              |     Router (Data Plane) |  |
|  |  (Control Plane)   |    HTTP      |                         |  |
|  |                    |   POST       |   +------------------+   |  |
|  |  +-------------+   | /routes/     |   |  Admin Server    |   |  |
|  |  | K8s Watcher +---| update       |-->|  (port 9901)     |   |  |
|  |  +------+------+   |              |   +--------+---------+   |  |
|  |         |          |              |            |             |  |
|  |  +------v------+   |              |   +--------v---------+   |  |
|  |  | Translator  |   |              |   | Config Storage   |   |  |
|  |  +-------------+   |              |   | (Double-Buffer)  |   |  |
|  |                    |              |   +--------+---------+   |  |
|  |  +-------------+   |              |            |             |  |
|  |  | Status Mgr  +---|--- PATCH     |   +--------v---------+   |  |
|  |  +-------------+   |   /status    |   | Router Handler   |   |  |
|  |         ^          |              |   | (port 8080)      |   |  |
|  |         |          |              |   +------------------+   |  |
|  +---------|----------+              +-------------------------+  |
|            |                                                      |
|   +--------v---------+                                            |
|   |  K8s API Server  |                                            |
|   +------------------+                                            |
+------------------------------------------------------------------+
```

### 1. Gateway Controller (`examples/gateway/`)

The Gateway Controller is a Kubernetes controller that:
- Watches Gateway API resources (GatewayClass, Gateway, HTTPRoute) and related resources (Service, Endpoints, Secret)
- Translates Gateway API configuration to serval-router JSON format
- Pushes configuration to router data plane instances via HTTP
- Updates Kubernetes resource status (e.g., Gateway.status.conditions)

**Key Files:**
| File | Purpose |
|------|---------|
| `/home/nick/repos/serval/examples/gateway/main.zig` | Entry point, CLI parsing, thread orchestration |
| `/home/nick/repos/serval/examples/gateway/controller.zig` | Core controller logic, config update coordination |
| `/home/nick/repos/serval/examples/gateway/data_plane.zig` | HTTP client for pushing config to routers |
| `/home/nick/repos/serval/examples/gateway/watcher/mod.zig` | K8s watch streams, resource tracking, reconciliation |
| `/home/nick/repos/serval/examples/gateway/resolver/mod.zig` | Service-to-Endpoints resolution for backends |
| `/home/nick/repos/serval/examples/gateway/k8s_client/mod.zig` | K8s API HTTP client with TLS |

### 2. Router (Data Plane) (`examples/router/`)

The Router is an HTTP reverse proxy that:
- Receives configuration from the Gateway Controller
- Routes incoming requests based on host/path matching
- Load balances traffic across upstream backends
- Provides admin API for health probes and configuration

**Key Files:**
| File | Purpose |
|------|---------|
| `/home/nick/repos/serval/examples/router/main.zig` | Entry point, server initialization |
| `/home/nick/repos/serval/examples/router/config_storage.zig` | Double-buffered atomic config swap |
| `/home/nick/repos/serval/examples/router/admin/mod.zig` | Admin API HTTP handler |
| `/home/nick/repos/serval/examples/router/admin/routes.zig` | Route CRUD operations |

---

## Data Flow Diagram

```
                            KUBERNETES API SERVER
                                     |
           +-------------------------+------------------------+
           |                         |                        |
           v                         v                        v
    [GatewayClass]            [Gateway]               [HTTPRoute]
           |                         |                        |
           |    +--------------------+--------------------+   |
           |    |                    |                    |   |
           v    v                    v                    v   v
      +------------------------------------------------------------------------+
      |                         WATCHER (mod.zig:137-1073)                      |
      |                                                                         |
      |  +------------------+  +------------------+  +------------------+       |
      |  | GatewayClass     |  | Gateway          |  | HTTPRoute        |       |
      |  | Watch Thread     |  | Watch Thread     |  | Watch Thread     |       |
      |  | (thread_idx=0)   |  | (thread_idx=1)   |  | (thread_idx=2)   |       |
      |  +--------+---------+  +--------+---------+  +--------+---------+       |
      |           |                     |                     |                 |
      |           +----------+----------+----------+----------+                 |
      |                      |                     |                            |
      |                      v                     v                            |
      |              ResourceStore          ResourceStore                       |
      |              (gateway_classes)      (gateways, http_routes, ...)        |
      |                      |                     |                            |
      +----------------------|---------------------|----------------------------+
                             |                     |
                             v                     v
                    +------------------+   +------------------+
                    | parseGatewayClass|   | parseGatewayJson |
                    | Json (parsing.zig)   | parseHTTPRouteJson
                    +--------+---------+   +--------+---------+
                             |                     |
                             v                     v
                    +------------------------------------------+
                    |           RECONCILE (mod.zig:746-791)    |
                    |                                          |
                    |  1. Parse GatewayClasses                 |
                    |  2. Filter by controllerName             |
                    |  3. Parse Gateways (filter by class)     |
                    |  4. Parse HTTPRoutes                     |
                    |  5. Build GatewayConfig struct           |
                    +--------------------+---------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |       onConfigChange CALLBACK            |
                    |       (main.zig:342-350)                 |
                    +--------------------+---------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |         CONTROLLER (controller.zig)      |
                    |                                          |
                    |  updateConfig (line 311-384):            |
                    |    1. Store config pointer               |
                    |    2. Push to data plane (single or HA)  |
                    |    3. Update Gateway status in K8s       |
                    +--------------------+---------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |      DATA PLANE CLIENT (data_plane.zig)  |
                    |                                          |
                    |  pushConfigToAll (line 741-833):         |
                    |    1. Resolve backends via Resolver      |
                    |    2. Translate to router JSON           |
                    |    3. POST to router admin API           |
                    |    4. Track synced endpoints             |
                    +--------------------+---------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |              ROUTER (data plane)         |
                    |                                          |
                    |  AdminHandler.onRequest (mod.zig:52-198) |
                    |    -> handleRouteUpdate (routes.zig:37)  |
                    |    -> swapRouter (config_storage.zig:218)|
                    +------------------------------------------+
```

---

## Control Flow - What Triggers What

### Startup Sequence

```
main() [main.zig:170-181]
    |
    +-> parseArgs() [main.zig:74-130]
    |
    +-> initK8sClient() [main.zig:354-375]
    |       |
    |       +-> K8sClient.initInCluster() OR initWithConfig()
    |           [k8s_client/mod.zig:196-327]
    |
    +-> Controller.create() [controller.zig:128-184]
    |       |
    |       +-> Resolver.create() [resolver/mod.zig:98-113]
    |       +-> DataPlaneClient.create() [data_plane.zig:167-191]
    |       +-> StatusManager.init()
    |
    +-> startAdminServer() [main.zig:396-404]
    |       |
    |       +-> Spawn thread: adminServerLoop() [main.zig:410-445]
    |           - Runs MinimalServer for /healthz, /readyz
    |
    +-> initAndStartWatcher() [main.zig:303-337]
    |       |
    |       +-> Watcher.init() [watcher/mod.zig:227-358]
    |       +-> Watcher.start() [watcher/mod.zig:385-443]
    |           |
    |           +-> Spawn 6 threads (one per resource type):
    |               - watchThreadLoop() [watcher/mod.zig:472-516]
    |
    +-> ctrl.setReady(true)
    |
    +-> waitForShutdown() [main.zig:379-390]
```

### Watch Event Processing

```
watchThreadLoop() [watcher/mod.zig:472-516]
    |
    +-> watchResourceType() [watcher/mod.zig:521-611]
    |       |
    |       +-> client.watch(path) [k8s_client/mod.zig:756-762]
    |       |       - Opens streaming HTTP connection to K8s API
    |       |
    |       +-> stream.readEvent() [k8s_client/mod.zig:855-933]
    |       |       - Reads newline-delimited JSON events
    |       |
    |       +-> handleEvent() [watcher/mod.zig:615-709]
    |               |
    |               +-> parseEvent() [parsing.zig]
    |               |       - Extracts type (ADDED/MODIFIED/DELETED/BOOKMARK)
    |               |       - Extracts raw_object JSON
    |               |
    |               +-> ResourceStore.upsert/remove() [types.zig:283-366]
    |               |       - Stores raw JSON in bounded buffer
    |               |
    |               +-> IF Endpoints: resolver.updateService() [resolver/mod.zig:137-199]
    |               |       - Parses pod IPs from Endpoints JSON
    |               |       - Stores in Resolver for backend resolution
    |               |
    |               +-> triggerReconciliationLocked() [watcher/mod.zig:715-735]
                            |
                            +-> reconcile() [watcher/mod.zig:746-791]
                            |       - Builds GatewayConfig from stored resources
                            |
                            +-> on_config_change(callback_ctx, &gateway_config, io)
                                    |
                                    +-> onConfigChange() [main.zig:342-350]
                                            |
                                            +-> Controller.updateConfig()
```

### Config Push to Router

```
Controller.updateConfig() [controller.zig:311-384]
    |
    +-> IF multi_endpoint_enabled:
    |       pushConfigMultiEndpoint() [controller.zig:447-521]
    |           |
    |           +-> DataPlaneClient.refreshEndpoints() [data_plane.zig:222-262]
    |           |       - Discovers router pod IPs via EndpointSlice API
    |           |
    |           +-> DataPlaneClient.pushConfigToAll() [data_plane.zig:741-833]
    |
    +-> ELSE:
    |       pushConfigWithRetry() [data_plane.zig:358-410]
    |           |
    |           +-> pushConfig() [data_plane.zig:288-352]
    |                   |
    |                   +-> resolveBackends() [data_plane.zig:416-485]
    |                   |       - Resolver.resolveBackend() for each BackendRef
    |                   |
    |                   +-> translator.translateToJson() [serval-k8s-gateway]
    |                   |       - Converts GatewayConfig to router JSON format
    |                   |
    |                   +-> sendConfigRequest() [data_plane.zig:491-555]
    |                           - POST to http://router:9901/routes/update
    |
    +-> StatusManager.updateGatewayStatus() [status.zig]
            - PATCH Gateway.status.conditions in K8s
```

### Router Config Swap (Data Plane)

```
AdminHandler.onRequest() [admin/mod.zig:52-198]
    |
    +-> IF path == "/routes/update" AND method == POST:
    |       |
    |       +-> ctx.readBody() - Read JSON body
    |       |
    |       +-> handleRouteUpdate() [admin/routes.zig:37-205]
    |               |
    |               +-> json.parseFromSlice(ConfigJson, body)
    |               |       - Parse routes, pools, upstreams from JSON
    |               |
    |               +-> Validate configuration
    |               |       - Pool count > 0, route pool_idx valid, etc.
    |               |
    |               +-> config_storage.swapRouter() [config_storage.zig:218-292]
    |                       |
    |                       +-> swap_mutex.lock()
    |                       |
    |                       +-> Calculate inactive_slot = 1 - active_slot
    |                       |
    |                       +-> Deinit old router in inactive slot (if any)
    |                       |
    |                       +-> storage[inactive_slot].copyRoutes/copyPoolConfigs()
    |                       |       - Deep copy config into persistent storage
    |                       |
    |                       +-> router_storage[inactive_slot].init()
    |                       |
    |                       +-> current_router.store(&router_storage[inactive_slot])
    |                       |
    |                       +-> active_slot.store(inactive_slot)
    |                       |
    |                       +-> router_generation.fetchAdd(1)
    |                       |
    |                       +-> nanosleep(grace_period)
    |                       |       - Wait for in-flight requests to complete
    |                       |
    |                       +-> swap_mutex.unlock()
```

---

## State Management

### Gateway Controller State

```
+------------------------------------------------------------------+
|                     CONTROLLER STATE                              |
|                                                                   |
|  +------------------+     +------------------+                    |
|  |  ready (atomic)  |     | shutdown (atomic)|                    |
|  +------------------+     +------------------+                    |
|                                                                   |
|  +----------------------------------------------------------+    |
|  |                    WATCHER STATE                          |    |
|  |                                                           |    |
|  |  ResourceStore[6]:                                        |    |
|  |    gateway_classes   - raw JSON + metadata               |    |
|  |    gateways          - raw JSON + metadata               |    |
|  |    http_routes       - raw JSON + metadata               |    |
|  |    services          - raw JSON + metadata               |    |
|  |    endpoints         - raw JSON + metadata               |    |
|  |    secrets           - raw JSON + metadata               |    |
|  |                                                           |    |
|  |  parsed_gateway_classes[MAX]  - StoredGatewayClass       |    |
|  |  parsed_gateways[MAX]         - StoredGateway            |    |
|  |  parsed_http_routes[MAX]      - StoredHTTPRoute          |    |
|  |                                                           |    |
|  |  controller_name              - "serval.dev/..."          |    |
|  |  mutex                        - protects reconciliation   |    |
|  +----------------------------------------------------------+    |
|                                                                   |
|  +----------------------------------------------------------+    |
|  |                   RESOLVER STATE                          |    |
|  |                                                           |    |
|  |  services[MAX_SERVICES]:                                  |    |
|  |    - name, namespace                                      |    |
|  |    - endpoints[MAX_ENDPOINTS_PER_SERVICE]:               |    |
|  |        - ip (string)                                      |    |
|  |        - port (u16)                                       |    |
|  |                                                           |    |
|  |  secrets[MAX_SECRETS]:                                    |    |
|  |    - name, namespace                                      |    |
|  |    - cert_pem, key_pem                                    |    |
|  +----------------------------------------------------------+    |
|                                                                   |
|  +----------------------------------------------------------+    |
|  |                DATA PLANE CLIENT STATE                    |    |
|  |                                                           |    |
|  |  admin_host, admin_port      - default router target      |    |
|  |  router_endpoints[MAX]       - discovered router pods     |    |
|  |  synced_pod_names[MAX]       - pods with current config   |    |
|  |  last_config_hash            - skip redundant pushes      |    |
|  |  multi_endpoint_mode         - HA mode flag               |    |
|  +----------------------------------------------------------+    |
|                                                                   |
+------------------------------------------------------------------+
```

### Router (Data Plane) State

```
+------------------------------------------------------------------+
|                     ROUTER STATE                                  |
|                                                                   |
|  DOUBLE-BUFFERED STORAGE:                                        |
|                                                                   |
|  +------------------------+    +------------------------+         |
|  |      SLOT 0            |    |      SLOT 1            |         |
|  |  router_storage[0]     |    |  router_storage[1]     |         |
|  |  storage[0]            |    |  storage[1]            |         |
|  |    (ConfigStorage)     |    |    (ConfigStorage)     |         |
|  +------------------------+    +------------------------+         |
|            ^                             ^                        |
|            |                             |                        |
|  +---------+-----------------------------+---------+              |
|  |              ATOMIC POINTERS                    |              |
|  |                                                 |              |
|  |  current_router: ?*Router = &router_storage[X] |              |
|  |  active_slot: u8 = 0 or 1                      |              |
|  |  router_generation: u64 (monotonic counter)    |              |
|  |                                                 |              |
|  +------------------------------------------------+              |
|                                                                   |
|  ConfigStorage contains:                                         |
|    - route_storage[MAX_ROUTES]                                   |
|    - pool_storage[MAX_POOLS]                                     |
|    - upstream_storage[MAX_POOLS][MAX_UPSTREAMS]                  |
|    - string_storage[BYTES] (names, paths, hosts)                 |
|    - allowed_hosts_storage[MAX][MAX_LEN]                         |
|                                                                   |
+------------------------------------------------------------------+
```

### Config Sync Flow (HA Mode)

```
                       CONTROLLER
                           |
         +----------------+|+----------------+
         |                 |                 |
         v                 v                 v
    +--------+        +--------+        +--------+
    |Router 1|        |Router 2|        |Router 3|
    | Pod A  |        | Pod B  |        | Pod C  |
    +--------+        +--------+        +--------+
         ^                 ^                 ^
         |                 |                 |
         +--------+--------+--------+--------+
                  |                 |
          EndpointSlice       Sync Thread
          Discovery           (5s interval)
                  |                 |
                  v                 v
         +-------------------------------------------+
         |        DataPlaneClient State              |
         |                                           |
         |  router_endpoints = [                     |
         |    { ip: "10.0.1.1", port: 9901, pod: A }|
         |    { ip: "10.0.1.2", port: 9901, pod: B }|
         |    { ip: "10.0.1.3", port: 9901, pod: C }|
         |  ]                                        |
         |                                           |
         |  synced_pod_names = [A, B]  <- Pod C new |
         |                                           |
         +-------------------------------------------+

    On config change:
      1. Clear synced_pod_names
      2. Push to ALL endpoints
      3. Record successful pods in synced_pod_names

    On sync interval (new pods):
      1. Refresh endpoints via EndpointSlice API
      2. Compare pod names (not IPs - IPs can be reused)
      3. Push ONLY to pods NOT in synced_pod_names
      4. Add successful pods to synced_pod_names
```

---

## Key Code References

### Gateway Controller

| Function | Location | Purpose |
|----------|----------|---------|
| `main()` | `/home/nick/repos/serval/examples/gateway/main.zig:170` | Entry point |
| `run()` | `/home/nick/repos/serval/examples/gateway/main.zig:208` | Main controller loop |
| `onConfigChange()` | `/home/nick/repos/serval/examples/gateway/main.zig:342` | Watcher callback |
| `Controller.create()` | `/home/nick/repos/serval/examples/gateway/controller.zig:128` | Controller initialization |
| `Controller.updateConfig()` | `/home/nick/repos/serval/examples/gateway/controller.zig:311` | Config push orchestration |
| `Watcher.init()` | `/home/nick/repos/serval/examples/gateway/watcher/mod.zig:227` | Watcher initialization |
| `Watcher.start()` | `/home/nick/repos/serval/examples/gateway/watcher/mod.zig:385` | Start watch threads |
| `Watcher.reconcile()` | `/home/nick/repos/serval/examples/gateway/watcher/mod.zig:746` | Build GatewayConfig |
| `handleEvent()` | `/home/nick/repos/serval/examples/gateway/watcher/mod.zig:615` | Process watch event |
| `DataPlaneClient.pushConfig()` | `/home/nick/repos/serval/examples/gateway/data_plane.zig:288` | Push to single router |
| `DataPlaneClient.pushConfigToAll()` | `/home/nick/repos/serval/examples/gateway/data_plane.zig:741` | Push to all routers (HA) |
| `Resolver.updateService()` | `/home/nick/repos/serval/examples/gateway/resolver/mod.zig:137` | Update endpoint data |
| `Resolver.resolveBackend()` | `/home/nick/repos/serval/examples/gateway/resolver/mod.zig:442` | Get backend IPs |
| `K8sClient.watch()` | `/home/nick/repos/serval/examples/gateway/k8s_client/mod.zig:756` | Open watch stream |
| `WatchStream.readEvent()` | `/home/nick/repos/serval/examples/gateway/k8s_client/mod.zig:855` | Read watch event |

### Router (Data Plane)

| Function | Location | Purpose |
|----------|----------|---------|
| `main()` | `/home/nick/repos/serval/examples/router/main.zig:75` | Entry point |
| `AdminHandler.onRequest()` | `/home/nick/repos/serval/examples/router/admin/mod.zig:52` | Admin API routing |
| `handleRouteUpdate()` | `/home/nick/repos/serval/examples/router/admin/routes.zig:37` | Full config replacement |
| `swapRouter()` | `/home/nick/repos/serval/examples/router/config_storage.zig:218` | Atomic config swap |
| `getActiveRouter()` | `/home/nick/repos/serval/examples/router/config_storage.zig:298` | Get current router |
| `ConfigStorage.copyRoutes()` | `/home/nick/repos/serval/examples/router/config_storage.zig:108` | Deep copy routes |

---

## Thread Model

### Gateway Controller Threads

```
Main Thread
    |
    +-- Admin Server Thread (adminServerLoop)
    |       - Serves /healthz, /readyz
    |       - Runs MinimalServer
    |
    +-- Watch Thread 0 (GatewayClass)
    |       - watchThreadLoop(resource_type=.gateway_class)
    |       - Dedicated Io runtime
    |
    +-- Watch Thread 1 (Gateway)
    |       - watchThreadLoop(resource_type=.gateway)
    |       - Dedicated Io runtime
    |
    +-- Watch Thread 2 (HTTPRoute)
    |       - watchThreadLoop(resource_type=.http_route)
    |       - Dedicated Io runtime
    |
    +-- Watch Thread 3 (Service)
    |       - watchThreadLoop(resource_type=.service)
    |       - Dedicated Io runtime
    |
    +-- Watch Thread 4 (Endpoints)
    |       - watchThreadLoop(resource_type=.endpoints)
    |       - Dedicated Io runtime
    |
    +-- Watch Thread 5 (Secret)
    |       - watchThreadLoop(resource_type=.secret)
    |       - Dedicated Io runtime
    |
    +-- Endpoint Sync Thread (HA mode only)
            - runEndpointSyncLoop()
            - 5-second interval
            - Pushes to new router pods
```

### Router Threads

```
Main Thread
    |
    +-- Admin Server Thread
    |       - Handles /healthz, /readyz, /routes/*
    |       - Port 9901
    |
    +-- Request Handler Connections
            - Server.run() accept loop
            - Port 8080
            - Routes requests via RouterHandler
```

---

## TigerStyle Compliance

The codebase follows TigerStyle principles:

1. **Bounded Buffers**: All buffers have explicit size limits (e.g., `MAX_ROUTES=64`, `MAX_LINE_SIZE_BYTES=64KB`)
2. **No Allocation After Init**: All memory allocated at startup, no runtime allocation
3. **Explicit Error Handling**: Every error path handled, no `catch {}`
4. **Bounded Loops**: All loops have explicit iteration limits
5. **Assertions**: ~2 assertions per function (preconditions, postconditions)
6. **Explicit Types**: `u8`, `u16`, `u32` instead of `usize` where bounded
7. **Units in Names**: `timeout_ms`, `size_bytes`, `grace_ns`
