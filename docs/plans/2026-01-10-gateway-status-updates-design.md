# Gateway Status Updates Design

## Overview

Implement Gateway API status updates so the controller writes status conditions back to Kubernetes, indicating whether Gateways are accepted and programmed.

## Requirements

1. **Full Gateway API spec compliance** for status conditions:
   - Gateway-level: `Accepted`, `Programmed`
   - Listener-level: `Accepted`, `Programmed`, `ResolvedRefs`

2. **GatewayClass support** - filter Gateways by GatewayClass.spec.controllerName

3. **Update on every reconcile** - ensures status always reflects current state

4. **Configurable controller name** via `--controller-name` CLI flag

## Design

### Status Types

Add to `serval-k8s-gateway/config.zig`:

```zig
pub const GatewayClass = struct {
    name: []const u8,            // metadata.name (cluster-scoped)
    controller_name: []const u8, // spec.controllerName
};

pub const GatewayClassStatus = struct {
    conditions: []const Condition,
};

pub const GatewayStatus = struct {
    conditions: []const Condition,
    listeners: []const ListenerStatus,
};

pub const ListenerStatus = struct {
    name: []const u8,
    attached_routes: u32,
    conditions: []const Condition,
};

pub const Condition = struct {
    type: ConditionType,
    status: ConditionStatus,
    reason: []const u8,
    message: []const u8,
    last_transition_time: []const u8,  // RFC3339
    observed_generation: i64,
};

pub const ConditionType = enum {
    Accepted,
    Programmed,
    ResolvedRefs,
};

pub const ConditionStatus = enum { True, False, Unknown };
```

### K8s Client PATCH Support

Add to `examples/gateway/k8s_client/mod.zig`:

```zig
/// PATCH the status subresource of a resource.
/// Uses JSON Merge Patch (application/merge-patch+json).
pub fn patchStatus(
    self: *Self,
    resource_path: []const u8,
    status_json: []const u8,
    io: Io,
) ClientError!void
```

- HTTP PATCH with `Content-Type: application/merge-patch+json`
- Path format: `/apis/gateway.networking.k8s.io/v1/namespaces/{ns}/gateways/{name}/status`
- Map HTTP 409 (Conflict) to retriable error

### Status Manager

New file `examples/gateway/status.zig`:

```zig
pub const StatusManager = struct {
    allocator: std.mem.Allocator,
    k8s_client: *K8sClient,
    controller_name: []const u8,

    // Pre-allocated buffers (TigerStyle)
    json_buffer: [MAX_STATUS_JSON_SIZE]u8,
    path_buffer: [MAX_PATH_SIZE]u8,

    pub fn updateGatewayStatus(
        self: *Self,
        gateway: *const Gateway,
        namespace: []const u8,
        result: ReconcileResult,
        io: Io,
    ) ClientError!void;

    pub fn updateGatewayClassStatus(
        self: *Self,
        gateway_class: *const GatewayClass,
        io: Io,
    ) ClientError!void;
};
```

**JSON serialization** uses `std.json.stringify` with structs matching K8s API shape:

```zig
const GatewayStatusJson = struct {
    status: struct {
        conditions: []const ConditionJson,
        listeners: []const ListenerStatusJson,
    },
};

const ConditionJson = struct {
    type: []const u8,
    status: []const u8,  // "True", "False", "Unknown"
    reason: []const u8,
    message: []const u8,
    lastTransitionTime: []const u8,
    observedGeneration: i64,
};
```

### GatewayClass Filtering

Watcher filters Gateways by GatewayClass:

```zig
fn reconcile(self: *Self) !GatewayConfig {
    // 1. Find GatewayClasses matching our controller name
    const our_classes = self.findMatchingGatewayClasses();

    // 2. Filter Gateways that reference our GatewayClasses
    for (self.parsed_gateways) |gw| {
        if (self.gatewayClassMatches(gw.gateway_class_name, our_classes)) {
            // Include this gateway
        }
    }
}
```

### Controller Integration

Status update flow:

```
Watcher detects change
    ↓
triggerReconciliation()
    ↓
reconcile() builds GatewayConfig (filtered by GatewayClass)
    ↓
onConfigChange callback → Controller.updateConfig()
    ↓
StatusManager.updateGatewayClassStatus() for matching classes
    ↓
StatusManager.updateGatewayStatus() for each Gateway
    ↓
PATCH to K8s API
```

Status updates are best-effort - failures are logged but don't fail reconciliation.

### CLI Configuration

Add to `examples/gateway/main.zig`:

```zig
const CliConfig = struct {
    // ... existing fields ...
    controller_name: []const u8 = "serval.dev/gateway-controller",
};
```

Usage:
```bash
./gateway --controller-name "serval.dev/gateway-controller"
```

## Files Changed

**New files:**
| File | Purpose |
|------|---------|
| `examples/gateway/status.zig` | StatusManager, JSON serialization, PATCH logic |

**Modified files:**
| File | Changes |
|------|---------|
| `serval-k8s-gateway/config.zig` | Add GatewayClass, GatewayStatus, Condition types |
| `examples/gateway/k8s_client/mod.zig` | Add `patchStatus()` method |
| `examples/gateway/watcher/types.zig` | Add StoredGatewayClass, MAX_GATEWAY_CLASSES |
| `examples/gateway/watcher/mod.zig` | Watch GatewayClass, filter Gateways by class |
| `examples/gateway/watcher/parsing.zig` | Add parseGatewayClassJson() |
| `examples/gateway/controller.zig` | Add StatusManager, call status updates |
| `examples/gateway/main.zig` | Add `--controller-name` CLI flag |

## Constants (TigerStyle bounds)

```zig
pub const MAX_GATEWAY_CLASSES: u8 = 8;
pub const MAX_STATUS_JSON_SIZE: u32 = 4096;
pub const MAX_CONDITIONS: u8 = 8;
pub const MAX_REASON_LEN: u8 = 64;
pub const MAX_MESSAGE_LEN: u16 = 256;
```

## Testing

- Unit tests for status JSON serialization
- Unit tests for GatewayClass filtering logic
- Integration test: mock K8s API, verify PATCH calls

## Condition Semantics

### GatewayClass Conditions
| Condition | True | False |
|-----------|------|-------|
| Accepted | Controller is watching this class | Never (we only update classes we accept) |

### Gateway Conditions
| Condition | True | False |
|-----------|------|-------|
| Accepted | Config is syntactically valid | Invalid spec (bad listener config, etc.) |
| Programmed | Config pushed to data plane | Data plane push failed |

### Listener Conditions
| Condition | True | False |
|-----------|------|-------|
| Accepted | Listener config is valid | Invalid port, protocol, etc. |
| Programmed | Listener is active on data plane | Data plane rejected listener |
| ResolvedRefs | TLS secrets exist and are valid | Missing or invalid certificate |
