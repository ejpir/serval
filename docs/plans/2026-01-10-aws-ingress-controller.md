# AWS Ingress Controller Implementation Plan

**Status:** Planned
**Created:** 2026-01-10
**Goal:** Complete ingress controller that eliminates ALB/NLB by using Route53 + Elastic IPs

## Overview

Build a complete Kubernetes ingress controller in pure Zig that:
1. Watches Gateway API resources (Gateway, HTTPRoute, Service, Endpoints, Nodes)
2. Manages AWS resources (Elastic IPs, Route53 records, health checks)
3. Pushes routing config to serval-router data plane pods

```
CDN (Akamai, etc.)
        │
        ▼
origin.example.com (Route53)
        │
        ▼ resolves to healthy EIPs
┌───────┴───────┐
▼               ▼
Node 1 EIP    Node 2 EIP
serval-router serval-router
        │
        ▼
   Backend Pods
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           serval-gateway                                     │
│                          (Control Plane)                                     │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Reconciler                                   │   │
│  │                                                                      │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────────┐│   │
│  │  │K8s Watcher│  │  Route53  │  │    EIP    │  │   Config Pusher   ││   │
│  │  │           │  │  Manager  │  │  Manager  │  │                   ││   │
│  │  │- Gateway  │  │           │  │           │  │- Push to routers  ││   │
│  │  │- HTTPRoute│  │- A records│  │- Allocate │  │- Atomic swap      ││   │
│  │  │- Service  │  │- Health   │  │- Attach   │  │- Retry w/ backoff ││   │
│  │  │- Endpoints│  │  checks   │  │- Release  │  │                   ││   │
│  │  │- Nodes    │  │- TTL mgmt │  │- Pool     │  │                   ││   │
│  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────────┬─────────┘│   │
│  │        │              │              │                  │          │   │
│  │        └──────────────┴──────────────┴──────────────────┘          │   │
│  │                              │                                      │   │
│  │                    Reconciliation Loop                              │   │
│  │                              │                                      │   │
│  └──────────────────────────────┼──────────────────────────────────────┘   │
│                                 │                                          │
│                    Desired State vs Current State                          │
│                                 │                                          │
└─────────────────────────────────┼──────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
   ┌─────────┐              ┌─────────┐              ┌─────────┐
   │ Route53 │              │   EC2   │              │ Routers │
   │         │              │  EIPs   │              │  :9901  │
   └─────────┘              └─────────┘              └─────────┘
```

## File Structure

```
serval-gateway/
├── mod.zig                      # Public exports
├── gateway.zig                  # ✅ EXISTS - Main struct, admin API
├── reconciler.zig               # ❌ NEW - Main reconciliation loop
│
├── k8s/
│   ├── mod.zig                  # ✅ EXISTS
│   ├── client.zig               # ✅ EXISTS - K8s HTTP client
│   ├── watcher.zig              # ✅ EXISTS - Gateway/HTTPRoute watcher
│   └── node_watcher.zig         # ❌ NEW - Node event watcher
│
├── aws/
│   ├── mod.zig                  # ❌ NEW - AWS module exports
│   ├── credentials.zig          # ❌ NEW - Credential loading (env, IMDS, file)
│   ├── sigv4.zig                # ❌ NEW - AWS Signature V4 signing
│   ├── client.zig               # ❌ NEW - Base HTTP client for AWS APIs
│   ├── ec2.zig                  # ❌ NEW - EC2 API (EIP operations)
│   ├── route53.zig              # ❌ NEW - Route53 API (records, health checks)
│   └── eip_manager.zig          # ❌ NEW - EIP pool management
│
├── config/
│   ├── mod.zig                  # ✅ EXISTS
│   ├── types.zig                # ✅ EXISTS - Gateway API types
│   └── translator.zig           # ✅ EXISTS - HTTPRoute → Router config
│
└── pusher/
    └── config_pusher.zig        # ❌ NEW - Extract from gateway.zig
```

---

## Phase 1: AWS Foundation

**Goal:** AWS API client with SigV4 signing, credential loading

### 1.1 Credential Loading (`aws/credentials.zig`)

Load AWS credentials in priority order:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. EC2 Instance Metadata Service (IMDS) for pods with IAM roles
3. Shared credentials file (`~/.aws/credentials`)

```zig
pub const Credentials = struct {
    access_key_id: [64]u8,
    access_key_id_len: u8,
    secret_access_key: [64]u8,
    secret_access_key_len: u8,
    session_token: ?[1024]u8,  // For temporary credentials
    session_token_len: u16,
    expiration_ns: ?u64,       // For IMDS credentials that expire

    pub fn loadFromEnvironment() !Credentials;
    pub fn loadFromIMDS(http_client: *HttpClient) !Credentials;
    pub fn loadFromFile(path: []const u8) !Credentials;
    pub fn load(http_client: *HttpClient) !Credentials;  // Try all sources

    pub fn isExpired(self: *const Credentials) bool;
    pub fn needsRefresh(self: *const Credentials) bool;  // Expires within 5 min
};
```

**TigerStyle:**
- Fixed-size buffers for credentials
- Explicit expiration tracking
- No allocation after init

### 1.2 SigV4 Signing (`aws/sigv4.zig`)

AWS Signature Version 4 request signing.

```zig
pub const SigV4Signer = struct {
    credentials: *const Credentials,
    region: [32]u8,
    region_len: u8,
    service: [32]u8,
    service_len: u8,

    /// Sign a request, adding Authorization header
    pub fn sign(
        self: *const SigV4Signer,
        method: []const u8,
        uri: []const u8,
        headers: *HeaderMap,
        body: []const u8,
        timestamp_ns: u64,
    ) !void;
};

// Internal helpers
fn createCanonicalRequest(...) ![]const u8;
fn createStringToSign(...) ![]const u8;
fn calculateSignature(...) ![64]u8;  // HMAC-SHA256 hex
```

**Implementation notes:**
- Use Zig stdlib `std.crypto.auth.hmac.sha2.HmacSha256`
- Use `std.crypto.hash.sha2.Sha256` for payload hash
- Date format: `YYYYMMDD'T'HHMMSS'Z'` (ISO 8601 basic)

### 1.3 AWS HTTP Client (`aws/client.zig`)

Base client for AWS API calls.

```zig
pub const AwsClient = struct {
    http_client: *serval.Client,  // Use serval-client
    credentials: Credentials,
    region: [32]u8,
    region_len: u8,

    pub fn init(allocator: Allocator, region: []const u8) !*AwsClient;
    pub fn deinit(self: *AwsClient) void;

    /// Make signed request to AWS API
    pub fn request(
        self: *AwsClient,
        service: []const u8,        // "ec2", "route53"
        method: []const u8,         // "GET", "POST"
        path: []const u8,
        query: []const u8,
        body: []const u8,
        response_buf: []u8,
    ) !Response;

    /// Refresh credentials if needed (for IMDS)
    pub fn refreshCredentialsIfNeeded(self: *AwsClient) !void;
};
```

### 1.4 Tests for Phase 1

```zig
test "SigV4 signing matches AWS examples" {
    // Use AWS documentation test vectors
    // https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
}

test "Credentials load from environment" {
    // Set env vars, verify loading
}

test "AwsClient makes signed request" {
    // Mock server, verify signature header format
}
```

---

## Phase 2: EC2 EIP Management

**Goal:** Allocate, attach, detach, release Elastic IPs

### 2.1 EC2 API (`aws/ec2.zig`)

```zig
pub const Ec2Client = struct {
    aws: *AwsClient,

    // Elastic IP operations
    pub fn allocateAddress(self: *Ec2Client) !AllocationResult;
    pub fn releaseAddress(self: *Ec2Client, allocation_id: []const u8) !void;
    pub fn associateAddress(
        self: *Ec2Client,
        allocation_id: []const u8,
        instance_id: []const u8,
    ) !AssociationResult;
    pub fn disassociateAddress(self: *Ec2Client, association_id: []const u8) !void;

    // Instance metadata
    pub fn describeInstances(self: *Ec2Client, instance_ids: []const []const u8) ![]Instance;

    // For getting current node's instance ID
    pub fn getInstanceIdFromIMDS(self: *Ec2Client) ![20]u8;
};

pub const AllocationResult = struct {
    allocation_id: [32]u8,
    allocation_id_len: u8,
    public_ip: [16]u8,
    public_ip_len: u8,
};

pub const Instance = struct {
    instance_id: [20]u8,
    instance_id_len: u8,
    private_ip: [16]u8,
    private_ip_len: u8,
    public_ip: ?[16]u8,
    public_ip_len: u8,
    state: InstanceState,
};
```

**EC2 API format:** Query string parameters, XML response

```
POST https://ec2.us-east-1.amazonaws.com/
Content-Type: application/x-www-form-urlencoded

Action=AllocateAddress&Domain=vpc&Version=2016-11-15
```

### 2.2 EIP Pool Manager (`aws/eip_manager.zig`)

Manages a pool of pre-allocated EIPs for fast node attachment.

```zig
pub const EipManager = struct {
    ec2: *Ec2Client,

    // Pool of available EIPs (pre-allocated)
    available: [MAX_EIPS]Eip,
    available_count: u8,

    // Currently attached EIPs
    attached: [MAX_EIPS]AttachedEip,
    attached_count: u8,

    pub const MAX_EIPS: u8 = 20;

    pub fn init(ec2: *Ec2Client) EipManager;

    /// Pre-allocate EIPs to pool
    pub fn warmPool(self: *EipManager, count: u8) !void;

    /// Get EIP from pool and attach to instance
    pub fn attachToInstance(self: *EipManager, instance_id: []const u8) !Eip;

    /// Detach from instance and return to pool (or release)
    pub fn detachFromInstance(self: *EipManager, instance_id: []const u8) !void;

    /// Get EIP for an instance
    pub fn getEipForInstance(self: *const EipManager, instance_id: []const u8) ?Eip;
};

pub const Eip = struct {
    allocation_id: [32]u8,
    allocation_id_len: u8,
    public_ip: [16]u8,
    public_ip_len: u8,
};

pub const AttachedEip = struct {
    eip: Eip,
    instance_id: [20]u8,
    instance_id_len: u8,
    association_id: [32]u8,
    association_id_len: u8,
};
```

---

## Phase 3: Route53 DNS Management

**Goal:** Create/update/delete A records and health checks

### 3.1 Route53 API (`aws/route53.zig`)

```zig
pub const Route53Client = struct {
    aws: *AwsClient,
    hosted_zone_id: [32]u8,
    hosted_zone_id_len: u8,
    hostname: [256]u8,
    hostname_len: u8,
    ttl_seconds: u32,

    pub fn init(
        aws: *AwsClient,
        hosted_zone_id: []const u8,
        hostname: []const u8,
        ttl_seconds: u32,
    ) Route53Client;

    // A Record management
    pub fn upsertARecord(self: *Route53Client, ip: []const u8) !void;
    pub fn deleteARecord(self: *Route53Client, ip: []const u8) !void;
    pub fn listARecords(self: *Route53Client, out: []ARecord) ![]ARecord;

    // Health check management
    pub fn createHealthCheck(
        self: *Route53Client,
        ip: []const u8,
        port: u16,
        path: []const u8,
    ) !HealthCheckId;
    pub fn deleteHealthCheck(self: *Route53Client, health_check_id: []const u8) !void;

    // Associate health check with record (for failover)
    pub fn setHealthCheckForRecord(
        self: *Route53Client,
        ip: []const u8,
        health_check_id: []const u8,
    ) !void;
};

pub const ARecord = struct {
    ip: [16]u8,
    ip_len: u8,
    health_check_id: ?[64]u8,
    health_check_id_len: u8,
};
```

**Route53 API format:** REST with XML body

```
POST /2013-04-01/hostedzone/Z1234567890/rrset HTTP/1.1
Host: route53.amazonaws.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeBatch>
    <Changes>
      <Change>
        <Action>UPSERT</Action>
        <ResourceRecordSet>
          <Name>origin.example.com</Name>
          <Type>A</Type>
          <TTL>60</TTL>
          <ResourceRecords>
            <ResourceRecord>
              <Value>1.2.3.4</Value>
            </ResourceRecord>
          </ResourceRecords>
        </ResourceRecordSet>
      </Change>
    </Changes>
  </ChangeBatch>
</ChangeResourceRecordSetsRequest>
```

### 3.2 XML Builder/Parser

Simple XML handling for Route53 requests/responses.

```zig
// aws/xml.zig

pub const XmlWriter = struct {
    buf: []u8,
    pos: u32,

    pub fn init(buf: []u8) XmlWriter;
    pub fn element(self: *XmlWriter, name: []const u8) !*XmlWriter;
    pub fn text(self: *XmlWriter, content: []const u8) !*XmlWriter;
    pub fn close(self: *XmlWriter) !*XmlWriter;
    pub fn slice(self: *const XmlWriter) []const u8;
};

pub fn extractElement(xml: []const u8, path: []const u8) ?[]const u8;
```

---

## Phase 4: Node Watcher

**Goal:** Watch K8s Node events, track ready nodes with instance IDs

### 4.1 Node Watcher (`k8s/node_watcher.zig`)

```zig
pub const NodeWatcher = struct {
    client: *K8sClient,

    nodes: [MAX_NODES]TrackedNode,
    node_count: u8,

    pub const MAX_NODES: u8 = 64;

    pub fn init(client: *K8sClient) NodeWatcher;

    /// Start watching nodes (blocking)
    pub fn watch(self: *NodeWatcher, on_change: *const fn(*NodeWatcher) void) !void;

    /// Get all ready nodes
    pub fn getReadyNodes(self: *const NodeWatcher, out: []TrackedNode) []TrackedNode;

    /// Get node by name
    pub fn getNode(self: *const NodeWatcher, name: []const u8) ?*TrackedNode;
};

pub const TrackedNode = struct {
    name: [64]u8,
    name_len: u8,

    // From node.spec.providerID: "aws:///us-east-1a/i-1234567890abcdef0"
    instance_id: [20]u8,
    instance_id_len: u8,

    // Node conditions
    ready: bool,

    // Our attached EIP (if any)
    eip: ?[16]u8,
    eip_len: u8,

    active: bool,
};
```

**Extracting instance ID from Node:**

```json
{
  "metadata": {"name": "ip-10-0-1-5.ec2.internal"},
  "spec": {
    "providerID": "aws:///us-east-1a/i-1234567890abcdef0"
  },
  "status": {
    "conditions": [
      {"type": "Ready", "status": "True"}
    ]
  }
}
```

---

## Phase 5: Reconciler

**Goal:** Main reconciliation loop tying everything together

### 5.1 Reconciler (`reconciler.zig`)

```zig
pub const Reconciler = struct {
    // Components
    k8s_watcher: *K8sWatcher,
    node_watcher: *NodeWatcher,
    eip_manager: *EipManager,
    route53: *Route53Client,
    config_pusher: *ConfigPusher,

    // State
    running: std.atomic.Value(bool),
    last_reconcile_ns: u64,

    // Config
    reconcile_interval_ms: u32,

    pub fn init(
        k8s_watcher: *K8sWatcher,
        node_watcher: *NodeWatcher,
        eip_manager: *EipManager,
        route53: *Route53Client,
        config_pusher: *ConfigPusher,
    ) Reconciler;

    /// Main loop - runs until stopped
    pub fn run(self: *Reconciler) void {
        while (self.running.load(.acquire)) {
            self.reconcileOnce() catch |err| {
                log.err("reconcile failed: {}", .{err});
            };

            std.time.sleep(self.reconcile_interval_ms * std.time.ns_per_ms);
        }
    }

    pub fn stop(self: *Reconciler) void {
        self.running.store(false, .release);
    }

    fn reconcileOnce(self: *Reconciler) !void {
        // 1. Reconcile nodes (EIPs + Route53)
        try self.reconcileNodes();

        // 2. Reconcile routes (push config to routers)
        try self.reconcileRoutes();
    }

    fn reconcileNodes(self: *Reconciler) !void {
        const ready_nodes = self.node_watcher.getReadyNodes(&node_buf);
        const current_records = self.route53.listARecords(&record_buf);

        // Nodes that need EIP + Route53 record
        for (ready_nodes) |node| {
            if (node.eip == null) {
                // Attach EIP
                const eip = try self.eip_manager.attachToInstance(node.instance_id);
                node.eip = eip.public_ip;

                // Add Route53 record
                try self.route53.upsertARecord(eip.public_ip);

                // Create health check
                const hc_id = try self.route53.createHealthCheck(eip.public_ip, 80, "/healthz");
                try self.route53.setHealthCheckForRecord(eip.public_ip, hc_id);
            }
        }

        // Records for nodes that no longer exist
        for (current_records) |record| {
            if (!hasNodeWithEip(ready_nodes, record.ip)) {
                try self.route53.deleteARecord(record.ip);
                if (record.health_check_id) |hc_id| {
                    try self.route53.deleteHealthCheck(hc_id);
                }
                try self.eip_manager.detachFromInstance(record.ip);
            }
        }
    }

    fn reconcileRoutes(self: *Reconciler) !void {
        // Get current config from K8s watcher
        const gw_config = try self.k8s_watcher.reconcile();

        // Translate to router config
        const router_config = try translator.translateConfig(&gw_config);

        // Push to all router pods
        for (ready_nodes) |node| {
            if (node.eip) |eip| {
                try self.config_pusher.push(eip, 9901, router_config);
            }
        }
    }
};
```

### 5.2 Config Pusher (`pusher/config_pusher.zig`)

Extract from `gateway.zig`, make reusable:

```zig
pub const ConfigPusher = struct {
    http_client: *serval.Client,
    retry_count: u8,
    retry_delay_ms: u32,

    pub fn push(
        self: *ConfigPusher,
        host: []const u8,
        port: u16,
        config: *const RouterConfig,
    ) !void;
};
```

---

## Phase 6: Main Entry Point

**Goal:** Wire everything together, handle signals

### 6.1 Gateway Main (`examples/gateway_main.zig`)

```zig
pub fn main() !void {
    // Parse config from env/flags
    const config = parseConfig();

    // Initialize components
    var aws_client = try AwsClient.init(allocator, config.aws_region);
    defer aws_client.deinit();

    var ec2 = Ec2Client{ .aws = &aws_client };
    var route53 = Route53Client.init(&aws_client, config.zone_id, config.hostname, 60);
    var eip_manager = EipManager.init(&ec2);

    var k8s_client = try K8sClient.initInCluster(allocator);
    defer k8s_client.deinit();

    var k8s_watcher = try K8sWatcher.init(allocator, &k8s_client, &onConfigChange);
    defer k8s_watcher.deinit();

    var node_watcher = NodeWatcher.init(&k8s_client);

    var config_pusher = ConfigPusher{ .http_client = &http_client };

    var reconciler = Reconciler.init(
        &k8s_watcher,
        &node_watcher,
        &eip_manager,
        &route53,
        &config_pusher,
    );

    // Warm EIP pool
    try eip_manager.warmPool(3);

    // Start watchers in background threads
    const k8s_thread = try k8s_watcher.start();
    const node_thread = try node_watcher.start();

    // Handle SIGTERM
    setupSignalHandler(&reconciler);

    // Run reconciler (blocks)
    reconciler.run();

    // Cleanup
    k8s_thread.join();
    node_thread.join();
}
```

---

## Phase 7: High Availability

**Goal:** Leader election for running multiple replicas

### 7.1 Leader Election (`ha/leader.zig`)

Use K8s Lease objects for leader election:

```zig
pub const LeaderElector = struct {
    k8s: *K8sClient,
    lease_name: []const u8,
    lease_namespace: []const u8,
    identity: []const u8,  // Pod name

    is_leader: std.atomic.Value(bool),

    pub fn run(self: *LeaderElector) void {
        while (self.running.load(.acquire)) {
            if (self.tryAcquireLease()) {
                self.is_leader.store(true, .release);
                self.renewLease();
            } else {
                self.is_leader.store(false, .release);
            }
            std.time.sleep(LEASE_DURATION_NS / 2);
        }
    }

    pub fn isLeader(self: *const LeaderElector) bool {
        return self.is_leader.load(.acquire);
    }
};
```

---

## Configuration

### Environment Variables

```bash
# AWS
AWS_REGION=us-east-1
# Credentials loaded from IMDS when running in K8s with IAM role

# Route53
ROUTE53_ZONE_ID=Z1234567890
ROUTE53_HOSTNAME=origin.example.com
ROUTE53_TTL=60

# EIP Pool
EIP_POOL_SIZE=5  # Pre-allocate this many EIPs

# Reconciliation
RECONCILE_INTERVAL_MS=5000

# Router Admin API
ROUTER_ADMIN_PORT=9901
```

### IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AllocateAddress",
        "ec2:ReleaseAddress",
        "ec2:AssociateAddress",
        "ec2:DisassociateAddress",
        "ec2:DescribeAddresses",
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:ChangeResourceRecordSets",
        "route53:ListResourceRecordSets"
      ],
      "Resource": "arn:aws:route53:::hostedzone/Z1234567890"
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:CreateHealthCheck",
        "route53:DeleteHealthCheck",
        "route53:GetHealthCheck"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Testing Strategy

### Unit Tests
- SigV4 signing against AWS test vectors
- XML building/parsing
- EIP pool management logic
- Reconciler state machine

### Integration Tests
- Mock AWS API server
- Verify correct API calls made
- Test error handling and retries

### E2E Tests (k3s + LocalStack)
- Full flow with LocalStack for AWS APIs
- Create Gateway/HTTPRoute, verify Route53 records created
- Kill node, verify Route53 record removed

---

## Success Criteria

1. **Functional:** CDN can reach backends via Route53 → EIPs → serval-router
2. **Reliable:** Nodes can come and go, Route53 stays in sync
3. **Fast:** Config updates < 100ms, Route53 updates < 5s
4. **Cost:** No ALB/NLB, only EIPs (~$3.60/mo each) + Route53 (~$0.50/mo)
5. **Observable:** Metrics for reconcile latency, node count, EIP usage

---

## Milestones

| Phase | Deliverable | Estimate |
|-------|-------------|----------|
| 1 | AWS client + SigV4 | - |
| 2 | EC2 EIP management | - |
| 3 | Route53 DNS management | - |
| 4 | Node watcher | - |
| 5 | Reconciler | - |
| 6 | Main entry point | - |
| 7 | Leader election (HA) | - |

---

## Open Questions

1. **EIP limits:** AWS default is 5 EIPs per region. Need to request increase for production.

2. **Multi-region:** How to handle multi-region deployments? Route53 latency routing?

3. **Gradual rollout:** How to do canary deployments of new router versions?

4. **Cost tracking:** Tag EIPs for cost allocation?

5. **Disaster recovery:** What happens if all nodes die? Pre-warm EIPs in pool.
