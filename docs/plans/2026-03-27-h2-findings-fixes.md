# H2 Findings Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix five audit findings in the serval-h2 module — two High severity (header-name validation, hop-by-hop bypass), one Medium (WINDOW_UPDATE preface validation), and two Low (dead error variants, oversized buffer requirement).

**Architecture:** All fixes are localized to the serval-h2 module (`request.zig`, `upgrade.zig`, `frame.zig`, `settings.zig`). Each finding gets its own task with TDD steps. Callers in `serval-server` that reference removed error variants need updating too.

**Tech Stack:** Zig 0.16, `zig build test-h2` for h2 unit tests, `zig build` for full compilation check when touching serval-server.

---

### Task 1: Header-name validation — enforce RFC 9110 token chars (Finding 1 — High)

The function `isHeaderNameLowercase` in `request.zig:511-523` only rejects uppercase `A-Z`. It must also reject control characters, spaces, separators, and any byte that is not a valid lowercase RFC 9110 `tchar`. Without this, malformed names like `bad name` or bytes with control characters pass decode and enter routing/header logic.

Valid lowercase tchar bytes: `!#$%&'*+-.0-9^_``a-z|~` plus `:` as pseudo-header prefix (first byte only).

**Files:**
- Modify: `serval-h2/request.zig:511-523`

**Step 1: Write failing tests**

Add these tests at the end of `serval-h2/request.zig` (before the final fuzz test). They use `isHeaderNameLowercase` directly since it's file-private — place them in the same file. Also include one end-to-end `decodeRequestHeaderBlock` test to confirm rejection at the API level.

```zig
test "isHeaderNameLowercase rejects space in header name" {
    try std.testing.expect(!isHeaderNameLowercase("bad name"));
}

test "isHeaderNameLowercase rejects control character in header name" {
    try std.testing.expect(!isHeaderNameLowercase("bad\x00name"));
    try std.testing.expect(!isHeaderNameLowercase("bad\x01name"));
    try std.testing.expect(!isHeaderNameLowercase("bad\x7fname"));
}

test "isHeaderNameLowercase rejects high bytes" {
    try std.testing.expect(!isHeaderNameLowercase("caf\xc3\xa9"));
}

test "isHeaderNameLowercase accepts valid tchar names" {
    try std.testing.expect(isHeaderNameLowercase("content-type"));
    try std.testing.expect(isHeaderNameLowercase("x-request-id"));
    try std.testing.expect(isHeaderNameLowercase("x_underscore"));
    try std.testing.expect(isHeaderNameLowercase("accept"));
    try std.testing.expect(isHeaderNameLowercase(":method"));
    try std.testing.expect(isHeaderNameLowercase(":path"));
}

test "isHeaderNameLowercase accepts all valid tchar specials" {
    try std.testing.expect(isHeaderNameLowercase("!#$%&'*+-.^_`|~"));
}

test "decodeRequestHeaderBlock rejects header with space in name" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "bad name", .value = "value" },
    }, &block_buf);

    try std.testing.expectError(error.InvalidHeaderName, decodeRequestHeaderBlock(block, 1, &request_storage_buf));
}
```

**Step 2: Run tests to verify the new ones fail**

Run: `zig build test-h2 2>&1`
Expected: FAIL — "rejects space", "rejects control character", "rejects high bytes", and "decodeRequestHeaderBlock rejects header with space in name" all fail because current code only checks uppercase.

**Step 3: Replace `isHeaderNameLowercase` with RFC-valid tchar check**

Replace the function body at `request.zig:511-523` with:

```zig
fn isHeaderNameLowercase(name: []const u8) bool {
    assert(name.len <= config.H2_MAX_HEADER_BLOCK_SIZE_BYTES);

    if (name.len == 0) return false;

    // ':' prefix is valid for pseudo-headers only; the remaining chars
    // must all be lowercase tchar (RFC 9110 Section 5.6.2, lowered for h2).
    const start: usize = if (name[0] == ':') 1 else 0;
    if (start == 1 and name.len == 1) return false; // bare ':' is invalid

    for (name[start..]) |c| {
        if (!is_valid_header_name_char[c]) return false;
    }
    return true;
}

const is_valid_header_name_char = comptime blk: {
    var table = [_]bool{false} ** 256;
    // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
    //         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA (lowercase only for h2)
    for ("!#$%&'*+-.^_`|~") |ch| {
        table[ch] = true;
    }
    for ('0'..'9' + 1) |ch| {
        table[ch] = true;
    }
    for ('a'..'z' + 1) |ch| {
        table[ch] = true;
    }
    break :blk table;
};
```

Note: We keep the function name `isHeaderNameLowercase` to avoid unnecessary churn — the existing name is used at exactly one callsite (line 316) and in existing tests.

**Step 4: Run tests to verify all pass**

Run: `zig build test-h2 2>&1`
Expected: PASS — all existing and new tests pass.

**Step 5: Commit**

```bash
git add serval-h2/request.zig
git commit -m "fix(h2): enforce RFC 9110 tchar validity in header-name check

isHeaderNameLowercase previously only rejected uppercase A-Z.
Now rejects spaces, control bytes, high bytes, and non-tchar
separators using a comptime lookup table."
```

---

### Task 2: Remove 64-token cutoff in `headerHasToken` (Finding 2 — High)

`headerHasToken` in `upgrade.zig:285-298` stops scanning after 64 comma-separated tokens. An attacker can pad the `Connection` header with >64 junk tokens so that real hop-by-hop header names (positioned after the 64th token) are missed by `shouldForwardHeader`, causing them to be forwarded upstream.

The fix: remove the artificial limit. The value is already bounded by the request parser's max header value size, so iterating all tokens is safe.

**Files:**
- Modify: `serval-h2/upgrade.zig:285-298`

**Step 1: Write failing test**

Add at the end of `serval-h2/upgrade.zig` (after existing tests):

```zig
test "headerHasToken finds token beyond 64th position" {
    // Build a Connection value: 70 "junk" tokens followed by "x-secret".
    var buf: [1024]u8 = undefined;
    var cursor: usize = 0;
    for (0..70) |i| {
        if (i > 0) {
            buf[cursor] = ',';
            cursor += 1;
        }
        @memcpy(buf[cursor..][0..4], "junk");
        cursor += 4;
    }
    @memcpy(buf[cursor..][0..9], ",x-secret");
    cursor += 9;
    try std.testing.expect(headerHasToken(buf[0..cursor], "x-secret"));
}
```

**Step 2: Run test to verify it fails**

Run: `zig build test-h2 2>&1`
Expected: FAIL — `headerHasToken` returns `false` because the target is after position 64.

**Step 3: Remove the token limit**

Replace `headerHasToken` at `upgrade.zig:285-298` with:

```zig
fn headerHasToken(value: []const u8, token: []const u8) bool {
    assert(token.len > 0);
    assert(token.len <= config.H2_MAX_HEADER_BLOCK_SIZE_BYTES);

    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        if (eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}
```

**Step 4: Run tests to verify all pass**

Run: `zig build test-h2 2>&1`
Expected: PASS

**Step 5: Commit**

```bash
git add serval-h2/upgrade.zig
git commit -m "fix(h2): remove 64-token cutoff in Connection header parsing

headerHasToken had a hard limit of 64 tokens. Tokens past
that position were silently ignored, allowing an attacker to
bypass hop-by-hop header stripping in shouldForwardHeader."
```

---

### Task 3: Validate WINDOW_UPDATE increment in preface parser (Finding 3 — Medium)

`parseInitialFrame` at `request.zig:127` only checks that WINDOW_UPDATE has a 4-byte payload. It does not parse the increment value or reject a zero increment, which is a PROTOCOL_ERROR per RFC 9113 Section 6.9. Additionally, `control.parseWindowUpdateFrame` already implements full validation (zero check, bounds check via `H2_MAX_WINDOW_SIZE_BYTES`). Reuse it instead of duplicating logic inline.

**Files:**
- Modify: `serval-h2/request.zig:1` (add `control` import)
- Modify: `serval-h2/request.zig:127`

**Step 1: Write failing test**

Add a new test after the existing preface tests (near the other `parseInitialRequest` tests):

```zig
test "parseInitialRequest rejects WINDOW_UPDATE with zero increment" {
    // Build: client preface + SETTINGS frame + WINDOW_UPDATE(stream=0, increment=0)
    const client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    // Empty SETTINGS frame: length=0, type=4(settings), flags=0, stream=0
    const settings_frame = [_]u8{ 0, 0, 0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
    // WINDOW_UPDATE: length=4, type=8, flags=0, stream=0, increment=0
    const wu_frame = [_]u8{ 0, 0, 4, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    var input: [client_preface.len + settings_frame.len + wu_frame.len]u8 = undefined;
    @memcpy(input[0..client_preface.len], client_preface);
    @memcpy(input[client_preface.len..][0..settings_frame.len], &settings_frame);
    @memcpy(input[client_preface.len + settings_frame.len ..][0..wu_frame.len], &wu_frame);

    var storage: [request_stable_storage_size_bytes]u8 = undefined;
    try std.testing.expectError(error.InvalidFrame, parseInitialRequest(&input, &storage));
}
```

**Step 2: Run test to verify it fails**

Run: `zig build test-h2 2>&1`
Expected: FAIL — parser returns `null` (accepts the frame) instead of `error.InvalidFrame`.

**Step 3: Add import and delegate to `control.parseWindowUpdateFrame`**

First, add the import at `request.zig:19` (after the `preface` import):

```zig
const control = @import("control.zig");
```

Then replace line 127 in `request.zig`:

```zig
        // Before (line 127):
        .window_update => if (header.length != 4) return error.InvalidFrame,

        // After:
        .window_update => {
            _ = control.parseWindowUpdateFrame(header, payload) catch return error.InvalidFrame;
        },
```

This delegates to `control.parseWindowUpdateFrame` which validates payload length (4 bytes), masks the reserved bit, rejects zero increments, and checks bounds against `H2_MAX_WINDOW_SIZE_BYTES`. All `control.Error` variants are mapped to the existing `error.InvalidFrame` since the initial parser treats any malformed preface frame as a protocol error.

**Step 4: Run tests to verify all pass**

Run: `zig build test-h2 2>&1`
Expected: PASS

**Step 5: Commit**

```bash
git add serval-h2/request.zig
git commit -m "fix(h2): reject WINDOW_UPDATE with zero increment in preface

Delegate to control.parseWindowUpdateFrame for full RFC 9113
Section 6.9 validation (zero check, window size bounds) instead
of only checking payload length."
```

---

### Task 4: Remove dead error variants (Finding 4 — Low)

`frame.Error.InvalidFrameType` and `frame.Error.ReservedBitSet` are never returned by any code path. `settings.Error.InvalidFrameType` is also never returned — `validateFrame` asserts the frame type rather than validating it at runtime. Per RFC 9113, unknown frame types map to `.extension` and the reserved stream-ID bit is silently masked — both are correct behavior, making these error variants dead code.

Note: `request.Error.UnsupportedPriority` is listed in the finding but is actively used by `serval-client/h2/runtime.zig:270,370` and `serval-server/h2/server.zig:2197`. It stays.

**Files:**
- Modify: `serval-h2/frame.zig:39-45` — remove `InvalidFrameType`, `ReservedBitSet`
- Modify: `serval-h2/settings.zig:51-61` — remove `InvalidFrameType`
- Modify: `serval-h2/request.zig:1278,1305` — remove corresponding arms from fuzz test switch
- Modify: `serval-server/h2/server.zig:2200` — remove `error.InvalidFrameType` arm

**Step 1: Remove `InvalidFrameType` and `ReservedBitSet` from `frame.Error`**

In `serval-h2/frame.zig:39-45`, change:

```zig
pub const Error = error{
    NeedMoreData,
    InvalidFrameType,
    ReservedBitSet,
    FrameTooLarge,
    BufferTooSmall,
};
```

to:

```zig
pub const Error = error{
    NeedMoreData,
    FrameTooLarge,
    BufferTooSmall,
};
```

**Step 2: Remove `InvalidFrameType` from `settings.Error`**

In `serval-h2/settings.zig:52`, remove the `InvalidFrameType,` line from the Error set:

```zig
pub const Error = error{
    InvalidStreamId,
    InvalidPayloadLength,
    AckMustBeEmpty,
    TooManySettings,
    BufferTooSmall,
    InvalidEnablePush,
    InvalidInitialWindowSize,
    InvalidMaxFrameSize,
};
```

**Step 3: Remove dead arms from fuzz test switch in `request.zig`**

In `serval-h2/request.zig`, remove these two lines from the fuzz test error switch (~line 1278 and ~1305):

```zig
                error.InvalidFrameType,
```
```zig
                error.ReservedBitSet,
```

**Step 4: Remove dead arm from server error mapping**

In `serval-server/h2/server.zig:2200`, remove:

```zig
        error.InvalidFrameType,
```

**Step 5: Run full compilation and h2 tests**

Run: `zig build test-h2 2>&1 && zig build 2>&1`
Expected: PASS — no code was returning these errors, so removing them changes no behavior. The `zig build` confirms serval-server compiles with the removed error arm.

**Step 6: Commit**

```bash
git add serval-h2/frame.zig serval-h2/settings.zig serval-h2/request.zig serval-server/h2/server.zig
git commit -m "fix(h2): remove dead error variants InvalidFrameType and ReservedBitSet

These errors were declared but never returned. Unknown frame types
correctly map to .extension and the reserved stream-ID bit is
correctly masked per RFC 9113."
```

---

### Task 5: Tighten upgrade settings buffer requirement (Finding 5 — Low)

`validateUpgradeRequest` at `upgrade.zig:69` asserts `decoded_settings_out.len >= H2_MAX_FRAME_SIZE_BYTES` (16,384 bytes). The actual maximum valid SETTINGS payload is `H2_MAX_SETTINGS_PER_FRAME * setting_size_bytes` = 32 x 6 = 192 bytes. This 85x overallocation adds unnecessary stack pressure at callsites.

**Files:**
- Modify: `serval-h2/upgrade.zig:22,69,149,155` — add constant, tighten asserts and validation bound
- Modify: `serval-h2/upgrade.zig:332,348` — update test buffer sizes
- Modify: `serval-h2/mod.zig` — export the constant
- Modify: `serval-server/h1/server.zig:2958` — update caller buffer size

**Step 1: Define the tight constant and mark it `pub`**

At the top of `upgrade.zig` (after the existing imports, around line 22), add:

```zig
pub const max_settings_payload_bytes = config.H2_MAX_SETTINGS_PER_FRAME * settings.setting_size_bytes;
```

It must be `pub` so `mod.zig` can re-export it.

**Step 2: Update `decodeSettingsValue`**

In `decodeSettingsValue` (line 148-161), replace the two `H2_MAX_FRAME_SIZE_BYTES` references:

```zig
fn decodeSettingsValue(value: []const u8, out: []u8) Error![]const u8 {
    assert(out.len >= max_settings_payload_bytes);
    assert(settings.setting_size_bytes == 6);

    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(value) catch {
        return error.InvalidHttp2Settings;
    };
    if (decoded_len > max_settings_payload_bytes) return error.InvalidHttp2Settings;
    if (decoded_len % 6 != 0) return error.InvalidSettingsPayload;

    std.base64.url_safe_no_pad.Decoder.decode(out[0..decoded_len], value) catch {
        return error.InvalidHttp2Settings;
    };
    return out[0..decoded_len];
}
```

**Step 3: Update `validateUpgradeRequest` assert**

In `validateUpgradeRequest` (line 69), replace:

```zig
    assert(decoded_settings_out.len >= config.H2_MAX_FRAME_SIZE_BYTES);
```

with:

```zig
    assert(decoded_settings_out.len >= max_settings_payload_bytes);
```

**Step 4: Update test buffer sizes in `upgrade.zig`**

In both tests that declare `var decoded_buf: [config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined;` (lines 332 and 348), replace with:

```zig
    var decoded_buf: [max_settings_payload_bytes]u8 = undefined;
```

**Step 5: Export from `mod.zig`**

Add to `serval-h2/mod.zig` after line 86 (in the upgrade section):

```zig
pub const max_settings_payload_bytes = upgrade.max_settings_payload_bytes;
```

**Step 6: Update caller buffer in `serval-server/h1/server.zig`**

At line 2958, replace:

```zig
                var h2c_upgrade_settings_buf: [config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined;
```

with:

```zig
                var h2c_upgrade_settings_buf: [serval_h2.max_settings_payload_bytes]u8 = undefined;
```

**Step 7: Run full compilation and h2 tests**

Run: `zig build test-h2 2>&1 && zig build 2>&1`
Expected: PASS. The `zig build` confirms serval-server compiles against the tightened buffer size.

**Step 8: Commit**

```bash
git add serval-h2/upgrade.zig serval-h2/mod.zig serval-server/h1/server.zig
git commit -m "fix(h2): tighten upgrade settings buffer from 16KiB to 192B

The decoded SETTINGS payload is bounded by MAX_SETTINGS_PER_FRAME
(32) * 6 bytes = 192 bytes. The previous H2_MAX_FRAME_SIZE_BYTES
(16,384) requirement was 85x larger than needed."
```
