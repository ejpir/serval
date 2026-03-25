# serval-filter-sdk

`serval-filter-sdk` is the **public, restricted** surface for user-authored filters.

It intentionally exposes only:
- `FilterContext`
- header/chunk views (`HeaderSliceView`, `HeaderWriteView`)
- bounded `EmitWriter`
- `Decision`
- `verifyFilter` compile-time contract checks

It does **not** expose server, socket, pool, parser, or transport internals.

## Example

```zig
const sdk = @import("serval-filter-sdk");

const MyFilter = struct {
    pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
        _ = self;
        _ = headers;
        ctx.setTag("plugin", "my-filter");
        return .continue_filtering;
    }

    pub fn onResponseChunk(
        self: *@This(),
        ctx: *sdk.FilterContext,
        chunk: sdk.ChunkView,
        emit: *sdk.EmitWriter,
    ) sdk.Decision {
        _ = self;
        _ = ctx;
        emit.emit(chunk.bytes) catch {
            return .{ .reject = .{ .status = 500, .reason = "emit failed" } };
        };
        return .continue_filtering;
    }
};

comptime sdk.verifyFilter(MyFilter);
```

## Writable Header Hooks

Filters may implement writable header hooks:
- `onRequestHeadersWrite(self, ctx, headers: sdk.HeaderWriteView)`
- `onResponseHeadersWrite(self, ctx, headers: sdk.HeaderWriteView)`

`HeaderWriteView` supports bounded mutation:
- `upsert(name, value)` (insert or replace, bounded by fixed header capacity)
- `remove(name)`
- `asReadOnly()` for read-only projection

Limits and behavior:
- No allocation (fixed storage, bounded by core header limits)
- `upsert` returns `error.TooManyHeaders` when capacity is exhausted
- Header names must be non-empty
- Existing read-only hooks (`onRequestHeaders`, `onResponseHeaders`) remain supported
