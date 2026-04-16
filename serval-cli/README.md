# serval-cli

Comptime-generic CLI argument parsing for Serval binaries.

`serval-cli` provides a zero-allocation argument parser with a shared base option set (`--port`, `--debug`, `--config`, `--help`, `--version`) plus binary-specific options through a comptime `Extra` struct.

## Layer

- Layer 5: orchestration
- Responsibility: process-argument parsing and help/version/error presentation for Serval executables
- Non-responsibility: socket/server runtime behavior, routing strategy, or proxy mechanics

## Public API

Top-level exports from [`mod.zig`](/home/nick/repos/serval/serval-cli/mod.zig):

| Export | Purpose |
|---|---|
| `args` | Namespace import for parser implementation (`args.zig`) |
| `Args` | Comptime generic parser type constructor (`Args(comptime Extra: type) type`) |
| `NoExtra` | Empty extra-options struct for binaries with no custom flags |
| `ParseResult` | Parse outcome enum (`ok`, `help`, `version`, `err`) |

## Usage pattern

```zig
const cli = @import("serval-cli");

const Extra = struct {
    backends: []const u8 = "127.0.0.1:8001",
    dry_run: bool = false,
};

var args = cli.Args(Extra).init("my-binary", "0.1.0", std.process.args());
switch (args.parse()) {
    .ok => {},
    .help, .version => return,
    .err => {
        args.printError();
        return error.InvalidArgs;
    },
}
```

## Contracts and invariants

- No runtime allocation in parser operations.
- Parse loop is bounded to `max_iterations` (currently 256 args).
- `init()` asserts non-empty binary name and version string.
- `Args` borrows process argument slices; it does not own or free them.

## File layout

| File | Purpose |
|---|---|
| `mod.zig` | Public re-exports |
| `args.zig` | Generic parser implementation and option decoding |
