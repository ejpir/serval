## 1. grpc-status semantics hardening

- [x] 1.1 Add parsed `grpc-status` helper API returning bounded status code.
- [x] 1.2 Extend `MetadataError` taxonomy for format vs range failure.
- [x] 1.3 Update `requireGrpcStatus()` to use semantic validation.
- [x] 1.4 Add unit tests for empty, non-digit, overflow, boundary, and out-of-range values.

## 2. strict metadata validation profile

- [x] 2.1 Add `validateRequestStrict()` with explicit stricter checks.
- [x] 2.2 Keep `validateRequest()` compatibility behavior unchanged unless explicitly intended.
- [x] 2.3 Add table-driven tests for content-type and TE grammar edge cases.
- [x] 2.4 Document strict vs compatibility behavior in `serval-grpc/README.md`.

## 3. wire frame scan helpers

- [x] 3.1 Add allocation-free frame-length/scanner helpers for multiple frames in one buffer.
- [x] 3.2 Ensure truncation returns `NeedMoreData` consistently.
- [x] 3.3 Add property/fuzz tests: parser never panics on arbitrary byte slices.
- [x] 3.4 Add boundary tests for zero-length, max-length, and max+1 payload behavior.

## 4. request classification integration

- [x] 4.1 Add `classifyRequest()` helper to `serval-grpc`.
- [x] 4.2 Replace ad-hoc gRPC request checks in `serval-server` with classification helper.
- [x] 4.3 Replace ad-hoc gRPC request checks in `serval-proxy` with classification helper.
- [x] 4.4 Add integration tests for mixed gRPC/non-gRPC streams sharing same h2 connection.

## 5. docs + architecture consistency

- [ ] 5.1 Align `serval/ARCHITECTURE.md` dependency note for `serval-grpc` with actual build imports.
- [ ] 5.2 Update `serval-grpc/README.md` contracts and error semantics.
- [ ] 5.3 Verify root `README.md` gRPC behavior text remains accurate.
- [ ] 5.4 Run and record verification commands (`zig build`, `zig build test`, `zig build test-grpc`).

## 6. PR slicing (recommended)

- [ ] PR1: `grpc-status` semantics + tests + README updates.
- [ ] PR2: strict metadata validation + grammar tests.
- [ ] PR3: wire frame scan helpers + fuzz/property tests.
- [ ] PR4: server/proxy classification integration + integration tests.
- [ ] PR5: doc/architecture cleanup + full verification pass.
