# serval-grpc

Minimal gRPC protocol helpers for serval.

## Layer

Layer 2 (Infrastructure).

## Current Scope

This first slice provides:
- gRPC request metadata validation (`POST`, `content-type`, `te: trailers`)
- gRPC response metadata validation helper for mandatory `grpc-status`
- 5-byte message envelope parsing/encoding

## Not in this module

- protobuf schemas/codegen
- native gRPC handler lifecycle
- compression codecs
- reflection/health service implementations
