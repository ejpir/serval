# serval-grpc

Minimal gRPC protocol helpers for serval.

## Layer

Layer 2 (Infrastructure).

## Current Scope

This module currently provides bounded protocol helpers:
- gRPC request metadata validation (`POST`, `content-type`, `te: trailers`)
- gRPC response metadata validation helper for mandatory `grpc-status`
- 5-byte message envelope parsing/encoding

## Status

- Native gRPC endpoints are **not implemented yet** (high priority).
- `serval-grpc` remains transport/helper-only; it does not own a server-side
  service/method registration or handler lifecycle.

## Not in this module

- protobuf schemas/codegen
- native gRPC handler lifecycle
- compression codecs
- reflection/health service implementations
