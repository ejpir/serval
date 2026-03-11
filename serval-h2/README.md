# serval-h2

Minimal HTTP/2 (`h2c`) protocol helpers for serval.

## Layer

Layer 1 (Protocol).

## Current Scope

This first slice provides bounded helpers for:
- HTTP/2 frame header parsing/encoding
- SETTINGS frame/payload parsing, validation, and state application
- control-frame parsing/encoding for SETTINGS ACK, PING, WINDOW_UPDATE, RST_STREAM, and GOAWAY
- explicit stream state transitions, per-stream window bookkeeping, and fixed-capacity stream tables
- client connection preface detection
- `Upgrade: h2c` request detection, validation, and `HTTP2-Settings` decoding
- bounded HPACK decoding/encoding including static-table and dynamic-table indexed fields, indexed names, literal header blocks, dynamic-table size updates, and Huffman string decoding
- request-header decoding for stream-aware server/client runtimes
- initial request parsing for h2c prior-knowledge connection routing, including bounded HEADERS+CONTINUATION reassembly
- HTTP/1.1 upgrade-request translation into an upstream prior-knowledge h2c preamble

## Not in this module

- socket ownership
- accept loops
- full stream multiplexing runtime
- HPACK dynamic-table encoding policies (decoder side is bounded and supported)
- full HPACK compression strategy/tuning beyond minimal bounded helpers

The module now provides bounded flow-control and control-frame primitives, but not a complete connection runtime. Those larger pieces remain future work; unsupported features fail closed.
