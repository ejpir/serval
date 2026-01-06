# serval-http

Zero-allocation HTTP/1.1 request and response parser.

## Purpose

Parses HTTP/1.1 requests into structured Request objects and provides response parsing utilities without dynamic memory allocation. Uses fixed-size buffers and slices into the original input.

## Exports

- `Parser` - HTTP/1.1 request parser
- `parser` - Parser module
- `chunked` - Chunked transfer encoding module
- `parseStatusCode` - Parse HTTP status code from response line
- `parseContentLength` - Parse Content-Length header from raw header block
- `parseContentLengthValue` - Parse Content-Length value string to u64
- `ChunkParser` - Zero-allocation chunked body parser

## Usage

### Request Parsing

```zig
const http = @import("serval-http");

var parser = http.Parser.init();
parser.parseHeaders(raw_bytes[0..n]) catch |err| {
    // Handle parse error
};

// Access parsed request
const method = parser.request.method;
const path = parser.request.path;
const host = parser.request.headers.get("Host");
```

### Response Parsing

```zig
const http = @import("serval-http");

// Parse status code from response line
const status = http.parseStatusCode("HTTP/1.1 200 OK\r\n...") orelse {
    // Invalid response format
};

// Parse Content-Length from raw headers
const content_length = http.parseContentLength(header_buffer[0..header_len]);

// Parse Content-Length value directly
const cl_value = http.parseContentLengthValue("12345") orelse {
    // Invalid value (empty, non-numeric, overflow, or leading zeros)
};
```

## Features

- Request line parsing (method, path, version)
- Header parsing into fixed-size HeaderMap
- Response status code parsing
- Content-Length header extraction and validation
- Leading zero rejection for Content-Length (TigerStyle)
- Zero-copy (slices into input buffer)

## Implementation Status

| Feature | Status |
|---------|--------|
| Request line parsing | Complete |
| Header parsing | Complete |
| Response status code | Complete |
| Content-Length parsing | Complete |
| Transfer-Encoding chunked | Implemented |
| Request body reading | Handled by forwarder |

## Limits

- Max 64 headers
- Max 8KB header section
- Max 8KB URI length
- Content-Length max: u64 (18446744073709551615)

## TigerStyle Compliance

- Fixed buffer sizes with compile-time constants
- Zero allocation during parsing
- Explicit error handling
- Assertions for preconditions
- Bounded loops with iteration limits
- Leading zeros rejected in Content-Length values
