//! HPACK Huffman Decoder
//!
//! RFC 7541 Appendix B canonical Huffman code table.
//! TigerStyle: bounded decode, fixed tables, no allocation.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    InvalidHuffman,
    BufferTooSmall,
};

const max_symbol_count: usize = 256;
const max_code_len_bits: u8 = 30;
const max_node_count: usize = 8192;

const Node = struct {
    left: i16 = -1,
    right: i16 = -1,
    symbol: i16 = -1,
};

const Trie = struct {
    nodes: [max_node_count]Node,
    count: u16,
};

const trie: Trie = buildTrie();

pub fn decode(input: []const u8, out: []u8) Error![]const u8 {
    assert(out.len > 0 or input.len == 0);
    assert(trie.count > 0);

    var node_index: u16 = 0;
    var out_len: usize = 0;
    var bits_since_symbol: u8 = 0;
    var trailing_ones: u8 = 0;

    for (input) |byte| {
        var shift: u8 = 8;
        while (shift > 0) {
            shift -= 1;
            const bit: u1 = @intCast((byte >> @intCast(shift)) & 0x1);
            const node = trie.nodes[node_index];
            const next: i16 = if (bit == 0) node.left else node.right;
            if (next < 0) return error.InvalidHuffman;
            node_index = @intCast(next);

            bits_since_symbol += 1;
            if (bit == 1) {
                if (trailing_ones < 7) {
                    trailing_ones += 1;
                }
            } else {
                trailing_ones = 0;
            }

            const symbol = trie.nodes[node_index].symbol;
            if (symbol >= 0) {
                if (out_len >= out.len) return error.BufferTooSmall;
                out[out_len] = @intCast(symbol);
                out_len += 1;
                node_index = 0;
                bits_since_symbol = 0;
                trailing_ones = 0;
            }
        }
    }

    if (node_index != 0) {
        if (bits_since_symbol == 0) return error.InvalidHuffman;
        if (bits_since_symbol > 7) return error.InvalidHuffman;
        if (trailing_ones != bits_since_symbol) return error.InvalidHuffman;
    }

    return out[0..out_len];
}

fn buildTrie() Trie {
    assert(max_symbol_count == 256);
    assert(max_code_len_bits == 30);

    @setEvalBranchQuota(20_000);

    var nodes = [_]Node{.{}} ** max_node_count;
    var next_index: u16 = 1;

    var symbol: usize = 0;
    while (symbol < max_symbol_count) : (symbol += 1) {
        const code = huffman_codes[symbol];
        const code_len = huffman_code_len[symbol];

        if (code_len == 0 or code_len > max_code_len_bits) {
            @compileError("invalid HPACK Huffman code length table");
        }

        var node_index: u16 = 0;
        var bit_index: u8 = 0;
        while (bit_index < code_len) : (bit_index += 1) {
            const shift: u5 = @intCast(code_len - 1 - bit_index);
            const bit: u1 = @intCast((code >> shift) & 0x1);

            const edge: *i16 = if (bit == 0)
                &nodes[node_index].left
            else
                &nodes[node_index].right;

            if (edge.* < 0) {
                if (next_index >= max_node_count) {
                    @compileError("HPACK Huffman trie node capacity exceeded");
                }
                edge.* = @intCast(next_index);
                next_index += 1;
            }

            node_index = @intCast(edge.*);
        }

        if (nodes[node_index].left >= 0 or nodes[node_index].right >= 0) {
            @compileError("HPACK Huffman code collides with existing prefix");
        }
        if (nodes[node_index].symbol >= 0) {
            @compileError("duplicate HPACK Huffman code");
        }
        nodes[node_index].symbol = @intCast(symbol);
    }

    return .{
        .nodes = nodes,
        .count = next_index,
    };
}

const huffman_codes = [256]u32{
    0x1ff8,
    0x7fffd8,
    0xfffffe2,
    0xfffffe3,
    0xfffffe4,
    0xfffffe5,
    0xfffffe6,
    0xfffffe7,
    0xfffffe8,
    0xffffea,
    0x3ffffffc,
    0xfffffe9,
    0xfffffea,
    0x3ffffffd,
    0xfffffeb,
    0xfffffec,
    0xfffffed,
    0xfffffee,
    0xfffffef,
    0xffffff0,
    0xffffff1,
    0xffffff2,
    0x3ffffffe,
    0xffffff3,
    0xffffff4,
    0xffffff5,
    0xffffff6,
    0xffffff7,
    0xffffff8,
    0xffffff9,
    0xffffffa,
    0xffffffb,
    0x14,
    0x3f8,
    0x3f9,
    0xffa,
    0x1ff9,
    0x15,
    0xf8,
    0x7fa,
    0x3fa,
    0x3fb,
    0xf9,
    0x7fb,
    0xfa,
    0x16,
    0x17,
    0x18,
    0x0,
    0x1,
    0x2,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    0x5c,
    0xfb,
    0x7ffc,
    0x20,
    0xffb,
    0x3fc,
    0x1ffa,
    0x21,
    0x5d,
    0x5e,
    0x5f,
    0x60,
    0x61,
    0x62,
    0x63,
    0x64,
    0x65,
    0x66,
    0x67,
    0x68,
    0x69,
    0x6a,
    0x6b,
    0x6c,
    0x6d,
    0x6e,
    0x6f,
    0x70,
    0x71,
    0x72,
    0xfc,
    0x73,
    0xfd,
    0x1ffb,
    0x7fff0,
    0x1ffc,
    0x3ffc,
    0x22,
    0x7ffd,
    0x3,
    0x23,
    0x4,
    0x24,
    0x5,
    0x25,
    0x26,
    0x27,
    0x6,
    0x74,
    0x75,
    0x28,
    0x29,
    0x2a,
    0x7,
    0x2b,
    0x76,
    0x2c,
    0x8,
    0x9,
    0x2d,
    0x77,
    0x78,
    0x79,
    0x7a,
    0x7b,
    0x7ffe,
    0x7fc,
    0x3ffd,
    0x1ffd,
    0xffffffc,
    0xfffe6,
    0x3fffd2,
    0xfffe7,
    0xfffe8,
    0x3fffd3,
    0x3fffd4,
    0x3fffd5,
    0x7fffd9,
    0x3fffd6,
    0x7fffda,
    0x7fffdb,
    0x7fffdc,
    0x7fffdd,
    0x7fffde,
    0xffffeb,
    0x7fffdf,
    0xffffec,
    0xffffed,
    0x3fffd7,
    0x7fffe0,
    0xffffee,
    0x7fffe1,
    0x7fffe2,
    0x7fffe3,
    0x7fffe4,
    0x1fffdc,
    0x3fffd8,
    0x7fffe5,
    0x3fffd9,
    0x7fffe6,
    0x7fffe7,
    0xffffef,
    0x3fffda,
    0x1fffdd,
    0xfffe9,
    0x3fffdb,
    0x3fffdc,
    0x7fffe8,
    0x7fffe9,
    0x1fffde,
    0x7fffea,
    0x3fffdd,
    0x3fffde,
    0xfffff0,
    0x1fffdf,
    0x3fffdf,
    0x7fffeb,
    0x7fffec,
    0x1fffe0,
    0x1fffe1,
    0x3fffe0,
    0x1fffe2,
    0x7fffed,
    0x3fffe1,
    0x7fffee,
    0x7fffef,
    0xfffea,
    0x3fffe2,
    0x3fffe3,
    0x3fffe4,
    0x7ffff0,
    0x3fffe5,
    0x3fffe6,
    0x7ffff1,
    0x3ffffe0,
    0x3ffffe1,
    0xfffeb,
    0x7fff1,
    0x3fffe7,
    0x7ffff2,
    0x3fffe8,
    0x1ffffec,
    0x3ffffe2,
    0x3ffffe3,
    0x3ffffe4,
    0x7ffffde,
    0x7ffffdf,
    0x3ffffe5,
    0xfffff1,
    0x1ffffed,
    0x7fff2,
    0x1fffe3,
    0x3ffffe6,
    0x7ffffe0,
    0x7ffffe1,
    0x3ffffe7,
    0x7ffffe2,
    0xfffff2,
    0x1fffe4,
    0x1fffe5,
    0x3ffffe8,
    0x3ffffe9,
    0xffffffd,
    0x7ffffe3,
    0x7ffffe4,
    0x7ffffe5,
    0xfffec,
    0xfffff3,
    0xfffed,
    0x1fffe6,
    0x3fffe9,
    0x1fffe7,
    0x1fffe8,
    0x7ffff3,
    0x3fffea,
    0x3fffeb,
    0x1ffffee,
    0x1ffffef,
    0xfffff4,
    0xfffff5,
    0x3ffffea,
    0x7ffff4,
    0x3ffffeb,
    0x7ffffe6,
    0x3ffffec,
    0x3ffffed,
    0x7ffffe7,
    0x7ffffe8,
    0x7ffffe9,
    0x7ffffea,
    0x7ffffeb,
    0xffffffe,
    0x7ffffec,
    0x7ffffed,
    0x7ffffee,
    0x7ffffef,
    0x7fffff0,
    0x3ffffee,
};

const huffman_code_len = [256]u8{
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,
    5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10,
    13, 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,
    15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
    6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7,  15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
};

test "decode decodes RFC 7541 Huffman example" {
    // RFC 7541 Appendix C.4.1: "www.example.com"
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var out: [32]u8 = undefined;
    const decoded = try decode(&encoded, &out);
    try std.testing.expectEqualStrings("www.example.com", decoded);
}

test "decode rejects overlong EOS padding" {
    var out: [8]u8 = undefined;
    try std.testing.expectError(error.InvalidHuffman, decode(&[_]u8{0xff}, &out));
}
