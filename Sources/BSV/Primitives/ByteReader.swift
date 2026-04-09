// SPDX-License-Identifier: Open BSV License Version 5
// Minimal cursor-based byte reader shared across the SDK.
//
// The wider transaction parser uses a plain `inout Int` offset because
// it works with strongly typed fields and wants to push decoding errors
// back to the caller. `ByteReader` is a lighter alternative for call
// sites that just want to walk a buffer and get `nil` back when they
// run out of bytes — used today by the certificate parser and
// available for any other pure-byte parsing tasks.

import Foundation

/// Cursor-based reader over a `Data` buffer. Returns `nil` when a read
/// would run past the end of the buffer so callers can short-circuit
/// cleanly without try/catch boilerplate.
struct ByteReader {
    private let buffer: Data
    private var cursor: Int

    init(_ buffer: Data) {
        self.buffer = buffer
        self.cursor = 0
    }

    /// Read exactly `count` bytes, advancing the cursor. Returns `nil`
    /// if fewer than `count` bytes remain.
    mutating func read(_ count: Int) -> Data? {
        guard count >= 0, cursor + count <= buffer.count else { return nil }
        let slice = buffer.subdata(in: (buffer.startIndex + cursor)..<(buffer.startIndex + cursor + count))
        cursor += count
        return slice
    }

    /// Decode a Bitcoin VarInt at the cursor position, advancing the
    /// cursor past the encoded bytes. Returns `nil` on a truncated or
    /// malformed VarInt.
    mutating func readVarInt() -> UInt64? {
        guard let decoded = VarInt.decode(buffer, offset: cursor) else { return nil }
        cursor += decoded.bytesRead
        return decoded.value
    }

    /// Return the unread tail of the buffer without advancing the cursor.
    func remaining() -> Data {
        guard cursor < buffer.count else { return Data() }
        return buffer.subdata(in: (buffer.startIndex + cursor)..<buffer.endIndex)
    }
}
