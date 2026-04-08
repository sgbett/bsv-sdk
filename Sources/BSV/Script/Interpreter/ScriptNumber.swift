// SPDX-License-Identifier: Open BSV License Version 5
// Bitcoin script number encoding (little-endian, sign-and-magnitude, minimal).

import Foundation

/// Helpers for encoding and decoding Bitcoin script numbers.
///
/// Bitcoin script numbers are variable-length little-endian integers with a
/// sign-and-magnitude representation: the most-significant bit of the most
/// significant byte indicates the sign (1 = negative). Zero is encoded as the
/// empty byte array. Minimal encoding forbids trailing zero bytes that could
/// be removed without changing the value.
public enum ScriptNumber {

    /// Default maximum number size for arithmetic operations (pre-genesis = 4).
    public static let defaultMaxNumSize = 4

    /// Decode a Bitcoin script number.
    ///
    /// - Parameters:
    ///   - data: the raw little-endian byte representation
    ///   - requireMinimal: if true, non-minimally-encoded inputs throw
    ///   - maxNumSize: maximum allowed size in bytes for the encoded form
    /// - Returns: the decoded signed integer
    public static func decode(
        _ data: Data,
        requireMinimal: Bool = true,
        maxNumSize: Int = defaultMaxNumSize
    ) throws -> Int64 {
        if data.count > maxNumSize {
            throw ScriptError.numberOverflow(
                "script number exceeds max size of \(maxNumSize) bytes"
            )
        }
        if data.isEmpty { return 0 }

        if requireMinimal {
            // The top byte's sign bit is the only bit allowed to be set in the
            // final byte if the rest of the byte is zero.
            let last = data[data.count - 1]
            if (last & 0x7f) == 0 {
                // Final byte is zero or just the sign bit — allowed only if
                // the sign bit in the previous byte is set (i.e. this one is
                // not redundant).
                if data.count <= 1 || (data[data.count - 2] & 0x80) == 0 {
                    throw ScriptError.nonMinimalNumber("non-minimally encoded script number")
                }
            }
        }

        var result: UInt64 = 0
        for i in 0..<data.count {
            result |= UInt64(data[i]) << (8 * i)
        }

        // Strip the sign bit from the high byte to get the magnitude.
        let signMask: UInt64 = UInt64(0x80) << (8 * (data.count - 1))
        let isNegative = (result & signMask) != 0
        let magnitude = Int64(result & ~signMask)

        return isNegative ? -magnitude : magnitude
    }

    /// Encode a signed integer as a Bitcoin script number (minimal form).
    public static func encode(_ value: Int64) -> Data {
        if value == 0 { return Data() }

        var result = Data()
        let negative = value < 0
        var absValue: UInt64 = negative ? UInt64(-(value + 1)) + 1 : UInt64(value)

        while absValue > 0 {
            result.append(UInt8(absValue & 0xff))
            absValue >>= 8
        }

        // If the final byte has the high bit set we need an extra byte so
        // the sign bit we're about to attach does not clobber the magnitude.
        if (result[result.count - 1] & 0x80) != 0 {
            result.append(negative ? 0x80 : 0x00)
        } else if negative {
            result[result.count - 1] |= 0x80
        }
        return result
    }

    /// Produce the minimal encoding of an existing script number buffer.
    /// Strips redundant trailing zero bytes while preserving the sign.
    public static func minimallyEncode(_ data: Data) -> Data {
        if data.isEmpty { return data }

        let last = data[data.count - 1]
        if (last & 0x7f) != 0 {
            return data
        }
        // The final byte contributes no magnitude; check if it can be dropped.
        if data.count == 1 { return Data() }

        // If the next byte's high bit is already set we still need the final
        // byte to hold the sign, but its value might be reducible to 0x80 or
        // 0x00 — leave it as the sign holder.
        if (data[data.count - 2] & 0x80) != 0 {
            return data
        }

        // Recurse on the shorter buffer, carrying the sign onto the new
        // final byte.
        var result = Data(data.prefix(data.count - 1))
        while result.count > 1 && result[result.count - 1] == 0 && (result[result.count - 2] & 0x80) == 0 {
            result = result.prefix(result.count - 1)
        }
        if !result.isEmpty {
            result[result.count - 1] |= (last & 0x80)
        } else if (last & 0x80) != 0 {
            // Value was ±0: collapse to empty buffer regardless of sign.
            return Data()
        }
        return result
    }

    /// Interpret a buffer as a boolean in Bitcoin-script semantics.
    /// Non-zero is true, but negative zero (0x80) is false.
    public static func castToBool(_ data: Data) -> Bool {
        if data.isEmpty { return false }
        for i in 0..<data.count {
            if data[i] != 0 {
                // Allow the sign bit in the final byte to still be "zero".
                if i == data.count - 1 && data[i] == 0x80 { return false }
                return true
            }
        }
        return false
    }
}
