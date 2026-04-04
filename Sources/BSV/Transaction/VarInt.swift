import Foundation

/// Bitcoin variable-length integer encoding.
///
/// Encoding scheme:
/// - `0x00–0xFC`: 1 byte (the value itself)
/// - `0xFD` prefix: followed by 2 bytes (little-endian), value `0xFD–0xFFFF`
/// - `0xFE` prefix: followed by 4 bytes (little-endian), value `0x10000–0xFFFFFFFF`
/// - `0xFF` prefix: followed by 8 bytes (little-endian), value `0x100000000–`
public enum VarInt {

    /// Encode a `UInt64` value as a Bitcoin variable-length integer.
    public static func encode(_ value: UInt64) -> Data {
        switch value {
        case 0...0xFC:
            return Data([UInt8(value)])

        case 0xFD...0xFFFF:
            var data = Data([0xFD])
            data.append(UInt8(truncatingIfNeeded: value))
            data.append(UInt8(truncatingIfNeeded: value >> 8))
            return data

        case 0x10000...0xFFFF_FFFF:
            var data = Data([0xFE])
            for shift in stride(from: 0, to: 32, by: 8) {
                data.append(UInt8(truncatingIfNeeded: value >> shift))
            }
            return data

        default:
            var data = Data([0xFF])
            for shift in stride(from: 0, to: 64, by: 8) {
                data.append(UInt8(truncatingIfNeeded: value >> shift))
            }
            return data
        }
    }

    /// Decode a Bitcoin variable-length integer from data at the given offset.
    ///
    /// - Parameters:
    ///   - data: The data buffer to read from.
    ///   - offset: The byte offset to start reading (default 0).
    /// - Returns: A tuple of the decoded value and the number of bytes consumed,
    ///   or `nil` if there are not enough bytes.
    public static func decode(_ data: Data, offset: Int = 0) -> (value: UInt64, bytesRead: Int)? {
        guard offset < data.count else { return nil }

        let prefix = data[data.startIndex + offset]

        switch prefix {
        case 0x00...0xFC:
            return (UInt64(prefix), 1)

        case 0xFD:
            guard offset + 3 <= data.count else { return nil }
            let value = UInt64(data[data.startIndex + offset + 1])
                | (UInt64(data[data.startIndex + offset + 2]) << 8)
            return (value, 3)

        case 0xFE:
            guard offset + 5 <= data.count else { return nil }
            var value: UInt64 = 0
            for i in 0..<4 {
                value |= UInt64(data[data.startIndex + offset + 1 + i]) << (i * 8)
            }
            return (value, 5)

        default: // 0xFF
            guard offset + 9 <= data.count else { return nil }
            var value: UInt64 = 0
            for i in 0..<8 {
                value |= UInt64(data[data.startIndex + offset + 1 + i]) << (i * 8)
            }
            return (value, 9)
        }
    }
}
