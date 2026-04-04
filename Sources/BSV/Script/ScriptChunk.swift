// SPDX-License-Identifier: Open BSV License Version 5
// Script chunk: an opcode with optional associated data.

import Foundation

/// A single parsed element of a Bitcoin script.
///
/// A chunk is either a bare opcode (e.g. OP_DUP) or a data push.
/// For data pushes, the opcode indicates the push method:
/// - 0x01-0x4b: push that many bytes directly
/// - OP_PUSHDATA1 (0x4c): 1-byte length prefix
/// - OP_PUSHDATA2 (0x4d): 2-byte LE length prefix
/// - OP_PUSHDATA4 (0x4e): 4-byte LE length prefix
public struct ScriptChunk {
    /// The opcode byte.
    public let opcode: UInt8
    /// Optional data associated with push operations.
    public let data: Data?

    public init(opcode: UInt8, data: Data? = nil) {
        self.opcode = opcode
        self.data = data
    }

    /// Whether this chunk is a data push operation.
    public var isDataPush: Bool {
        return opcode >= 0x01 && opcode <= OpCodes.OP_PUSHDATA4
    }

    /// Whether this chunk pushes a small integer (OP_0 or OP_1..OP_16).
    public var isSmallInt: Bool {
        return OpCodes.isSmallInt(opcode)
    }

    // MARK: - Serialisation

    /// Serialise this chunk to its binary wire format.
    public func toBinary() -> Data {
        var result = Data()
        result.append(opcode)

        guard let data = data else {
            return result
        }

        switch opcode {
        case OpCodes.OP_PUSHDATA1:
            result.append(UInt8(data.count))
            result.append(data)
        case OpCodes.OP_PUSHDATA2:
            var length = UInt16(data.count).littleEndian
            result.append(Data(bytes: &length, count: 2))
            result.append(data)
        case OpCodes.OP_PUSHDATA4:
            var length = UInt32(data.count).littleEndian
            result.append(Data(bytes: &length, count: 4))
            result.append(data)
        default:
            // Direct push (0x01-0x4b): opcode IS the length
            result.append(data)
        }

        return result
    }

    /// The ASM string representation of this chunk.
    public func toASM() -> String {
        if opcode == OpCodes.OP_0 && data == nil {
            return "0"
        }
        if isDataPush, let data = data {
            return data.hex
        }
        return OpCodes.name(for: opcode)
    }

    // MARK: - Parsing

    /// Errors that can occur during chunk parsing.
    public enum ParseError: Error {
        case dataTooSmall
        case indexOutOfRange
    }

    /// Parse a single chunk from binary data at the given offset.
    /// Updates `offset` to point past the parsed chunk.
    public static func fromBinary(_ data: Data, offset: inout Int) throws -> ScriptChunk {
        guard offset < data.count else {
            throw ParseError.indexOutOfRange
        }

        let op = data[offset]

        switch op {
        case 0x01...0x4b:
            // Direct push: opcode is the byte count
            let length = Int(op)
            guard offset + 1 + length <= data.count else {
                throw ParseError.dataTooSmall
            }
            let pushData = data[(offset + 1)..<(offset + 1 + length)]
            offset += 1 + length
            return ScriptChunk(opcode: op, data: Data(pushData))

        case OpCodes.OP_PUSHDATA1:
            guard offset + 2 <= data.count else {
                throw ParseError.dataTooSmall
            }
            let length = Int(data[offset + 1])
            guard offset + 2 + length <= data.count else {
                throw ParseError.dataTooSmall
            }
            let pushData = data[(offset + 2)..<(offset + 2 + length)]
            offset += 2 + length
            return ScriptChunk(opcode: op, data: Data(pushData))

        case OpCodes.OP_PUSHDATA2:
            guard offset + 3 <= data.count else {
                throw ParseError.dataTooSmall
            }
            let length = Int(data[offset + 1]) | (Int(data[offset + 2]) << 8)
            guard offset + 3 + length <= data.count else {
                throw ParseError.dataTooSmall
            }
            let pushData = data[(offset + 3)..<(offset + 3 + length)]
            offset += 3 + length
            return ScriptChunk(opcode: op, data: Data(pushData))

        case OpCodes.OP_PUSHDATA4:
            guard offset + 5 <= data.count else {
                throw ParseError.dataTooSmall
            }
            let length = Int(data[offset + 1])
                | (Int(data[offset + 2]) << 8)
                | (Int(data[offset + 3]) << 16)
                | (Int(data[offset + 4]) << 24)
            guard offset + 5 + length <= data.count else {
                throw ParseError.dataTooSmall
            }
            let pushData = data[(offset + 5)..<(offset + 5 + length)]
            offset += 5 + length
            return ScriptChunk(opcode: op, data: Data(pushData))

        default:
            // Bare opcode (no data)
            offset += 1
            return ScriptChunk(opcode: op)
        }
    }

    /// Parse all chunks from binary script data.
    public static func parseAll(from data: Data) throws -> [ScriptChunk] {
        var chunks = [ScriptChunk]()
        var offset = 0
        while offset < data.count {
            let chunk = try fromBinary(data, offset: &offset)
            chunks.append(chunk)
        }
        return chunks
    }

    // MARK: - Push Data Encoding

    /// Create a data push chunk with the minimal encoding for the given data.
    public static func encodePushData(_ pushData: Data) -> ScriptChunk {
        let length = pushData.count
        if length <= 75 {
            return ScriptChunk(opcode: UInt8(length), data: pushData)
        } else if length <= 0xFF {
            return ScriptChunk(opcode: OpCodes.OP_PUSHDATA1, data: pushData)
        } else if length <= 0xFFFF {
            return ScriptChunk(opcode: OpCodes.OP_PUSHDATA2, data: pushData)
        } else {
            return ScriptChunk(opcode: OpCodes.OP_PUSHDATA4, data: pushData)
        }
    }
}
