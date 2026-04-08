// SPDX-License-Identifier: Open BSV License Version 5
// Bitwise opcodes (EQUAL, AND, OR, XOR, INVERT, LSHIFT, RSHIFT).

import Foundation

extension Interpreter {

    /// Dispatch OP_EQUAL / OP_EQUALVERIFY.
    func opEqual(opcode: UInt8) throws {
        let b = try stack.pop(); let a = try stack.pop()
        let equal = (a == b)
        try stack.push(equal ? Data([0x01]) : Data())
        if opcode == OpCodes.OP_EQUALVERIFY {
            if !equal { throw ScriptError.verifyFailed("OP_EQUALVERIFY") }
            _ = try stack.pop()
        }
    }

    /// Dispatch OP_AND / OP_OR / OP_XOR (element-wise, equal lengths).
    func opBitwiseBinary(opcode: UInt8) throws {
        let b = try stack.pop(); let a = try stack.pop()
        if a.count != b.count {
            throw ScriptError.invalidOperandSize("bitwise op requires equal lengths")
        }
        var out = Data(count: a.count)
        for i in 0..<a.count {
            switch opcode {
            case OpCodes.OP_AND: out[i] = a[i] & b[i]
            case OpCodes.OP_OR: out[i] = a[i] | b[i]
            default: out[i] = a[i] ^ b[i]
            }
        }
        try stack.push(out)
    }

    /// Dispatch OP_INVERT.
    func opInvert() throws {
        let a = try stack.pop()
        var out = Data(count: a.count)
        for i in 0..<a.count { out[i] = ~a[i] }
        try stack.push(out)
    }

    /// Dispatch OP_LSHIFT / OP_RSHIFT — bit-by-bit shift preserving byte length.
    /// LSHIFT moves bits toward the MSB (big-endian "left"), RSHIFT toward the LSB.
    func opShift(opcode: UInt8) throws {
        let n = try popInt()
        if n < 0 { throw ScriptError.negativeShift("shift amount must be non-negative") }
        let buf = try stack.pop()
        if buf.isEmpty { try stack.push(Data()); return }
        let shift = Int(n)
        let totalBits = buf.count * 8
        var out = Data(count: buf.count)
        for i in 0..<totalBits {
            let srcBit = opcode == OpCodes.OP_LSHIFT ? i + shift : i - shift
            if srcBit < 0 || srcBit >= totalBits { continue }
            let srcByte = srcBit / 8
            let srcBitInByte = 7 - (srcBit % 8)
            let bit = (buf[srcByte] >> srcBitInByte) & 1
            let dstByte = i / 8
            let dstBitInByte = 7 - (i % 8)
            out[dstByte] |= bit << dstBitInByte
        }
        try stack.push(out)
    }
}
