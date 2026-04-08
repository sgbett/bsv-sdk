// SPDX-License-Identifier: Open BSV License Version 5
// Splice opcodes (CAT, SPLIT, NUM2BIN, BIN2NUM, SIZE).

import Foundation

extension Interpreter {

    /// Dispatch OP_CAT: concatenate top two stack items.
    func opCat() throws {
        let b = try stack.pop(); let a = try stack.pop()
        var combined = a
        combined.append(b)
        if combined.count > Self.maxScriptElementSize {
            throw ScriptError.pushSize("OP_CAT result exceeds max element size")
        }
        try stack.push(combined)
    }

    /// Dispatch OP_SPLIT: split top buffer into two at position `n`.
    func opSplit() throws {
        let n = try popInt()
        let buf = try stack.pop()
        guard n >= 0 && Int(n) <= buf.count else {
            throw ScriptError.invalidSplitRange("OP_SPLIT position out of range")
        }
        let idx = Int(n)
        try stack.push(Data(buf.prefix(idx)))
        try stack.push(Data(buf.suffix(buf.count - idx)))
    }

    /// Dispatch OP_SIZE: push the byte length of the top stack item.
    func opSize() throws {
        let top = try stack.peek()
        try stack.push(ScriptNumber.encode(Int64(top.count)))
    }

    /// Dispatch OP_NUM2BIN: re-encode a script number to an exact byte width,
    /// preserving its sign bit.
    func opNum2Bin() throws {
        let sz = try popInt()
        guard sz >= 0 && Int(sz) <= Self.maxScriptElementSize else {
            throw ScriptError.pushSize("OP_NUM2BIN size out of range")
        }
        let size = Int(sz)
        let raw = try stack.pop()
        let minimal = ScriptNumber.minimallyEncode(raw)
        if minimal.count > size {
            throw ScriptError.invalidOperandSize("OP_NUM2BIN value too large for size")
        }
        if minimal.count == size {
            try stack.push(minimal); return
        }
        var result = Data(count: size)
        var signBit: UInt8 = 0
        var working = minimal
        if !working.isEmpty {
            signBit = working[working.count - 1] & 0x80
            working[working.count - 1] &= 0x7f
        }
        for i in 0..<working.count { result[i] = working[i] }
        if signBit != 0 {
            result[size - 1] |= 0x80
        }
        try stack.push(result)
    }

    /// Dispatch OP_BIN2NUM: reduce a buffer to its minimal script-number form.
    func opBin2Num() throws {
        let buf = try stack.pop()
        let minimal = ScriptNumber.minimallyEncode(buf)
        try stack.push(minimal)
    }
}
