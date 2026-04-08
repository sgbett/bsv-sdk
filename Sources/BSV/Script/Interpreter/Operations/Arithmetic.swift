// SPDX-License-Identifier: Open BSV License Version 5
// Numeric and comparison opcodes (ADD, SUB, MUL, DIV, MOD, NUMEQUAL, ...).

import Foundation

extension Interpreter {

    /// Dispatch a unary arithmetic opcode (1ADD, 1SUB, NEGATE, ABS, NOT, 0NOTEQUAL).
    func opUnaryArithmetic(opcode: UInt8) throws {
        let a = try popInt()
        let r: Int64
        switch opcode {
        case OpCodes.OP_1ADD: r = a + 1
        case OpCodes.OP_1SUB: r = a - 1
        case OpCodes.OP_NEGATE: r = -a
        case OpCodes.OP_ABS: r = a < 0 ? -a : a
        case OpCodes.OP_NOT: r = a == 0 ? 1 : 0
        case OpCodes.OP_0NOTEQUAL: r = a == 0 ? 0 : 1
        default: throw ScriptError.invalidOpcode("unhandled unary arithmetic op")
        }
        try stack.push(ScriptNumber.encode(r))
    }

    /// Dispatch a binary arithmetic or comparison opcode.
    func opBinaryArithmetic(opcode: UInt8) throws {
        let b = try popInt()
        let a = try popInt()
        let r: Int64
        switch opcode {
        case OpCodes.OP_ADD: r = a &+ b
        case OpCodes.OP_SUB: r = a &- b
        case OpCodes.OP_MUL: r = a &* b
        case OpCodes.OP_DIV:
            if b == 0 { throw ScriptError.divisionByZero("OP_DIV by zero") }
            r = a / b
        case OpCodes.OP_MOD:
            if b == 0 { throw ScriptError.divisionByZero("OP_MOD by zero") }
            r = a % b
        case OpCodes.OP_BOOLAND: r = (a != 0 && b != 0) ? 1 : 0
        case OpCodes.OP_BOOLOR: r = (a != 0 || b != 0) ? 1 : 0
        case OpCodes.OP_NUMEQUAL, OpCodes.OP_NUMEQUALVERIFY: r = a == b ? 1 : 0
        case OpCodes.OP_NUMNOTEQUAL: r = a != b ? 1 : 0
        case OpCodes.OP_LESSTHAN: r = a < b ? 1 : 0
        case OpCodes.OP_GREATERTHAN: r = a > b ? 1 : 0
        case OpCodes.OP_LESSTHANOREQUAL: r = a <= b ? 1 : 0
        case OpCodes.OP_GREATERTHANOREQUAL: r = a >= b ? 1 : 0
        case OpCodes.OP_MIN: r = min(a, b)
        case OpCodes.OP_MAX: r = max(a, b)
        default: throw ScriptError.invalidOpcode("unhandled arithmetic op")
        }
        try stack.push(ScriptNumber.encode(r))
        if opcode == OpCodes.OP_NUMEQUALVERIFY {
            if r == 0 { throw ScriptError.verifyFailed("OP_NUMEQUALVERIFY") }
            _ = try stack.pop()
        }
    }

    /// Dispatch OP_WITHIN: x min max -> (min <= x < max).
    func opWithin() throws {
        let mx = try popInt()
        let mn = try popInt()
        let x = try popInt()
        try stack.push((x >= mn && x < mx) ? Data([0x01]) : Data())
    }
}
