// SPDX-License-Identifier: Open BSV License Version 5
// Stack manipulation opcodes (DUP, DROP, SWAP, PICK, ROLL, alt stack, ...).

import Foundation

extension Interpreter {

    /// Dispatch a stack manipulation opcode.
    func opStackOp(opcode: UInt8) throws {
        switch opcode {
        case OpCodes.OP_TOALTSTACK:
            try stack.pushAlt(try stack.pop())
        case OpCodes.OP_FROMALTSTACK:
            try stack.push(try stack.popAlt())
        case OpCodes.OP_2DROP:
            _ = try stack.pop(); _ = try stack.pop()
        case OpCodes.OP_2DUP:
            let b = try stack.peek(0); let a = try stack.peek(1)
            try stack.push(a); try stack.push(b)
        case OpCodes.OP_3DUP:
            let c = try stack.peek(0); let b = try stack.peek(1); let a = try stack.peek(2)
            try stack.push(a); try stack.push(b); try stack.push(c)
        case OpCodes.OP_2OVER:
            let a = try stack.peek(3); let b = try stack.peek(2)
            try stack.push(a); try stack.push(b)
        case OpCodes.OP_2ROT:
            let f = try stack.pop(); let e = try stack.pop()
            let d = try stack.pop(); let c = try stack.pop()
            let b = try stack.pop(); let a = try stack.pop()
            try stack.push(c); try stack.push(d); try stack.push(e); try stack.push(f)
            try stack.push(a); try stack.push(b)
        case OpCodes.OP_2SWAP:
            let d = try stack.pop(); let c = try stack.pop()
            let b = try stack.pop(); let a = try stack.pop()
            try stack.push(c); try stack.push(d); try stack.push(a); try stack.push(b)
        case OpCodes.OP_IFDUP:
            let v = try stack.peek()
            if ScriptNumber.castToBool(v) { try stack.push(v) }
        case OpCodes.OP_DEPTH:
            try stack.push(ScriptNumber.encode(Int64(stack.size)))
        case OpCodes.OP_DROP:
            _ = try stack.pop()
        case OpCodes.OP_DUP:
            try stack.push(try stack.peek())
        case OpCodes.OP_NIP:
            let top = try stack.pop()
            _ = try stack.pop()
            try stack.push(top)
        case OpCodes.OP_OVER:
            try stack.push(try stack.peek(1))
        case OpCodes.OP_PICK, OpCodes.OP_ROLL:
            let n = try popInt()
            guard n >= 0 && Int(n) < stack.size else {
                throw ScriptError.invalidNumberRange("\(OpCodes.name(for: opcode)) index out of range")
            }
            let idx = Int(n)
            if opcode == OpCodes.OP_ROLL {
                let item = try stack.remove(idx)
                try stack.push(item)
            } else {
                try stack.push(try stack.peek(idx))
            }
        case OpCodes.OP_ROT:
            let c = try stack.pop(); let b = try stack.pop(); let a = try stack.pop()
            try stack.push(b); try stack.push(c); try stack.push(a)
        case OpCodes.OP_SWAP:
            let b = try stack.pop(); let a = try stack.pop()
            try stack.push(b); try stack.push(a)
        case OpCodes.OP_TUCK:
            let b = try stack.pop(); let a = try stack.pop()
            try stack.push(b); try stack.push(a); try stack.push(b)
        default:
            throw ScriptError.invalidOpcode("unhandled stack opcode 0x\(String(opcode, radix: 16))")
        }
    }
}
