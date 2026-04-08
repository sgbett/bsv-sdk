// SPDX-License-Identifier: Open BSV License Version 5
// Flow control opcodes (IF, NOTIF, ELSE, ENDIF, VERIFY, RETURN).

import Foundation

extension Interpreter {

    /// Dispatch OP_IF / OP_NOTIF: push branch condition onto ifStack.
    func opIf(opcode: UInt8) throws {
        var value = false
        if !ifStack.contains(false) {
            let top = try stack.pop()
            value = ScriptNumber.castToBool(top)
            if opcode == OpCodes.OP_NOTIF { value = !value }
        }
        ifStack.append(value)
    }

    /// Dispatch OP_ELSE: flip the top ifStack entry.
    func opElse() throws {
        guard !ifStack.isEmpty else {
            throw ScriptError.unbalancedConditional("OP_ELSE without OP_IF")
        }
        ifStack[ifStack.count - 1] = !ifStack[ifStack.count - 1]
    }

    /// Dispatch OP_ENDIF: pop the top ifStack entry.
    func opEndif() throws {
        guard !ifStack.isEmpty else {
            throw ScriptError.unbalancedConditional("OP_ENDIF without OP_IF")
        }
        _ = ifStack.popLast()
    }

    /// Dispatch OP_VERIFY: fail unless top stack item is truthy.
    func opVerify() throws {
        let v = try stack.peek()
        if !ScriptNumber.castToBool(v) {
            throw ScriptError.verifyFailed("OP_VERIFY requires truthy top stack")
        }
        _ = try stack.pop()
    }

    /// Dispatch OP_RETURN: unconditional failure in post-genesis executing branches.
    func opReturn() throws {
        throw ScriptError.verifyFailed("OP_RETURN encountered")
    }
}
