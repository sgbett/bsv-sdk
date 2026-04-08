// SPDX-License-Identifier: Open BSV License Version 5
// Constant push operations: OP_1NEGATE, OP_1..OP_16.

import Foundation

extension Interpreter {

    /// Push constant values onto the stack (OP_1NEGATE, OP_1..OP_16).
    func opConstantPush(opcode: UInt8) throws {
        if opcode == OpCodes.OP_1NEGATE {
            try stack.push(ScriptNumber.encode(-1))
            return
        }
        try stack.push(ScriptNumber.encode(Int64(opcode - OpCodes.OP_1 + 1)))
    }
}
