// SPDX-License-Identifier: Open BSV License Version 5
// Bitcoin script interpreter (post-genesis consensus rules).
//
// Primary reference: ts-sdk src/script/Spend.ts
// Secondary references: go-sdk script/interpreter, py-sdk bsv/script/spend.py
//
// Per-opcode implementations live in Operations/ as extensions on Interpreter.

import Foundation

/// The script interpreter evaluates unlocking + locking script combinations.
///
/// Operates in post-genesis consensus mode only. A script evaluates successfully
/// when both scripts run to completion without error and the top stack item is
/// truthy under Bitcoin-script semantics.
public final class Interpreter {

    // MARK: - Consensus limits (post-genesis)

    /// Maximum number of operations (non-push) per script.
    public static let maxOpsPerScript = 500
    /// Maximum size of any single stack element we support in this SDK.
    /// (Much larger in consensus, but practical and safe for wallets.)
    public static let maxScriptElementSize = 1024 * 1024
    /// Maximum size of a script number for arithmetic (post-genesis 750,000).
    public static let maxScriptNumLength = 750_000

    // MARK: - Execution context

    /// Transaction being validated — optional; required for CHECKSIG.
    let transaction: Transaction?
    /// Index of the input currently being validated.
    let inputIndex: Int
    /// Satoshis of the output being spent.
    let satoshis: UInt64
    /// Locking script being executed.
    let lockingScript: Script
    /// Unlocking script being executed.
    let unlockingScript: Script

    // MARK: - Execution state

    /// A single entry on the conditional execution stack.
    /// `active` is the current branch truth value; `elseSeen` enforces the
    /// post-genesis rule that only one `OP_ELSE` is permitted per `OP_IF`.
    struct IfFrame {
        var active: Bool
        var elseSeen: Bool
    }

    var stack = ScriptStack()
    var programCounter = 0
    var lastCodeSeparator = 0
    var ifStack: [IfFrame] = []
    var opCount = 0
    /// True while executing the unlocking script, false for locking script.
    var inUnlocking = true

    // MARK: - Construction

    init(unlockingScript: Script,
         lockingScript: Script,
         transaction: Transaction? = nil,
         inputIndex: Int = 0,
         satoshis: UInt64 = 0) {
        self.unlockingScript = unlockingScript
        self.lockingScript = lockingScript
        self.transaction = transaction
        self.inputIndex = inputIndex
        self.satoshis = satoshis
    }

    // MARK: - Entry points

    /// Verify the spend at the given input index of a fully populated
    /// transaction. The input must expose either a `sourceTransaction` or an
    /// explicit `sourceLockingScript`/`sourceSatoshis` so that the locking
    /// script can be resolved for evaluation.
    @discardableResult
    public static func verify(
        transaction: Transaction,
        inputIndex: Int
    ) throws -> Bool {
        guard inputIndex < transaction.inputs.count else {
            throw ScriptError.generic("input index \(inputIndex) out of range")
        }
        let input = transaction.inputs[inputIndex]
        guard let locking = input.sourceScript() else {
            throw ScriptError.generic("input \(inputIndex) has no source locking script")
        }
        return try evaluate(
            unlockingScript: input.unlockingScript,
            lockingScript: locking,
            transaction: transaction,
            inputIndex: inputIndex,
            satoshis: input.sourceSatoshiValue() ?? 0
        )
    }

    /// Evaluate the given unlocking + locking script pair.
    /// Returns true if evaluation succeeds (top stack item truthy and clean stack).
    public static func evaluate(
        unlockingScript: Script,
        lockingScript: Script,
        transaction: Transaction? = nil,
        inputIndex: Int = 0,
        satoshis: UInt64 = 0
    ) throws -> Bool {
        let interp = Interpreter(
            unlockingScript: unlockingScript,
            lockingScript: lockingScript,
            transaction: transaction,
            inputIndex: inputIndex,
            satoshis: satoshis
        )
        return try interp.run()
    }

    /// Run both scripts and return the final result.
    func run() throws -> Bool {
        // Post-genesis: unlocking script must be push-only.
        if !unlockingScript.isPushOnly {
            throw ScriptError.pushOnly("unlocking script contains non-push opcodes")
        }

        // Execute unlocking script first, then locking script with its stack.
        try execute(script: unlockingScript)

        // Snapshot stack isn't needed for P2SH (not used on BSV), just continue.
        inUnlocking = false
        opCount = 0
        programCounter = 0
        lastCodeSeparator = 0
        try execute(script: lockingScript)

        if !ifStack.isEmpty {
            throw ScriptError.unbalancedConditional("unterminated OP_IF/OP_NOTIF")
        }

        if stack.isEmpty {
            throw ScriptError.emptyStack("stack empty after script execution")
        }

        let top = try stack.peek()
        if !ScriptNumber.castToBool(top) {
            throw ScriptError.falseStackTop("top stack item is not truthy")
        }

        return true
    }

    // MARK: - Core execution loop

    func execute(script: Script) throws {
        if script.data.count > 10_000_000 {
            throw ScriptError.scriptSize("script too large")
        }

        let chunks = script.chunks
        programCounter = 0

        while programCounter < chunks.count {
            let chunk = chunks[programCounter]
            let op = chunk.opcode

            let executing = !ifStack.contains(where: { !$0.active })

            // Data pushes.
            if op >= 0 && op <= OpCodes.OP_PUSHDATA4 {
                if executing {
                    let data = chunk.data ?? Data()
                    if data.count > Self.maxScriptElementSize {
                        throw ScriptError.pushSize("push exceeds max element size")
                    }
                    try stack.push(data)
                }
                programCounter += 1
                continue
            }

            // Non-push ops count toward the limit.
            opCount += 1
            if opCount > Self.maxOpsPerScript {
                throw ScriptError.opCount("too many operations")
            }

            // Disabled opcodes fail even when not executed? In BSV post-genesis
            // the historically disabled ops (OP_2MUL, OP_2DIV, OP_VER, OP_VERIF,
            // OP_VERNOTIF, OP_LEFT, OP_RIGHT, OP_SUBSTR) may be re-enabled;
            // we treat OP_VERIF/OP_VERNOTIF as always-invalid (like Bitcoin Core)
            // because they're unconditional fail ops.
            if op == OpCodes.OP_VERIF || op == OpCodes.OP_VERNOTIF {
                throw ScriptError.invalidOpcode("OP_VERIF/OP_VERNOTIF are invalid")
            }

            // Flow control ops must always be dispatched, even when skipping.
            let isFlowControl = (op >= OpCodes.OP_IF && op <= OpCodes.OP_ENDIF)

            if executing || isFlowControl {
                try dispatch(opcode: op, chunk: chunk, script: script)
            }

            programCounter += 1
        }
    }

    // MARK: - Dispatch
    //
    // Routes each opcode to the appropriate category module in `Operations/`.

    func dispatch(opcode: UInt8, chunk: ScriptChunk, script: Script) throws {
        switch opcode {
        // Constants
        case OpCodes.OP_1NEGATE,
             OpCodes.OP_1, OpCodes.OP_2, OpCodes.OP_3, OpCodes.OP_4,
             OpCodes.OP_5, OpCodes.OP_6, OpCodes.OP_7, OpCodes.OP_8,
             OpCodes.OP_9, OpCodes.OP_10, OpCodes.OP_11, OpCodes.OP_12,
             OpCodes.OP_13, OpCodes.OP_14, OpCodes.OP_15, OpCodes.OP_16:
            try opConstantPush(opcode: opcode)

        // NOPs
        case OpCodes.OP_NOP, OpCodes.OP_NOP1, OpCodes.OP_NOP4, OpCodes.OP_NOP5,
             OpCodes.OP_NOP6, OpCodes.OP_NOP7, OpCodes.OP_NOP8, OpCodes.OP_NOP9,
             OpCodes.OP_NOP10, OpCodes.OP_CHECKLOCKTIMEVERIFY, OpCodes.OP_CHECKSEQUENCEVERIFY:
            break

        // Flow control
        case OpCodes.OP_IF, OpCodes.OP_NOTIF:
            try opIf(opcode: opcode)
        case OpCodes.OP_ELSE:
            try opElse()
        case OpCodes.OP_ENDIF:
            try opEndif()
        case OpCodes.OP_VERIFY:
            try opVerify()
        case OpCodes.OP_RETURN:
            try opReturn()

        // Stack
        case OpCodes.OP_TOALTSTACK, OpCodes.OP_FROMALTSTACK,
             OpCodes.OP_2DROP, OpCodes.OP_2DUP, OpCodes.OP_3DUP,
             OpCodes.OP_2OVER, OpCodes.OP_2ROT, OpCodes.OP_2SWAP,
             OpCodes.OP_IFDUP, OpCodes.OP_DEPTH, OpCodes.OP_DROP,
             OpCodes.OP_DUP, OpCodes.OP_NIP, OpCodes.OP_OVER,
             OpCodes.OP_PICK, OpCodes.OP_ROLL, OpCodes.OP_ROT,
             OpCodes.OP_SWAP, OpCodes.OP_TUCK:
            try opStackOp(opcode: opcode)

        // Splice
        case OpCodes.OP_CAT:
            try opCat()
        case OpCodes.OP_SPLIT:
            try opSplit()
        case OpCodes.OP_SIZE:
            try opSize()
        case OpCodes.OP_NUM2BIN:
            try opNum2Bin()
        case OpCodes.OP_BIN2NUM:
            try opBin2Num()

        // Bitwise
        case OpCodes.OP_EQUAL, OpCodes.OP_EQUALVERIFY:
            try opEqual(opcode: opcode)
        case OpCodes.OP_AND, OpCodes.OP_OR, OpCodes.OP_XOR:
            try opBitwiseBinary(opcode: opcode)
        case OpCodes.OP_INVERT:
            try opInvert()
        case OpCodes.OP_LSHIFT, OpCodes.OP_RSHIFT:
            try opShift(opcode: opcode)

        // Arithmetic
        case OpCodes.OP_1ADD, OpCodes.OP_1SUB, OpCodes.OP_NEGATE, OpCodes.OP_ABS,
             OpCodes.OP_NOT, OpCodes.OP_0NOTEQUAL:
            try opUnaryArithmetic(opcode: opcode)
        case OpCodes.OP_ADD, OpCodes.OP_SUB, OpCodes.OP_MUL, OpCodes.OP_DIV, OpCodes.OP_MOD,
             OpCodes.OP_BOOLAND, OpCodes.OP_BOOLOR,
             OpCodes.OP_NUMEQUAL, OpCodes.OP_NUMEQUALVERIFY, OpCodes.OP_NUMNOTEQUAL,
             OpCodes.OP_LESSTHAN, OpCodes.OP_GREATERTHAN,
             OpCodes.OP_LESSTHANOREQUAL, OpCodes.OP_GREATERTHANOREQUAL,
             OpCodes.OP_MIN, OpCodes.OP_MAX:
            try opBinaryArithmetic(opcode: opcode)
        case OpCodes.OP_WITHIN:
            try opWithin()

        // Crypto
        case OpCodes.OP_RIPEMD160, OpCodes.OP_SHA1, OpCodes.OP_SHA256,
             OpCodes.OP_HASH160, OpCodes.OP_HASH256:
            try opHash(opcode: opcode)
        case OpCodes.OP_CODESEPARATOR:
            opCodeSeparator()
        case OpCodes.OP_CHECKSIG, OpCodes.OP_CHECKSIGVERIFY:
            try opCheckSig(opcode: opcode, script: script)
        case OpCodes.OP_CHECKMULTISIG, OpCodes.OP_CHECKMULTISIGVERIFY:
            try opCheckMultisig(opcode: opcode, script: script)

        default:
            throw ScriptError.invalidOpcode("unknown or disabled opcode 0x\(String(opcode, radix: 16))")
        }
    }

    // MARK: - Shared helpers

    /// Pop the top stack item and decode it as a script number.
    func popInt(maxSize: Int = ScriptNumber.defaultMaxNumSize) throws -> Int64 {
        let d = try stack.pop()
        return try ScriptNumber.decode(d, requireMinimal: true, maxNumSize: maxSize)
    }
}

// MARK: - Push-only detection

extension Script {
    /// Whether the script contains only push operations (required for unlocking).
    var isPushOnly: Bool {
        for chunk in chunks {
            if chunk.opcode > OpCodes.OP_16 { return false }
        }
        return true
    }
}
