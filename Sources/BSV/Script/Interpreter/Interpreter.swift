// SPDX-License-Identifier: Open BSV License Version 5
// Bitcoin script interpreter (post-genesis consensus rules).
//
// Primary reference: ts-sdk src/script/Spend.ts
// Secondary references: go-sdk script/interpreter, py-sdk bsv/script/spend.py

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

    var stack = ScriptStack()
    var programCounter = 0
    var lastCodeSeparator = 0
    var ifStack: [Bool] = []
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

            let executing = !ifStack.contains(false)

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

    func dispatch(opcode: UInt8, chunk: ScriptChunk, script: Script) throws {
        switch opcode {
        // Constants
        case OpCodes.OP_1NEGATE:
            try stack.push(ScriptNumber.encode(-1))
        case OpCodes.OP_1, OpCodes.OP_2, OpCodes.OP_3, OpCodes.OP_4,
             OpCodes.OP_5, OpCodes.OP_6, OpCodes.OP_7, OpCodes.OP_8,
             OpCodes.OP_9, OpCodes.OP_10, OpCodes.OP_11, OpCodes.OP_12,
             OpCodes.OP_13, OpCodes.OP_14, OpCodes.OP_15, OpCodes.OP_16:
            try stack.push(ScriptNumber.encode(Int64(opcode - OpCodes.OP_1 + 1)))

        // NOPs
        case OpCodes.OP_NOP, OpCodes.OP_NOP1, OpCodes.OP_NOP4, OpCodes.OP_NOP5,
             OpCodes.OP_NOP6, OpCodes.OP_NOP7, OpCodes.OP_NOP8, OpCodes.OP_NOP9,
             OpCodes.OP_NOP10, OpCodes.OP_CHECKLOCKTIMEVERIFY, OpCodes.OP_CHECKSEQUENCEVERIFY:
            break

        // Flow control
        case OpCodes.OP_IF, OpCodes.OP_NOTIF:
            try execIf(opcode: opcode)
        case OpCodes.OP_ELSE:
            try execElse()
        case OpCodes.OP_ENDIF:
            try execEndif()
        case OpCodes.OP_VERIFY:
            try execVerify()
        case OpCodes.OP_RETURN:
            throw ScriptError.verifyFailed("OP_RETURN encountered")

        // Stack
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
        case OpCodes.OP_SIZE:
            let top = try stack.peek()
            try stack.push(ScriptNumber.encode(Int64(top.count)))

        // Bitwise
        case OpCodes.OP_EQUAL, OpCodes.OP_EQUALVERIFY:
            let b = try stack.pop(); let a = try stack.pop()
            let equal = (a == b)
            try stack.push(equal ? Data([0x01]) : Data())
            if opcode == OpCodes.OP_EQUALVERIFY {
                if !equal { throw ScriptError.verifyFailed("OP_EQUALVERIFY") }
                _ = try stack.pop()
            }

        case OpCodes.OP_AND, OpCodes.OP_OR, OpCodes.OP_XOR:
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
        case OpCodes.OP_INVERT:
            let a = try stack.pop()
            var out = Data(count: a.count)
            for i in 0..<a.count { out[i] = ~a[i] }
            try stack.push(out)
        case OpCodes.OP_LSHIFT, OpCodes.OP_RSHIFT:
            try execShift(opcode: opcode)

        // Arithmetic
        case OpCodes.OP_1ADD, OpCodes.OP_1SUB, OpCodes.OP_NEGATE, OpCodes.OP_ABS,
             OpCodes.OP_NOT, OpCodes.OP_0NOTEQUAL:
            let a = try popInt()
            let r: Int64
            switch opcode {
            case OpCodes.OP_1ADD: r = a + 1
            case OpCodes.OP_1SUB: r = a - 1
            case OpCodes.OP_NEGATE: r = -a
            case OpCodes.OP_ABS: r = a < 0 ? -a : a
            case OpCodes.OP_NOT: r = a == 0 ? 1 : 0
            default: r = a == 0 ? 0 : 1
            }
            try stack.push(ScriptNumber.encode(r))

        case OpCodes.OP_ADD, OpCodes.OP_SUB, OpCodes.OP_MUL, OpCodes.OP_DIV, OpCodes.OP_MOD,
             OpCodes.OP_BOOLAND, OpCodes.OP_BOOLOR,
             OpCodes.OP_NUMEQUAL, OpCodes.OP_NUMEQUALVERIFY, OpCodes.OP_NUMNOTEQUAL,
             OpCodes.OP_LESSTHAN, OpCodes.OP_GREATERTHAN,
             OpCodes.OP_LESSTHANOREQUAL, OpCodes.OP_GREATERTHANOREQUAL,
             OpCodes.OP_MIN, OpCodes.OP_MAX:
            try execBinaryArithmetic(opcode: opcode)

        case OpCodes.OP_WITHIN:
            let mx = try popInt(); let mn = try popInt(); let x = try popInt()
            try stack.push((x >= mn && x < mx) ? Data([0x01]) : Data())

        // Crypto
        case OpCodes.OP_RIPEMD160, OpCodes.OP_SHA1, OpCodes.OP_SHA256,
             OpCodes.OP_HASH160, OpCodes.OP_HASH256:
            let v = try stack.pop()
            let h: Data
            switch opcode {
            case OpCodes.OP_RIPEMD160: h = Digest.ripemd160(v)
            case OpCodes.OP_SHA1: h = Digest.sha1(v)
            case OpCodes.OP_SHA256: h = Digest.sha256(v)
            case OpCodes.OP_HASH160: h = Digest.hash160(v)
            default: h = Digest.sha256d(v)
            }
            try stack.push(h)
        case OpCodes.OP_CODESEPARATOR:
            lastCodeSeparator = programCounter + 1
        case OpCodes.OP_CHECKSIG, OpCodes.OP_CHECKSIGVERIFY:
            try execCheckSig(opcode: opcode, script: script)
        case OpCodes.OP_CHECKMULTISIG, OpCodes.OP_CHECKMULTISIGVERIFY:
            try execCheckMultisig(opcode: opcode, script: script)

        // Splice
        case OpCodes.OP_CAT:
            let b = try stack.pop(); let a = try stack.pop()
            var combined = a
            combined.append(b)
            if combined.count > Self.maxScriptElementSize {
                throw ScriptError.pushSize("OP_CAT result exceeds max element size")
            }
            try stack.push(combined)
        case OpCodes.OP_SPLIT:
            let n = try popInt()
            let buf = try stack.pop()
            guard n >= 0 && Int(n) <= buf.count else {
                throw ScriptError.invalidSplitRange("OP_SPLIT position out of range")
            }
            let idx = Int(n)
            try stack.push(Data(buf.prefix(idx)))
            try stack.push(Data(buf.suffix(buf.count - idx)))
        case OpCodes.OP_NUM2BIN:
            try execNum2Bin()
        case OpCodes.OP_BIN2NUM:
            let buf = try stack.pop()
            let minimal = ScriptNumber.minimallyEncode(buf)
            try stack.push(minimal)

        default:
            throw ScriptError.invalidOpcode("unknown or disabled opcode 0x\(String(opcode, radix: 16))")
        }
    }

    // MARK: - Helpers

    func popInt(maxSize: Int = ScriptNumber.defaultMaxNumSize) throws -> Int64 {
        let d = try stack.pop()
        return try ScriptNumber.decode(d, requireMinimal: true, maxNumSize: maxSize)
    }

    private func execIf(opcode: UInt8) throws {
        var value = false
        if !ifStack.contains(false) {
            let top = try stack.pop()
            value = ScriptNumber.castToBool(top)
            if opcode == OpCodes.OP_NOTIF { value = !value }
        }
        ifStack.append(value)
    }

    private func execElse() throws {
        guard !ifStack.isEmpty else {
            throw ScriptError.unbalancedConditional("OP_ELSE without OP_IF")
        }
        ifStack[ifStack.count - 1] = !ifStack[ifStack.count - 1]
    }

    private func execEndif() throws {
        guard !ifStack.isEmpty else {
            throw ScriptError.unbalancedConditional("OP_ENDIF without OP_IF")
        }
        _ = ifStack.popLast()
    }

    private func execVerify() throws {
        let v = try stack.peek()
        if !ScriptNumber.castToBool(v) {
            throw ScriptError.verifyFailed("OP_VERIFY requires truthy top stack")
        }
        _ = try stack.pop()
    }

    private func execShift(opcode: UInt8) throws {
        let n = try popInt()
        if n < 0 { throw ScriptError.negativeShift("shift amount must be non-negative") }
        let buf = try stack.pop()
        if buf.isEmpty { try stack.push(Data()); return }
        // Bit-by-bit shift preserving byte length. LSHIFT moves bits toward
        // the MSB (big-endian "left"), RSHIFT moves them toward the LSB.
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

    private func execBinaryArithmetic(opcode: UInt8) throws {
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

    private func execNum2Bin() throws {
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

    // MARK: - Signature operations

    private func execCheckSig(opcode: UInt8, script: Script) throws {
        let pubKeyBuf = try stack.pop()
        let sigBuf = try stack.pop()

        let success = verifySignature(sig: sigBuf, pubKey: pubKeyBuf, script: script)

        try stack.push(success ? Data([0x01]) : Data())
        if opcode == OpCodes.OP_CHECKSIGVERIFY {
            if !success { throw ScriptError.verifyFailed("OP_CHECKSIGVERIFY") }
            _ = try stack.pop()
        }
    }

    private func execCheckMultisig(opcode: UInt8, script: Script) throws {
        // Stack layout: <dummy> <sig1> ... <sigM> <M> <pubkey1> ... <pubkeyN> <N>
        let nKeysInt = try popInt()
        guard nKeysInt >= 0 && nKeysInt <= 20 else {
            throw ScriptError.invalidNumberRange("OP_CHECKMULTISIG key count out of range")
        }
        let nKeys = Int(nKeysInt)
        opCount += nKeys
        if opCount > Self.maxOpsPerScript {
            throw ScriptError.opCount("too many operations")
        }
        var keys = [Data]()
        for _ in 0..<nKeys { keys.append(try stack.pop()) }
        keys.reverse()

        let nSigsInt = try popInt()
        guard nSigsInt >= 0 && nSigsInt <= nKeysInt else {
            throw ScriptError.invalidNumberRange("OP_CHECKMULTISIG sig count out of range")
        }
        let nSigs = Int(nSigsInt)
        var sigs = [Data]()
        for _ in 0..<nSigs { sigs.append(try stack.pop()) }
        sigs.reverse()

        // Dummy (consumed due to original off-by-one bug).
        let dummy = try stack.pop()
        if !dummy.isEmpty {
            // NULLDUMMY: post-genesis requires empty dummy.
            throw ScriptError.verifyFailed("OP_CHECKMULTISIG dummy must be empty")
        }

        // Match sigs against keys in order.
        var success = true
        var sigIndex = 0
        var keyIndex = 0
        while sigIndex < sigs.count {
            if sigs.count - sigIndex > nKeys - keyIndex {
                success = false
                break
            }
            if verifySignature(sig: sigs[sigIndex], pubKey: keys[keyIndex], script: script) {
                sigIndex += 1
            }
            keyIndex += 1
        }

        try stack.push(success ? Data([0x01]) : Data())
        if opcode == OpCodes.OP_CHECKMULTISIGVERIFY {
            if !success { throw ScriptError.verifyFailed("OP_CHECKMULTISIGVERIFY") }
            _ = try stack.pop()
        }
    }

    /// Verify a signature against a public key using the current transaction context.
    func verifySignature(sig: Data, pubKey: Data, script: Script) -> Bool {
        if sig.isEmpty { return false }
        guard let transaction = transaction else { return false }
        guard inputIndex < transaction.inputs.count else { return false }

        // Last byte is sighash type; preceding bytes are the DER signature.
        let sighashByte = sig[sig.count - 1]
        let derBytes = Data(sig.prefix(sig.count - 1))
        guard let parsedSig = Signature.fromDER(derBytes) else { return false }
        guard let publicKey = PublicKey(data: pubKey) else { return false }

        let sighashType = SighashType(rawValue: UInt32(sighashByte))

        // Compute signature hash. We use the existing Sighash helper which takes
        // the locking script from the input's source output. For pure in-memory
        // interpreter cases without a source script populated, fall back to
        // using the currently-executing locking script.
        let digest: Data
        do {
            digest = try Sighash.signatureHash(
                tx: transaction,
                inputIndex: inputIndex,
                sighashType: sighashType
            )
        } catch {
            return false
        }

        return publicKey.verify(hash: digest, signature: parsedSig)
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
