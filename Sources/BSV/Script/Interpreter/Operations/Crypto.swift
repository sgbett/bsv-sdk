// SPDX-License-Identifier: Open BSV License Version 5
// Cryptographic opcodes (hash, CHECKSIG, CHECKMULTISIG, CODESEPARATOR).

import Foundation

extension Interpreter {

    /// Dispatch a hash opcode (RIPEMD160, SHA1, SHA256, HASH160, HASH256).
    func opHash(opcode: UInt8) throws {
        let v = try stack.pop()
        let h: Data
        switch opcode {
        case OpCodes.OP_RIPEMD160: h = Digest.ripemd160(v)
        case OpCodes.OP_SHA1: h = Digest.sha1(v)
        case OpCodes.OP_SHA256: h = Digest.sha256(v)
        case OpCodes.OP_HASH160: h = Digest.hash160(v)
        case OpCodes.OP_HASH256: h = Digest.sha256d(v)
        default: throw ScriptError.invalidOpcode("unhandled hash opcode")
        }
        try stack.push(h)
    }

    /// Dispatch OP_CODESEPARATOR: marks the sig hash starting point.
    func opCodeSeparator() {
        lastCodeSeparator = programCounter + 1
    }

    /// Dispatch OP_CHECKSIG / OP_CHECKSIGVERIFY.
    func opCheckSig(opcode: UInt8, script: Script) throws {
        let pubKeyBuf = try stack.pop()
        let sigBuf = try stack.pop()
        let success = verifySignature(sig: sigBuf, pubKey: pubKeyBuf, script: script)
        try stack.push(success ? Data([0x01]) : Data())
        if opcode == OpCodes.OP_CHECKSIGVERIFY {
            if !success { throw ScriptError.verifyFailed("OP_CHECKSIGVERIFY") }
            _ = try stack.pop()
        }
    }

    /// Dispatch OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY.
    /// Stack layout: <dummy> <sig1> ... <sigM> <M> <pubkey1> ... <pubkeyN> <N>.
    func opCheckMultisig(opcode: UInt8, script: Script) throws {
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

        // NULLDUMMY: post-genesis requires empty dummy.
        let dummy = try stack.pop()
        if !dummy.isEmpty {
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
