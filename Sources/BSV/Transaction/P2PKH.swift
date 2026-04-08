// SPDX-License-Identifier: Open BSV License Version 5
// Pay-to-Public-Key-Hash template for transaction signing.

import Foundation

/// P2PKH locking and unlocking script template.
public enum P2PKH {

    /// Create a P2PKH locking script from a 20-byte public key hash.
    /// OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    public static func lock(hash160: Data) -> Script {
        return Script.p2pkhLock(hash160: hash160)
    }

    /// Create an unlocking script template that signs with the given private key.
    public static func unlock(privateKey: PrivateKey, sighashType: SighashType = .allForkID) -> P2PKHUnlock {
        return P2PKHUnlock(privateKey: privateKey, sighashType: sighashType)
    }
}

/// P2PKH unlocking script template. Conforms to `UnlockingScriptTemplate`.
public struct P2PKHUnlock: UnlockingScriptTemplate {
    let privateKey: PrivateKey
    let sighashType: SighashType

    public init(privateKey: PrivateKey, sighashType: SighashType = .allForkID) {
        self.privateKey = privateKey
        self.sighashType = sighashType
    }

    public func sign(tx: Transaction, inputIndex: Int) throws -> Script {
        // Compute sighash digest
        let hash = try Sighash.signatureHash(
            tx: tx,
            inputIndex: inputIndex,
            sighashType: sighashType
        )

        // Sign with ECDSA
        guard let sig = privateKey.sign(hash: hash) else {
            throw TransactionError.signingFailed
        }

        // DER-encode signature + sighash type byte
        var sigData = sig.toDER()
        sigData.append(UInt8(sighashType.rawValue & 0xFF))

        // Compressed public key
        let pubKey = PublicKey.fromPrivateKey(privateKey)
        let pubKeyData = pubKey.toCompressed()

        // Build unlocking script: <sig+hashtype> <compressed pubkey>
        return Script.p2pkhUnlock(signature: sigData, publicKey: pubKeyData)
    }

    public func estimateLength(tx: Transaction, inputIndex: Int) -> Int {
        // Typical P2PKH unlocking script: 1 + ~72 (DER sig + hashtype) + 1 + 33 (compressed pubkey) ≈ 107
        return 107
    }
}
