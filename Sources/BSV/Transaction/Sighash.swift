// SPDX-License-Identifier: Open BSV License Version 5
// BIP-143 sighash computation with FORKID for BSV.

import Foundation

/// Sighash computation for BSV transactions.
///
/// BSV uses BIP-143 style sighash with FORKID (0x40). The preimage consists of:
/// 1. nVersion (4 bytes LE)
/// 2. hashPrevouts (sha256d of all input outpoints) — or zeros if ANYONECANPAY
/// 3. hashSequence (sha256d of all input sequences) — or zeros if ANYONECANPAY/NONE/SINGLE
/// 4. outpoint (32-byte txid + 4-byte index of this input)
/// 5. scriptCode (locking script with varint length prefix)
/// 6. value (8 bytes LE — satoshis of the output being spent)
/// 7. nSequence (4 bytes LE of this input)
/// 8. hashOutputs (sha256d of all outputs) — varies for NONE/SINGLE
/// 9. nLockTime (4 bytes LE)
/// 10. sighash type (4 bytes LE — with FORKID bit set)
public enum Sighash {

    /// Compute the BIP-143 sighash preimage for a specific input.
    public static func preimage(
        tx: Transaction,
        inputIndex: Int,
        sighashType: SighashType
    ) throws -> Data {
        guard inputIndex < tx.inputs.count else {
            throw TransactionError.missingSighashData
        }

        let input = tx.inputs[inputIndex]

        guard let lockingScript = input.sourceScript() else {
            throw TransactionError.missingSighashData
        }

        let satoshis = input.sourceSatoshiValue() ?? 0

        // 1. hashPrevouts
        var hashPrevouts = Data(count: 32)
        if !sighashType.hasAnyOneCanPay {
            var buf = Data()
            for inp in tx.inputs {
                buf.append(inp.sourceTXID)
                appendUInt32LE(&buf, inp.sourceOutputIndex)
            }
            hashPrevouts = Digest.sha256d(buf)
        }

        // 2. hashSequence
        var hashSequence = Data(count: 32)
        if !sighashType.hasAnyOneCanPay
            && sighashType.baseType != SighashType.single.rawValue
            && sighashType.baseType != SighashType.none.rawValue {
            var buf = Data()
            for inp in tx.inputs {
                appendUInt32LE(&buf, inp.sequenceNumber)
            }
            hashSequence = Digest.sha256d(buf)
        }

        // 3. hashOutputs
        var hashOutputs = Data(count: 32)
        if sighashType.baseType != SighashType.single.rawValue
            && sighashType.baseType != SighashType.none.rawValue {
            var buf = Data()
            for out in tx.outputs {
                buf.append(outputBytesForSighash(out))
            }
            hashOutputs = Digest.sha256d(buf)
        } else if sighashType.baseType == SighashType.single.rawValue
            && inputIndex < tx.outputs.count {
            let buf = outputBytesForSighash(tx.outputs[inputIndex])
            hashOutputs = Digest.sha256d(buf)
        }

        // Build preimage
        var preimage = Data()
        preimage.reserveCapacity(256)

        // nVersion
        appendUInt32LE(&preimage, tx.version)
        // hashPrevouts
        preimage.append(hashPrevouts)
        // hashSequence
        preimage.append(hashSequence)
        // outpoint
        preimage.append(input.sourceTXID)
        appendUInt32LE(&preimage, input.sourceOutputIndex)
        // scriptCode (with varint length)
        let scriptData = lockingScript.toBinary()
        preimage.append(VarInt.encode(UInt64(scriptData.count)))
        preimage.append(scriptData)
        // value
        appendUInt64LE(&preimage, satoshis)
        // nSequence
        appendUInt32LE(&preimage, input.sequenceNumber)
        // hashOutputs
        preimage.append(hashOutputs)
        // nLockTime
        appendUInt32LE(&preimage, tx.lockTime)
        // sighash type
        appendUInt32LE(&preimage, sighashType.rawValue)

        return preimage
    }

    /// Compute the sighash digest (double-SHA256 of the preimage).
    public static func signatureHash(
        tx: Transaction,
        inputIndex: Int,
        sighashType: SighashType
    ) throws -> Data {
        let pre = try preimage(tx: tx, inputIndex: inputIndex, sighashType: sighashType)
        return Digest.sha256d(pre)
    }

    // MARK: - Private Helpers

    private static func outputBytesForSighash(_ output: TransactionOutput) -> Data {
        var buf = Data()
        appendUInt64LE(&buf, output.satoshis)
        let scriptData = output.lockingScript.toBinary()
        buf.append(VarInt.encode(UInt64(scriptData.count)))
        buf.append(scriptData)
        return buf
    }

    private static func appendUInt32LE(_ data: inout Data, _ value: UInt32) {
        var v = value.littleEndian
        data.append(Data(bytes: &v, count: 4))
    }

    private static func appendUInt64LE(_ data: inout Data, _ value: UInt64) {
        var v = value.littleEndian
        data.append(Data(bytes: &v, count: 8))
    }
}
