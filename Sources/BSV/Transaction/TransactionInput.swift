// SPDX-License-Identifier: Open BSV License Version 5
// Bitcoin transaction input.

import Foundation

/// Default sequence number (0xFFFFFFFF).
public let defaultSequenceNumber: UInt32 = 0xFFFFFFFF

/// A Bitcoin transaction input.
///
/// Wire format:
/// - 32-byte previous txid (little-endian)
/// - 4-byte previous output index (little-endian)
/// - varint script length
/// - unlocking script bytes
/// - 4-byte sequence number (little-endian)
public struct TransactionInput {
    /// Previous transaction ID (32 bytes, internal byte order).
    public var sourceTXID: Data
    /// Index of the output being spent.
    public var sourceOutputIndex: UInt32
    /// The unlocking script (scriptSig).
    public var unlockingScript: Script
    /// Sequence number.
    public var sequenceNumber: UInt32

    /// Optional reference to the full source transaction (for sighash).
    public var sourceTransaction: Transaction?
    /// Optional satoshi value of the output being spent (for sighash when sourceTransaction is nil).
    public var sourceSatoshis: UInt64?
    /// Optional locking script of the output being spent (for sighash when sourceTransaction is nil).
    public var sourceLockingScript: Script?

    public init(
        sourceTXID: Data = Data(count: 32),
        sourceOutputIndex: UInt32 = 0,
        unlockingScript: Script = Script(data: Data()),
        sequenceNumber: UInt32 = defaultSequenceNumber
    ) {
        self.sourceTXID = sourceTXID
        self.sourceOutputIndex = sourceOutputIndex
        self.unlockingScript = unlockingScript
        self.sequenceNumber = sequenceNumber
    }

    /// The locking script of the output being spent, resolved from
    /// either the source transaction or the explicit property.
    public func sourceScript() -> Script? {
        if let tx = sourceTransaction {
            guard Int(sourceOutputIndex) < tx.outputs.count else { return nil }
            return tx.outputs[Int(sourceOutputIndex)].lockingScript
        }
        return sourceLockingScript
    }

    /// The satoshi value of the output being spent, resolved from
    /// either the source transaction or the explicit property.
    public func sourceSatoshiValue() -> UInt64? {
        if let tx = sourceTransaction {
            guard Int(sourceOutputIndex) < tx.outputs.count else { return nil }
            return tx.outputs[Int(sourceOutputIndex)].satoshis
        }
        return sourceSatoshis
    }

    // MARK: - Serialisation

    /// Serialise to Bitcoin wire format.
    public func toBinary() -> Data {
        var result = Data()
        result.append(sourceTXID)
        var vout = sourceOutputIndex.littleEndian
        result.append(Data(bytes: &vout, count: 4))
        let scriptData = unlockingScript.toBinary()
        result.append(VarInt.encode(UInt64(scriptData.count)))
        result.append(scriptData)
        var seq = sequenceNumber.littleEndian
        result.append(Data(bytes: &seq, count: 4))
        return result
    }

    /// Parse a transaction input from binary data at the given offset.
    /// Updates `offset` to point past the consumed bytes.
    public static func fromBinary(_ data: Data, offset: inout Int) throws -> TransactionInput {
        guard offset + 36 <= data.count else {
            throw TransactionError.dataTooShort
        }

        let txid = Data(data[offset..<(offset + 32)])
        offset += 32

        let vout = UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
        offset += 4

        guard let (scriptLen, viSize) = VarInt.decode(data, offset: offset) else {
            throw TransactionError.dataTooShort
        }
        offset += viSize

        let scriptEnd = offset + Int(scriptLen)
        guard scriptEnd <= data.count else {
            throw TransactionError.dataTooShort
        }
        let scriptData = Data(data[offset..<scriptEnd])
        offset = scriptEnd

        guard offset + 4 <= data.count else {
            throw TransactionError.dataTooShort
        }
        let seq = UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
        offset += 4

        return TransactionInput(
            sourceTXID: txid,
            sourceOutputIndex: vout,
            unlockingScript: Script(data: scriptData),
            sequenceNumber: seq
        )
    }
}
