// SPDX-License-Identifier: Open BSV License Version 5
// Bitcoin transaction output.

import Foundation

/// A Bitcoin transaction output.
///
/// Wire format:
/// - 8-byte value in satoshis (Int64, little-endian)
/// - varint script length
/// - locking script bytes
public struct TransactionOutput {
    /// Value in satoshis.
    public var satoshis: UInt64
    /// The locking script (scriptPubKey).
    public var lockingScript: Script
    /// Whether this output is a change output (used during transaction building).
    public var isChange: Bool

    public init(
        satoshis: UInt64 = 0,
        lockingScript: Script = Script(data: Data()),
        isChange: Bool = false
    ) {
        self.satoshis = satoshis
        self.lockingScript = lockingScript
        self.isChange = isChange
    }

    // MARK: - Serialisation

    /// Serialise to Bitcoin wire format.
    public func toBinary() -> Data {
        var result = Data()
        var sats = satoshis.littleEndian
        result.append(Data(bytes: &sats, count: 8))
        let scriptData = lockingScript.toBinary()
        result.append(VarInt.encode(UInt64(scriptData.count)))
        result.append(scriptData)
        return result
    }

    /// Parse a transaction output from binary data at the given offset.
    /// Updates `offset` to point past the consumed bytes.
    public static func fromBinary(_ data: Data, offset: inout Int) throws -> TransactionOutput {
        guard offset + 8 <= data.count else {
            throw TransactionError.dataTooShort
        }

        var sats: UInt64 = 0
        for i in 0..<8 {
            sats |= UInt64(data[offset + i]) << (i * 8)
        }
        offset += 8

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

        return TransactionOutput(
            satoshis: sats,
            lockingScript: Script(data: scriptData)
        )
    }
}
