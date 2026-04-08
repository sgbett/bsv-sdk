// SPDX-License-Identifier: Open BSV License Version 5
// Bitcoin transaction — wire format serialisation and signing.

import Foundation

/// A Bitcoin transaction.
///
/// Wire format:
/// - 4-byte version (little-endian)
/// - varint input count
/// - inputs
/// - varint output count
/// - outputs
/// - 4-byte lockTime (little-endian)
public class Transaction {
    /// Transaction version (typically 1 or 2).
    public var version: UInt32
    /// Transaction inputs.
    public var inputs: [TransactionInput]
    /// Transaction outputs.
    public var outputs: [TransactionOutput]
    /// Lock time.
    public var lockTime: UInt32

    public init(
        version: UInt32 = 1,
        inputs: [TransactionInput] = [],
        outputs: [TransactionOutput] = [],
        lockTime: UInt32 = 0
    ) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lockTime = lockTime
    }

    // MARK: - Serialisation

    /// Serialise to Bitcoin wire format.
    public func toBinary() -> Data {
        var result = Data()
        var ver = version.littleEndian
        result.append(Data(bytes: &ver, count: 4))
        result.append(VarInt.encode(UInt64(inputs.count)))
        for input in inputs {
            result.append(input.toBinary())
        }
        result.append(VarInt.encode(UInt64(outputs.count)))
        for output in outputs {
            result.append(output.toBinary())
        }
        var lt = lockTime.littleEndian
        result.append(Data(bytes: &lt, count: 4))
        return result
    }

    /// Hex-encoded serialised transaction.
    public func toHex() -> String {
        return toBinary().hex
    }

    /// Transaction ID: double-SHA256 of the serialised bytes, reversed (big-endian display).
    public func txid() -> String {
        let hash = Digest.sha256d(toBinary())
        return Data(hash.reversed()).hex
    }

    /// Transaction ID as raw bytes (little-endian, internal byte order).
    public func txidData() -> Data {
        return Digest.sha256d(toBinary())
    }

    /// Parse a transaction from binary data.
    public static func fromBinary(_ data: Data) throws -> Transaction {
        var offset = 0
        return try fromBinary(data, offset: &offset)
    }

    /// Parse a transaction from binary data at the given offset.
    public static func fromBinary(_ data: Data, offset: inout Int) throws -> Transaction {
        guard offset + 4 <= data.count else {
            throw TransactionError.dataTooShort
        }

        let version = UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
        offset += 4

        guard let (inputCount, viSize1) = VarInt.decode(data, offset: offset) else {
            throw TransactionError.dataTooShort
        }
        offset += viSize1

        var inputs = [TransactionInput]()
        for _ in 0..<inputCount {
            inputs.append(try TransactionInput.fromBinary(data, offset: &offset))
        }

        guard let (outputCount, viSize2) = VarInt.decode(data, offset: offset) else {
            throw TransactionError.dataTooShort
        }
        offset += viSize2

        var outputs = [TransactionOutput]()
        for _ in 0..<outputCount {
            outputs.append(try TransactionOutput.fromBinary(data, offset: &offset))
        }

        guard offset + 4 <= data.count else {
            throw TransactionError.dataTooShort
        }
        let lockTime = UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
        offset += 4

        return Transaction(
            version: version,
            inputs: inputs,
            outputs: outputs,
            lockTime: lockTime
        )
    }

    /// Parse a transaction from a hex string.
    public static func fromHex(_ hex: String) throws -> Transaction {
        guard let data = Data(hex: hex) else {
            throw TransactionError.invalidFormat
        }
        return try fromBinary(data)
    }

    // MARK: - Building

    /// Add an input from a UTXO, with an unlocking script template for signing.
    public func addInput(
        sourceTXID: Data,
        sourceOutputIndex: UInt32,
        sourceSatoshis: UInt64,
        sourceLockingScript: Script,
        unlockingScriptTemplate: (any UnlockingScriptTemplate)? = nil,
        sequenceNumber: UInt32 = defaultSequenceNumber
    ) {
        var input = TransactionInput(
            sourceTXID: sourceTXID,
            sourceOutputIndex: sourceOutputIndex,
            sequenceNumber: sequenceNumber
        )
        input.sourceSatoshis = sourceSatoshis
        input.sourceLockingScript = sourceLockingScript
        input.unlockingScriptTemplate = unlockingScriptTemplate
        inputs.append(input)
    }

    /// Add an output.
    public func addOutput(satoshis: UInt64, lockingScript: Script, isChange: Bool = false) {
        outputs.append(TransactionOutput(
            satoshis: satoshis,
            lockingScript: lockingScript,
            isChange: isChange
        ))
    }

    // MARK: - Signing

    /// Sign all inputs that have an unlocking script template attached.
    /// Each template's `sign(tx:inputIndex:)` is called to produce
    /// the unlocking script.
    public func sign() throws {
        for i in 0..<inputs.count {
            guard let template = inputs[i].unlockingScriptTemplate else {
                continue
            }
            inputs[i].unlockingScript = try template.sign(tx: self, inputIndex: i)
        }
    }

    // MARK: - Fee Estimation

    /// Estimated size of the transaction in bytes, using template
    /// estimated lengths for unsigned inputs.
    public func estimatedSize() -> Int {
        var size = 4 // version
        size += VarInt.encode(UInt64(inputs.count)).count
        for input in inputs {
            // txid + vout + sequence = 40 bytes
            size += 40
            if let template = input.unlockingScriptTemplate {
                let scriptLen = template.estimateLength(tx: self, inputIndex: 0)
                size += VarInt.encode(UInt64(scriptLen)).count + scriptLen
            } else {
                let scriptLen = input.unlockingScript.data.count
                size += VarInt.encode(UInt64(scriptLen)).count + scriptLen
            }
        }
        size += VarInt.encode(UInt64(outputs.count)).count
        for output in outputs {
            size += output.toBinary().count
        }
        size += 4 // lockTime
        return size
    }
}
