import Foundation

/// Data format for a transaction entry within BEEF V2.
public enum BeefTxDataFormat: UInt8 {
    /// Raw transaction without a BUMP index.
    case rawTx = 0
    /// Raw transaction with a BUMP index.
    case rawTxAndBumpIndex = 1
    /// Transaction ID only (32 bytes).
    case txidOnly = 2
}

/// A single transaction entry within a BEEF structure.
public struct BeefTx {
    /// The data format of this entry.
    public var dataFormat: BeefTxDataFormat
    /// The full transaction (nil when `dataFormat == .txidOnly`).
    public var transaction: Transaction?
    /// Index into the BEEF's `bumps` array (only set when `dataFormat == .rawTxAndBumpIndex`).
    public var bumpIndex: Int
    /// Known txid when `dataFormat == .txidOnly` (32 bytes, internal byte order).
    public var knownTxID: Data?

    public init(
        dataFormat: BeefTxDataFormat = .rawTx,
        transaction: Transaction? = nil,
        bumpIndex: Int = 0,
        knownTxID: Data? = nil
    ) {
        self.dataFormat = dataFormat
        self.transaction = transaction
        self.bumpIndex = bumpIndex
        self.knownTxID = knownTxID
    }
}

// MARK: - BEEF versions

/// BEEF V1 version marker (0x0100BEEF in little-endian).
public let beefV1Version: UInt32 = 4022206465

/// BEEF V2 version marker (0x0200BEEF in little-endian).
public let beefV2Version: UInt32 = 4022206466

/// Atomic BEEF version marker.
public let atomicBeefVersion: UInt32 = 0x01010101

/// Background Evaluation Extended Format (BEEF).
///
/// Bundles transactions with their Merkle proofs for SPV verification.
/// Supports both V1 (BRC-62) and V2 (BRC-96) formats.
public struct Beef {
    /// BEEF version (V1 or V2).
    public var version: UInt32
    /// Merkle paths (BUMPs) referenced by transactions.
    public var bumps: [MerklePath]
    /// Ordered list of transactions.
    public var transactions: [BeefTx]

    public init(
        version: UInt32 = beefV2Version,
        bumps: [MerklePath] = [],
        transactions: [BeefTx] = []
    ) {
        self.version = version
        self.bumps = bumps
        self.transactions = transactions
    }

    // MARK: - Deserialisation

    /// Decode BEEF from binary data.
    public static func fromBinary(_ data: Data) throws -> Beef {
        guard data.count >= 4 else {
            throw BeefError.insufficientData
        }

        var offset = 0

        // Check for Atomic BEEF wrapper.
        let firstFour = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        if firstFour == atomicBeefVersion {
            // Skip the atomic header: 4 bytes version + 32 bytes txid.
            guard data.count >= 36 else {
                throw BeefError.insufficientData
            }
            offset = 36
        }

        // Read version.
        guard offset + 4 <= data.count else {
            throw BeefError.insufficientData
        }
        let version = data.withUnsafeBytes { buf -> UInt32 in
            buf.load(fromByteOffset: offset, as: UInt32.self)
        }
        offset += 4

        guard version == beefV1Version || version == beefV2Version else {
            throw BeefError.invalidVersion(version)
        }

        // Read BUMPs.
        guard let (nBumps, nbBytes) = VarInt.decode(data, offset: offset) else {
            throw BeefError.insufficientData
        }
        offset += nbBytes

        var bumps = [MerklePath]()
        bumps.reserveCapacity(Int(nBumps))
        for _ in 0..<nBumps {
            let bump = try MerklePath.fromBinary(data, offset: &offset)
            bumps.append(bump)
        }

        // Read transactions.
        if version == beefV1Version {
            return try readV1Transactions(data: data, offset: &offset, version: version, bumps: bumps)
        } else {
            return try readV2Transactions(data: data, offset: &offset, version: version, bumps: bumps)
        }
    }

    /// Decode BEEF from a hexadecimal string.
    public static func fromHex(_ hex: String) throws -> Beef {
        guard let data = Data(hex: hex) else {
            throw BeefError.invalidHex
        }
        return try fromBinary(data)
    }

    // MARK: - Serialisation

    /// Encode to BEEF V2 binary format.
    public func toBinary() -> Data {
        var data = Data()

        // Version (4 bytes, little-endian).
        var ver = version.littleEndian
        data.append(Data(bytes: &ver, count: 4))

        // Number of BUMPs.
        data.append(VarInt.encode(UInt64(bumps.count)))

        // BUMP data.
        for bump in bumps {
            data.append(bump.toBinary())
        }

        // Number of transactions.
        data.append(VarInt.encode(UInt64(transactions.count)))

        // Transaction data (V2 format).
        for tx in transactions {
            data.append(tx.dataFormat.rawValue)
            switch tx.dataFormat {
            case .txidOnly:
                if let txid = tx.knownTxID {
                    data.append(txid)
                }
            case .rawTxAndBumpIndex:
                data.append(VarInt.encode(UInt64(tx.bumpIndex)))
                if let transaction = tx.transaction {
                    data.append(transaction.toBinary())
                }
            case .rawTx:
                if let transaction = tx.transaction {
                    data.append(transaction.toBinary())
                }
            }
        }

        return data
    }

    /// Encode to a hexadecimal string.
    public func toHex() -> String {
        toBinary().hex
    }

    // MARK: - V1 reading

    /// Read BEEF V1 format: tx bytes then has_bump flag then optional bump_index.
    private static func readV1Transactions(
        data: Data,
        offset: inout Int,
        version: UInt32,
        bumps: [MerklePath]
    ) throws -> Beef {
        guard let (nTxs, ntBytes) = VarInt.decode(data, offset: offset) else {
            throw BeefError.insufficientData
        }
        offset += ntBytes

        var transactions = [BeefTx]()
        transactions.reserveCapacity(Int(nTxs))

        for _ in 0..<nTxs {
            let tx = try Transaction.fromBinary(data, offset: &offset)

            // Read has_bump flag.
            guard offset < data.count else {
                throw BeefError.insufficientData
            }
            let hasBump = data[data.startIndex + offset]
            offset += 1

            var beefTx = BeefTx(transaction: tx)
            if hasBump != 0 {
                guard let (bumpIdx, biBytes) = VarInt.decode(data, offset: offset) else {
                    throw BeefError.insufficientData
                }
                offset += biBytes
                beefTx.dataFormat = .rawTxAndBumpIndex
                beefTx.bumpIndex = Int(bumpIdx)
            }
            transactions.append(beefTx)
        }

        return Beef(version: version, bumps: bumps, transactions: transactions)
    }

    // MARK: - V2 reading

    /// Read BEEF V2 format: format byte per transaction.
    private static func readV2Transactions(
        data: Data,
        offset: inout Int,
        version: UInt32,
        bumps: [MerklePath]
    ) throws -> Beef {
        guard let (nTxs, ntBytes) = VarInt.decode(data, offset: offset) else {
            throw BeefError.insufficientData
        }
        offset += ntBytes

        var transactions = [BeefTx]()
        transactions.reserveCapacity(Int(nTxs))

        for _ in 0..<nTxs {
            guard offset < data.count else {
                throw BeefError.insufficientData
            }
            let formatByte = data[data.startIndex + offset]
            offset += 1

            guard let format = BeefTxDataFormat(rawValue: formatByte) else {
                throw BeefError.invalidDataFormat(formatByte)
            }

            switch format {
            case .txidOnly:
                guard offset + 32 <= data.count else {
                    throw BeefError.insufficientData
                }
                let txid = data[(data.startIndex + offset)..<(data.startIndex + offset + 32)]
                offset += 32
                transactions.append(BeefTx(dataFormat: .txidOnly, knownTxID: Data(txid)))

            case .rawTxAndBumpIndex:
                guard let (bumpIdx, biBytes) = VarInt.decode(data, offset: offset) else {
                    throw BeefError.insufficientData
                }
                offset += biBytes
                let tx = try Transaction.fromBinary(data, offset: &offset)
                transactions.append(BeefTx(
                    dataFormat: .rawTxAndBumpIndex,
                    transaction: tx,
                    bumpIndex: Int(bumpIdx)
                ))

            case .rawTx:
                let tx = try Transaction.fromBinary(data, offset: &offset)
                transactions.append(BeefTx(dataFormat: .rawTx, transaction: tx))
            }
        }

        return Beef(version: version, bumps: bumps, transactions: transactions)
    }
}

// MARK: - Errors

public enum BeefError: Error, LocalizedError {
    case insufficientData
    case invalidHex
    case invalidVersion(UInt32)
    case invalidDataFormat(UInt8)

    public var errorDescription: String? {
        switch self {
        case .insufficientData:
            return "BEEF data does not contain enough bytes"
        case .invalidHex:
            return "Invalid hexadecimal string"
        case .invalidVersion(let v):
            return "Invalid BEEF version: \(v)"
        case .invalidDataFormat(let f):
            return "Invalid transaction data format: \(f)"
        }
    }
}
