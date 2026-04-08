import Foundation

/// A single leaf node in a Merkle path level.
public struct MerklePathLeaf {
    /// The offset (position) of this leaf within its level.
    public var offset: UInt64
    /// The 32-byte hash in internal byte order, or `nil` if this is a duplicate marker.
    public var hash: Data?
    /// Whether this leaf represents a transaction ID (i.e. a leaf we are proving).
    public var txid: Bool
    /// Whether this leaf is a duplicate of its sibling (Bitcoin Merkle tree behaviour).
    public var duplicate: Bool

    public init(offset: UInt64, hash: Data? = nil, txid: Bool = false, duplicate: Bool = false) {
        self.offset = offset
        self.hash = hash
        self.txid = txid
        self.duplicate = duplicate
    }
}

/// BRC-74 Merkle Path (BUMP format).
///
/// Proves a transaction's inclusion in a block by encoding the minimal set of
/// sibling hashes needed to recompute the Merkle root.
///
/// Hashes are stored in internal byte order (little-endian, as used on the wire).
/// Display-order (big-endian, as shown in block explorers) is the reverse.
public struct MerklePath {
    /// The height of the block containing the proved transaction(s).
    public var blockHeight: UInt32
    /// The path levels. Level 0 is the leaf (transaction) level; each subsequent
    /// level moves towards the root. Each level contains one or more `MerklePathLeaf` entries.
    public var path: [[MerklePathLeaf]]

    // MARK: - Initialisers

    public init(blockHeight: UInt32, path: [[MerklePathLeaf]]) {
        self.blockHeight = blockHeight
        self.path = path
    }

    /// Decode a Merkle path from its BUMP binary representation.
    public static func fromBinary(_ data: Data) throws -> MerklePath {
        guard data.count >= 2 else {
            throw MerklePathError.insufficientData
        }
        var offset = 0
        return try fromBinary(data, offset: &offset)
    }

    /// Decode a Merkle path from binary data starting at the given offset.
    /// The offset is advanced past the consumed bytes.
    public static func fromBinary(_ data: Data, offset: inout Int) throws -> MerklePath {
        guard let (blockHeightVal, bhBytes) = VarInt.decode(data, offset: offset) else {
            throw MerklePathError.insufficientData
        }
        offset += bhBytes

        guard offset < data.count else {
            throw MerklePathError.insufficientData
        }
        let treeHeight = Int(data[data.startIndex + offset])
        offset += 1

        var path = [[MerklePathLeaf]]()
        path.reserveCapacity(treeHeight)

        for _ in 0..<treeHeight {
            guard let (nLeaves, nlBytes) = VarInt.decode(data, offset: offset) else {
                throw MerklePathError.insufficientData
            }
            offset += nlBytes

            var level = [MerklePathLeaf]()
            level.reserveCapacity(Int(nLeaves))

            for _ in 0..<nLeaves {
                guard let (leafOffset, loBytes) = VarInt.decode(data, offset: offset) else {
                    throw MerklePathError.insufficientData
                }
                offset += loBytes

                guard offset < data.count else {
                    throw MerklePathError.insufficientData
                }
                let flags = data[data.startIndex + offset]
                offset += 1

                let isDuplicate = (flags & 1) != 0
                let isTxid = (flags & 2) != 0

                var hash: Data?
                if !isDuplicate {
                    guard offset + 32 <= data.count else {
                        throw MerklePathError.insufficientData
                    }
                    hash = data[(data.startIndex + offset)..<(data.startIndex + offset + 32)]
                    offset += 32
                }

                level.append(MerklePathLeaf(
                    offset: leafOffset,
                    hash: hash,
                    txid: isTxid,
                    duplicate: isDuplicate
                ))
            }

            // Sort by offset for consistency.
            level.sort { $0.offset < $1.offset }
            path.append(level)
        }

        return MerklePath(blockHeight: UInt32(blockHeightVal), path: path)
    }

    /// Decode a Merkle path from a hexadecimal BUMP string.
    public static func fromHex(_ hex: String) throws -> MerklePath {
        guard let data = Data(hex: hex) else {
            throw MerklePathError.invalidHex
        }
        return try fromBinary(data)
    }

    // MARK: - Serialisation

    /// Encode the Merkle path to BUMP binary format.
    public func toBinary() -> Data {
        var data = VarInt.encode(UInt64(blockHeight))
        data.append(UInt8(path.count))

        for level in path {
            data.append(contentsOf: VarInt.encode(UInt64(level.count)))
            for leaf in level {
                data.append(contentsOf: VarInt.encode(leaf.offset))
                var flags: UInt8 = 0
                if leaf.duplicate { flags |= 1 }
                if leaf.txid { flags |= 2 }
                data.append(flags)
                if !leaf.duplicate, let hash = leaf.hash {
                    data.append(hash)
                }
            }
        }

        return data
    }

    /// Encode the Merkle path to a hexadecimal BUMP string.
    public func toHex() -> String {
        toBinary().hex
    }

    // MARK: - Root computation

    /// Compute the Merkle root for a given transaction ID (in internal byte order).
    ///
    /// If `txid` is `nil`, the first available hash at level 0 is used.
    ///
    /// - Parameter txid: 32-byte transaction hash in internal byte order.
    /// - Returns: The 32-byte Merkle root in internal byte order.
    public func computeRoot(txid: Data? = nil) throws -> Data {
        var targetTxid = txid

        // If no txid provided, pick the first available hash from level 0.
        if targetTxid == nil {
            for leaf in path[0] {
                if let h = leaf.hash {
                    targetTxid = h
                    break
                }
            }
        }
        guard let resolvedTxid = targetTxid else {
            throw MerklePathError.noTxidProvided
        }

        // Single transaction in block — the root is the txid itself.
        if path.count == 1 && path[0].count == 1 {
            return resolvedTxid
        }

        // Build an indexed lookup for efficient access.
        var indexedPath = [[UInt64: MerklePathLeaf]]()
        for level in path {
            var dict = [UInt64: MerklePathLeaf]()
            for leaf in level {
                dict[leaf.offset] = leaf
            }
            indexedPath.append(dict)
        }

        // Find the leaf matching the txid at level 0.
        guard let txLeaf = path[0].first(where: { $0.hash == resolvedTxid }) else {
            throw MerklePathError.txidNotFound
        }

        var workingHash = resolvedTxid
        let index = txLeaf.offset

        // Compute effective tree height from max offset (handles compound paths).
        let maxOffset = path[0].reduce(UInt64(0)) { max($0, $1.offset) }
        let bitsNeeded = 64 - maxOffset.leadingZeroBitCount
        let effectiveHeight = max(path.count, bitsNeeded)

        for height in 0..<effectiveHeight {
            let siblingOffset = (index >> height) ^ 1
            guard let sibling = getOffsetLeaf(
                indexedPath: indexedPath, layer: height, offset: siblingOffset
            ) else {
                throw MerklePathError.missingHash(height: height)
            }

            if sibling.duplicate {
                workingHash = merkleTreeParent(left: workingHash, right: workingHash)
            } else if let siblingHash = sibling.hash {
                if siblingOffset % 2 != 0 {
                    workingHash = merkleTreeParent(left: workingHash, right: siblingHash)
                } else {
                    workingHash = merkleTreeParent(left: siblingHash, right: workingHash)
                }
            } else {
                throw MerklePathError.missingHash(height: height)
            }
        }

        return workingHash
    }

    /// Compute the Merkle root from a hex-encoded txid (display order, i.e. big-endian).
    ///
    /// - Parameter txid: Transaction ID in display (big-endian) hex.
    /// - Returns: The Merkle root in display (big-endian) hex.
    public func computeRootHex(txid: String? = nil) throws -> String {
        let internalTxid: Data?
        if let txid {
            guard let data = Data(hex: txid) else {
                throw MerklePathError.invalidHex
            }
            internalTxid = Data(data.reversed())
        } else {
            internalTxid = nil
        }
        let root = try computeRoot(txid: internalTxid)
        return Data(root.reversed()).hex
    }

    // MARK: - Private helpers

    /// Compute double-SHA256 of concatenated left and right hashes (internal byte order).
    private func merkleTreeParent(left: Data, right: Data) -> Data {
        var combined = Data(capacity: 64)
        combined.append(left)
        combined.append(right)
        return Digest.sha256d(combined)
    }

    /// Recursively look up a leaf at a given layer and offset, computing intermediate
    /// nodes from children if necessary (for compound paths).
    private func getOffsetLeaf(
        indexedPath: [[UInt64: MerklePathLeaf]],
        layer: Int,
        offset: UInt64
    ) -> MerklePathLeaf? {
        // Direct lookup if this layer exists in the indexed path.
        if layer < indexedPath.count, let leaf = indexedPath[layer][offset] {
            return leaf
        }

        // Cannot recurse below level 0.
        if layer == 0 { return nil }

        let childOffset = offset * 2
        guard let left = getOffsetLeaf(indexedPath: indexedPath, layer: layer - 1, offset: childOffset),
              let right = getOffsetLeaf(indexedPath: indexedPath, layer: layer - 1, offset: childOffset + 1)
        else {
            return nil
        }

        guard let leftHash = left.hash else { return nil }

        let parentHash: Data
        if right.duplicate {
            parentHash = merkleTreeParent(left: leftHash, right: leftHash)
        } else if let rightHash = right.hash {
            parentHash = merkleTreeParent(left: leftHash, right: rightHash)
        } else {
            return nil
        }

        return MerklePathLeaf(offset: offset, hash: parentHash)
    }
}

// MARK: - Errors

public enum MerklePathError: Error, LocalizedError {
    case insufficientData
    case invalidHex
    case noTxidProvided
    case txidNotFound
    case missingHash(height: Int)

    public var errorDescription: String? {
        switch self {
        case .insufficientData:
            return "BUMP data does not contain enough bytes to be valid"
        case .invalidHex:
            return "Invalid hexadecimal string"
        case .noTxidProvided:
            return "No transaction ID provided and none found in path"
        case .txidNotFound:
            return "Transaction ID not found in the Merkle path"
        case .missingHash(let height):
            return "Missing hash at height \(height)"
        }
    }
}
