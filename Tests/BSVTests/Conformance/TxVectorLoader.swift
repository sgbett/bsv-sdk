// SPDX-License-Identifier: Open BSV License Version 5
// Shared helpers for tx_valid.json / tx_invalid.json reference vectors.

import Foundation
@testable import BSV

/// A parsed reference-test transaction vector.
struct TxVector {
    /// List of prevouts the spending transaction consumes.
    var prevouts: [TxVectorPrevout]
    /// Serialised spending transaction, as hex.
    var rawTxHex: String
    /// Raw comma-separated verify flags string (may be empty).
    var flags: String
}

/// A single prevout declared by a test vector.
struct TxVectorPrevout {
    /// Previous transaction ID in **display** (reversed) byte order, as the
    /// JSON fixture presents it.
    var displayTxID: String
    /// Output index being spent.
    var outputIndex: UInt32
    /// Locking script of the output, parsed from reference-test short form.
    var lockingScript: Script
    /// Satoshi amount (optional in the fixture; defaults to 0 when absent).
    var satoshis: UInt64
}

/// Loads and parses reference-test transaction vectors from the `Vectors/`
/// bundle resources and adapts them for use with `Interpreter.verify`.
enum TxVectorLoader {

    /// Load a tx_valid / tx_invalid JSON file from the test bundle.
    static func load(_ name: String) throws -> [[Any]] {
        guard let url = Bundle.module.url(
            forResource: name, withExtension: "json", subdirectory: "Vectors"
        ) else {
            throw NSError(domain: "TxVectorLoader", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "missing vector file \(name).json"])
        }
        let data = try Data(contentsOf: url)
        let obj = try JSONSerialization.jsonObject(with: data, options: [])
        guard let arr = obj as? [[Any]] else {
            throw NSError(domain: "TxVectorLoader", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "vector file not an array of arrays"])
        }
        return arr
    }

    /// Parse one raw JSON vector into a `TxVector`, returning `nil` for
    /// comment lines or any vector whose shape we cannot interpret.
    static func parse(_ vec: [Any]) -> TxVector? {
        // Comment lines are single-string arrays.
        guard vec.count == 3 else { return nil }
        guard let prevoutsRaw = vec[0] as? [[Any]] else { return nil }
        guard let rawTxHex = vec[1] as? String else { return nil }
        guard let flags = vec[2] as? String else { return nil }

        var prevouts = [TxVectorPrevout]()
        for row in prevoutsRaw {
            guard row.count >= 3 else { return nil }
            guard let displayTxID = row[0] as? String else { return nil }

            // Output index may be an Int or NSNumber.
            let idx: UInt32
            if let n = row[1] as? Int {
                idx = UInt32(bitPattern: Int32(n))
            } else if let n = row[1] as? NSNumber {
                idx = UInt32(bitPattern: Int32(truncating: n))
            } else {
                return nil
            }

            guard let scriptStr = row[2] as? String else { return nil }
            guard let lockingScript = ShortFormParser.parse(scriptStr) else { return nil }

            var sats: UInt64 = 0
            if row.count >= 4 {
                if let n = row[3] as? Int {
                    sats = UInt64(max(0, n))
                } else if let n = row[3] as? NSNumber {
                    sats = UInt64(max(0, Int(truncating: n)))
                }
            }

            prevouts.append(TxVectorPrevout(
                displayTxID: displayTxID,
                outputIndex: idx,
                lockingScript: lockingScript,
                satoshis: sats
            ))
        }

        return TxVector(prevouts: prevouts, rawTxHex: rawTxHex, flags: flags)
    }

    /// Whether a vector should be skipped because its flags depend on
    /// features the Swift post-genesis interpreter does not implement.
    ///
    /// Note: almost every vector includes "P2SH" in its flag list — this
    /// is the Bitcoin Core default, not a requirement to actually evaluate
    /// a P2SH redeem script. We therefore do not skip on P2SH here; P2SH
    /// wrapping is detected by inspecting the locking scripts themselves
    /// (see `looksLikeP2SH`).
    static func shouldSkip(flags: String) -> Bool {
        if flags.contains("WITNESS") || flags.contains("TAPROOT") {
            return true
        }
        return false
    }

    /// Whether any of the prevout locking scripts are P2SH wrappers
    /// (`HASH160 <20-byte hash> EQUAL`). BSV does not implement P2SH
    /// redeem-script evaluation, so these vectors are out of scope.
    static func containsP2SH(_ prevouts: [TxVectorPrevout]) -> Bool {
        for p in prevouts where p.lockingScript.isP2SH {
            return true
        }
        return false
    }

    /// Attach the prevouts from a vector onto each input of the parsed
    /// transaction. Returns false if any input cannot be matched to a
    /// declared prevout.
    ///
    /// Note: transaction fixtures list prevout txids in **display** (reversed)
    /// byte order, while `TransactionInput.sourceTXID` stores them in
    /// internal wire order. We compare against the reversed hex to match.
    static func attachPrevouts(to tx: Transaction, prevouts: [TxVectorPrevout]) -> Bool {
        for i in 0..<tx.inputs.count {
            let input = tx.inputs[i]
            let wireHex = input.sourceTXID.reversed().map { String(format: "%02x", $0) }.joined()

            guard let match = prevouts.first(where: {
                $0.displayTxID.lowercased() == wireHex && $0.outputIndex == input.sourceOutputIndex
            }) else {
                return false
            }

            tx.inputs[i].sourceLockingScript = match.lockingScript
            tx.inputs[i].sourceSatoshis = match.satoshis
        }
        return true
    }
}
