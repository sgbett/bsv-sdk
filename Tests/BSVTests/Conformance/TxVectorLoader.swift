// SPDX-License-Identifier: Open BSV License Version 5
// Shared loader/parser for tx_valid.json and tx_invalid.json reference
// vectors. Used by TxValidConformanceTests and TxInvalidConformanceTests.

import Foundation
import XCTest
@testable import BSV

/// A single prevout entry from a tx_valid / tx_invalid vector row.
struct TxVectorPrevout {
    /// Previous transaction id in **internal / wire** byte order — already
    /// reversed from the big-endian display form used in the JSON fixture.
    let txidWire: Data
    /// Output index being spent.
    let outputIndex: UInt32
    /// Locking script of the prevout (parsed from reference-test short form).
    let lockingScript: Script
    /// Satoshi amount (optional in the fixture; defaults to 0 when absent).
    let satoshis: UInt64
}

/// A fully parsed tx_valid / tx_invalid vector row.
struct TxVector {
    let prevouts: [TxVectorPrevout]
    let rawTxHex: String
    let flags: String
}

/// Loads and parses reference-test transaction vectors.
enum TxVectorLoader {

    /// Flags whose semantics the Swift interpreter does not model.
    /// Vectors exercising these are skipped rather than counted as
    /// failures, matching the Phase 7 script_tests.json convention.
    /// Note: "P2SH" is NOT in this list. In Bitcoin Core's verify-flag
    /// vocabulary, "P2SH" only means "enforce P2SH semantics if the
    /// locking script is P2SH-shaped" — nearly every historic vector
    /// sets it, including ones whose actual scripts are bare P2PKH /
    /// multisig. We skip P2SH content at the script level via
    /// `containsP2SH`, not via this flag list.
    private static let unsupportedFlags: Set<String> = [
        "WITNESS",
        "TAPROOT",
        "MINIMALIF",
        "NULLFAIL",
        "LOW_S",
        "STRICTENC",
        "DERSIG",
        "CHECKLOCKTIMEVERIFY",
        "CHECKSEQUENCEVERIFY",
        "DISCOURAGE_UPGRADABLE_NOPS",
        "CLEANSTACK"
    ]

    /// Load a tx_valid / tx_invalid JSON file from the test bundle.
    static func load(_ name: String) throws -> [[Any]] {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Vectors"),
            "missing test vector file: \(name).json"
        )
        let data = try Data(contentsOf: url)
        let obj = try JSONSerialization.jsonObject(with: data, options: [])
        return try XCTUnwrap(obj as? [[Any]], "expected top-level JSON array of arrays")
    }

    /// Parse one raw JSON vector into a `TxVector`, returning `nil` for
    /// comment lines or any vector whose shape we cannot interpret, or
    /// for any vector whose prevout short-form scripts the parser does
    /// not recognise.
    static func parse(_ vec: [Any]) -> TxVector? {
        guard vec.count == 3 else { return nil }
        guard let prevoutsRaw = vec[0] as? [[Any]] else { return nil }
        guard let rawTxHex = vec[1] as? String else { return nil }
        guard let flags = vec[2] as? String else { return nil }

        var prevouts = [TxVectorPrevout]()
        for row in prevoutsRaw {
            guard row.count >= 3 else { return nil }
            guard let displayTxID = row[0] as? String else { return nil }

            // Output index is JSON-numeric.
            let idx: UInt32
            if let n = row[1] as? NSNumber {
                let signed = Int32(truncating: n)
                idx = UInt32(bitPattern: signed)
            } else {
                return nil
            }

            guard let scriptStr = row[2] as? String else { return nil }
            guard let lockingScript = ShortFormParser.parse(scriptStr) else { return nil }

            var sats: UInt64 = 0
            if row.count >= 4, let n = row[3] as? NSNumber {
                let signed = Int64(truncating: n)
                if signed > 0 { sats = UInt64(signed) }
            }

            // JSON presents the prevout txid in big-endian / display form.
            // The SDK stores txids in internal (wire) byte order, which is
            // reversed. Store the already-reversed form for direct matching.
            guard let displayBytes = Data(hex: displayTxID) else { return nil }
            let wireBytes = Data(displayBytes.reversed())

            prevouts.append(TxVectorPrevout(
                txidWire: wireBytes,
                outputIndex: idx,
                lockingScript: lockingScript,
                satoshis: sats
            ))
        }

        return TxVector(prevouts: prevouts, rawTxHex: rawTxHex, flags: flags)
    }

    /// True if any prevout in the list is a P2SH locking script.
    /// P2SH is not valid on BSV post-genesis: the interpreter does not
    /// re-execute the pushed redeem script, so any vector whose expected
    /// outcome depends on P2SH evaluation is out of scope.
    static func containsP2SH(_ prevouts: [TxVectorPrevout]) -> Bool {
        for po in prevouts where po.lockingScript.isP2SH {
            return true
        }
        return false
    }

    /// True if the vector's verify flags include anything the Swift
    /// interpreter does not enforce. Matches on comma-separated tokens.
    static func shouldSkip(flags: String) -> Bool {
        let tokens = flags
            .split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
        for tok in tokens where unsupportedFlags.contains(tok) {
            return true
        }
        return false
    }

    /// Attach each vector prevout to its matching input on `tx`.
    ///
    /// Returns `false` if any input of `tx` has no matching prevout in
    /// the vector, or if any matched prevout is P2SH (not valid on BSV
    /// post-genesis — the interpreter does not re-execute redeem scripts
    /// so the vector's expected outcome is undefined for us).
    static func attachPrevouts(to tx: Transaction, prevouts: [TxVectorPrevout]) -> Bool {
        // Build a (txid, vout) → prevout map once.
        var map = [String: TxVectorPrevout]()
        for po in prevouts {
            map["\(po.txidWire.hex):\(po.outputIndex)"] = po
        }

        for i in 0..<tx.inputs.count {
            let key = "\(tx.inputs[i].sourceTXID.hex):\(tx.inputs[i].sourceOutputIndex)"
            guard let po = map[key] else {
                return false
            }
            if po.lockingScript.isP2SH {
                return false
            }
            tx.inputs[i].sourceLockingScript = po.lockingScript
            tx.inputs[i].sourceSatoshis = po.satoshis
        }
        return true
    }
}
