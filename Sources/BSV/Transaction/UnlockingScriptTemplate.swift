// SPDX-License-Identifier: Open BSV License Version 5
// Protocol for unlocking script templates used during transaction signing.

import Foundation

/// Protocol that P2PKH and future script templates conform to.
///
/// Templates know how to sign a specific input of a transaction and
/// produce the unlocking script, as well as estimate the resulting
/// script length for fee calculation.
public protocol UnlockingScriptTemplate {
    /// Sign the input at `inputIndex` of `tx` and return the unlocking script.
    func sign(tx: Transaction, inputIndex: Int) throws -> Script

    /// Estimated byte length of the unlocking script this template will produce.
    /// Used for fee estimation before signing.
    func estimateLength(tx: Transaction, inputIndex: Int) -> Int
}
