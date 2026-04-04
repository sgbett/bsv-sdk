// SPDX-License-Identifier: Open BSV License Version 5

import Foundation

/// Errors related to transaction parsing and construction.
public enum TransactionError: Error {
    case dataTooShort
    case invalidFormat
    case missingSighashData
    case signingFailed
}
