// SPDX-License-Identifier: Open BSV License Version 5
// Retry helper that reacts to double-spend errors by re-broadcasting the
// competing transaction before retrying the original operation.
//
// Ported from ts-sdk src/overlay-tools/withDoubleSpendRetry.ts. Swift does
// not have a direct equivalent of the ts-sdk `WERR_REVIEW_ACTIONS` class,
// so we express double-spend detection via a small protocol that callers
// can conform their own error types to. The retry helper itself is a
// generic async function that runs `operation` up to `maxRetries` times,
// broadcasting the competing transaction on the overlay whenever the
// operation throws a double-spend error.

import Foundation

/// The maximum number of retries attempted by `withDoubleSpendRetry`.
public let defaultDoubleSpendRetryLimit = 5

/// A competing transaction reported by a wallet review-action error.
public struct DoubleSpendCompetingAction: Sendable {
    /// The serialised BEEF of the competing transaction chain.
    public var beef: Data
    /// The txid of the competing transaction (display order hex).
    public var txid: String

    public init(beef: Data, txid: String) {
        self.beef = beef
        self.txid = txid
    }
}

/// An error that exposes a double-spend competing action. Conform the
/// wallet's action-review error type to this protocol to opt into the
/// retry loop.
public protocol DoubleSpendReportingError: Error {
    /// Return the competing action details, or `nil` if the error is not
    /// a double-spend.
    var competingAction: DoubleSpendCompetingAction? { get }
}

/// Attempt `operation` up to `maxRetries` times, broadcasting the
/// competing transaction on the overlay between retries when a
/// double-spend error is reported.
///
/// - Parameters:
///   - maxRetries: Maximum number of attempts.
///   - broadcaster: The SHIP broadcaster used to sync missing state.
///   - operation: The async operation to run.
/// - Throws: The underlying error if all retries are exhausted or the
///   error is not a double-spend.
public func withDoubleSpendRetry<T: Sendable>(
    maxRetries: Int = defaultDoubleSpendRetryLimit,
    broadcaster: SHIPBroadcaster,
    operation: @Sendable () async throws -> T
) async throws -> T {
    var attempts = 0
    var lastError: Error = OverlayError.networkFailure("retry loop did not execute")

    while attempts < maxRetries {
        attempts += 1
        do {
            return try await operation()
        } catch let error as DoubleSpendReportingError {
            lastError = error
            guard attempts < maxRetries,
                  let competing = error.competingAction else {
                throw error
            }
            do {
                let beef = try Beef.fromBinary(competing.beef)
                let tx: Transaction? = beef.transactions
                    .last(where: { $0.transaction != nil })?
                    .transaction
                if let competingTx = tx {
                    // Broadcast the competing transaction so the overlay
                    // picks up the state we were missing, then retry.
                    _ = try await broadcaster.broadcast(competingTx)
                }
            } catch {
                // If the competing broadcast fails, rethrow the original
                // double-spend error so the caller sees the real cause.
                throw lastError
            }
        } catch {
            throw error
        }
    }

    throw lastError
}
