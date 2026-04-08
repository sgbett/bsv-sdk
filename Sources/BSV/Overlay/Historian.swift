// SPDX-License-Identifier: Open BSV License Version 5
// Historian: build a chronological history of interpreted output values by
// traversing the input ancestry of a starting transaction.
//
// Ported from ts-sdk src/overlay-tools/Historian.ts. An interpreter maps
// `(tx, outputIndex) -> T?` and controls what counts as "history". The
// traversal is cycle-safe, order is oldest-first, and optional caching
// deduplicates repeated queries across the same interpreter version and
// context key.

import Foundation

/// Function shape used by `Historian`: decodes a single output into a
/// domain value, or returns `nil` if the output does not contribute to
/// history.
///
/// - Parameters:
///   - tx: The transaction containing the output.
///   - outputIndex: Index of the output within `tx.outputs`.
///   - context: Optional caller-supplied context.
/// - Returns: The interpreted domain value, or `nil` if the output is
///   not relevant for this interpreter/context.
public typealias HistorianInterpreter<T, C> = (
    _ tx: Transaction,
    _ outputIndex: Int,
    _ context: C?
) async throws -> T?

/// Key derivation strategy used when caching Historian results.
public typealias HistorianContextKey<C> = (C?) -> String

/// Historian traverses a transaction's input ancestry to build a
/// chronological history of interpreted values.
///
/// `Historian` is not an actor: `Transaction` is a class and therefore not
/// `Sendable`, so the traversal and interpreter both run on the caller's
/// isolation domain. The optional cache is layered on top as an `actor`.
public struct Historian<T: Sendable, C> {
    private let interpreter: HistorianInterpreter<T, C>
    private let contextKeyFn: HistorianContextKey<C>
    private let interpreterVersion: String
    private let cache: HistorianCache<T>?

    /// Create a new historian.
    ///
    /// - Parameters:
    ///   - interpreter: Function that decodes a single output.
    ///   - interpreterVersion: Bump this when interpreter semantics change to
    ///     invalidate any cached entries keyed by the old version.
    ///   - enableCache: When `true`, builds an in-memory cache keyed by
    ///     `interpreterVersion|txid|contextKey`.
    ///   - contextKeyFn: Optional closure that maps a context to a stable
    ///     cache-key fragment. Defaults to `"nil"` or `"ctx:\(value)"`.
    public init(
        interpreter: @escaping HistorianInterpreter<T, C>,
        interpreterVersion: String = "v1",
        enableCache: Bool = false,
        contextKeyFn: HistorianContextKey<C>? = nil
    ) {
        self.interpreter = interpreter
        self.interpreterVersion = interpreterVersion
        self.cache = enableCache ? HistorianCache() : nil
        self.contextKeyFn = contextKeyFn ?? { context in
            guard let context else { return "nil" }
            return "ctx:\(String(describing: context))"
        }
    }

    /// Build a chronological history of interpreted values.
    ///
    /// The traversal starts at `startTransaction`, walks
    /// `inputs[].sourceTransaction` recursively, and collects interpreted
    /// values. Each transaction is visited at most once. Results are
    /// returned oldest-first.
    public func buildHistory(
        startTransaction: Transaction,
        context: C? = nil
    ) async throws -> [T] {
        let key = cacheKey(for: startTransaction, context: context)
        if let cache, let cached = await cache.get(key) {
            return cached
        }

        var history: [T] = []
        var visited = Set<String>()
        try await traverse(
            transaction: startTransaction,
            context: context,
            visited: &visited,
            history: &history
        )
        // Traversal appends in reverse chronological order, so reverse it.
        let chronological = Array(history.reversed())

        if let cache {
            await cache.set(key, chronological)
        }
        return chronological
    }

    // MARK: - Private helpers

    private func cacheKey(for tx: Transaction, context: C?) -> String {
        "\(interpreterVersion)|\(tx.txid())|\(contextKeyFn(context))"
    }

    private func traverse(
        transaction: Transaction,
        context: C?,
        visited: inout Set<String>,
        history: inout [T]
    ) async throws {
        let txid = transaction.txid()
        if visited.contains(txid) { return }
        visited.insert(txid)

        for index in 0..<transaction.outputs.count {
            do {
                if let value = try await interpreter(transaction, index, context) {
                    history.append(value)
                }
            } catch {
                // Swallow interpreter errors — they just mean the output is
                // not relevant for this history.
            }
        }

        for input in transaction.inputs {
            if let parent = input.sourceTransaction {
                try await traverse(
                    transaction: parent,
                    context: context,
                    visited: &visited,
                    history: &history
                )
            }
        }
    }
}

/// A tiny actor-backed cache used by `Historian` when caching is enabled.
///
/// This is not exposed outside the overlay module; callers that want
/// externally-visible caching should wrap their own storage.
final actor HistorianCache<T: Sendable> {
    private var storage: [String: [T]] = [:]

    func get(_ key: String) -> [T]? { storage[key] }
    func set(_ key: String, _ value: [T]) { storage[key] = value }
}
