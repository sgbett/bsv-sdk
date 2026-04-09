import XCTest
@testable import BSV

/// Tests for `CachedKeyDeriver`.
///
/// Covers cache correctness (hit returns the same value as a fresh call,
/// different arguments don't collide), LRU eviction ordering when the
/// cache fills up, and concurrent access under contention.
final class CachedKeyDeriverTests: XCTestCase {

    private func makeDeriver(maxCacheSize: Int = 1000) -> (CachedKeyDeriver, KeyDeriver) {
        let root = PrivateKey.random()!
        let cached = CachedKeyDeriver(rootKey: root, maxCacheSize: maxCacheSize)
        let uncached = KeyDeriver(rootKey: root)
        return (cached, uncached)
    }

    private var testProtocol: WalletProtocol {
        WalletProtocol(securityLevel: .app, protocol: "cached keyderiver test")
    }

    // MARK: - Correctness

    func testCacheHitMatchesUncachedResult() throws {
        let (cached, uncached) = makeDeriver()
        let counterparty = WalletCounterparty.publicKey(
            PublicKey.fromPrivateKey(PrivateKey.random()!)
        )

        let first = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "1", counterparty: counterparty
        )
        let second = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "1", counterparty: counterparty
        )
        let reference = try uncached.derivePublicKey(
            protocolID: testProtocol, keyID: "1", counterparty: counterparty
        )

        XCTAssertEqual(first.hex, reference.hex)
        XCTAssertEqual(second.hex, reference.hex, "second call should be served from cache")
    }

    func testDifferentKeyIDsDoNotCollide() throws {
        let (cached, _) = makeDeriver()
        let counterparty = WalletCounterparty.publicKey(
            PublicKey.fromPrivateKey(PrivateKey.random()!)
        )

        let a = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "a", counterparty: counterparty
        )
        let b = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "b", counterparty: counterparty
        )
        XCTAssertNotEqual(a.hex, b.hex)
    }

    func testDifferentCounterpartiesDoNotCollide() throws {
        let (cached, _) = makeDeriver()
        let cp1 = WalletCounterparty.publicKey(
            PublicKey.fromPrivateKey(PrivateKey.random()!)
        )
        let cp2 = WalletCounterparty.publicKey(
            PublicKey.fromPrivateKey(PrivateKey.random()!)
        )

        let a = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "x", counterparty: cp1
        )
        let b = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "x", counterparty: cp2
        )
        XCTAssertNotEqual(a.hex, b.hex)
    }

    func testForSelfDiscriminatesCacheEntries() throws {
        let (cached, _) = makeDeriver()
        let counterparty = WalletCounterparty.publicKey(
            PublicKey.fromPrivateKey(PrivateKey.random()!)
        )

        let forSelf = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "1", counterparty: counterparty, forSelf: true
        )
        let forOther = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "1", counterparty: counterparty, forSelf: false
        )
        XCTAssertNotEqual(forSelf.hex, forOther.hex)
    }

    func testPrivateAndPublicCachesDoNotCollide() throws {
        let (cached, _) = makeDeriver()
        let counterparty = WalletCounterparty.publicKey(
            PublicKey.fromPrivateKey(PrivateKey.random()!)
        )

        _ = try cached.derivePrivateKey(
            protocolID: testProtocol, keyID: "1", counterparty: counterparty
        )
        // Must still return a PublicKey, not fail an internal type cast.
        let pub = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "1", counterparty: counterparty, forSelf: true
        )
        XCTAssertFalse(pub.hex.isEmpty)
    }

    // MARK: - LRU eviction

    func testLRUEvictsLeastRecentlyUsedWhenFull() throws {
        // maxCacheSize = 3, insert four keys — the first one must be evicted.
        let (cached, _) = makeDeriver(maxCacheSize: 3)
        let counterparty = WalletCounterparty.publicKey(
            PublicKey.fromPrivateKey(PrivateKey.random()!)
        )

        // Insert four distinct keys: a, b, c, d. "a" should be evicted.
        for keyID in ["a", "b", "c", "d"] {
            _ = try cached.derivePublicKey(
                protocolID: testProtocol, keyID: keyID, counterparty: counterparty
            )
        }

        // Probe the cache indirectly: override inner by checking whether
        // hits touch state. Inspect via reflection of the private lookup.
        let mirror = Mirror(reflecting: cached)
        let lookupChild = mirror.children.first { $0.label == "lookup" }
        XCTAssertNotNil(lookupChild)
        let lookup = lookupChild?.value as? [String: Any] ?? [:]
        XCTAssertEqual(lookup.count, 3, "cache size must be capped at maxCacheSize")

        // The evicted entry must be the least recent one ("a").
        let keys = lookup.keys.map { $0 }
        XCTAssertFalse(keys.contains(where: { $0.contains("|a|") }), "oldest key should be evicted")
        XCTAssertTrue(keys.contains(where: { $0.contains("|b|") }))
        XCTAssertTrue(keys.contains(where: { $0.contains("|c|") }))
        XCTAssertTrue(keys.contains(where: { $0.contains("|d|") }))
    }

    func testLRUAccessOrderPromotesRecency() throws {
        // maxCacheSize = 3. Insert a, b, c. Touch "a" again. Insert d.
        // Now "b" (not "a") should be evicted.
        let (cached, _) = makeDeriver(maxCacheSize: 3)
        let counterparty = WalletCounterparty.publicKey(
            PublicKey.fromPrivateKey(PrivateKey.random()!)
        )

        for keyID in ["a", "b", "c"] {
            _ = try cached.derivePublicKey(
                protocolID: testProtocol, keyID: keyID, counterparty: counterparty
            )
        }
        // Touch "a" — it should now be the most-recent entry.
        _ = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "a", counterparty: counterparty
        )
        // Insert "d" — "b" (now the oldest) should be evicted.
        _ = try cached.derivePublicKey(
            protocolID: testProtocol, keyID: "d", counterparty: counterparty
        )

        let mirror = Mirror(reflecting: cached)
        let lookupChild = mirror.children.first { $0.label == "lookup" }
        let lookup = lookupChild?.value as? [String: Any] ?? [:]
        XCTAssertEqual(lookup.count, 3)
        let keys = lookup.keys.map { $0 }
        XCTAssertTrue(keys.contains(where: { $0.contains("|a|") }), "recently accessed 'a' must survive")
        XCTAssertFalse(keys.contains(where: { $0.contains("|b|") }), "'b' must be evicted as the new LRU")
        XCTAssertTrue(keys.contains(where: { $0.contains("|c|") }))
        XCTAssertTrue(keys.contains(where: { $0.contains("|d|") }))
    }

    // MARK: - Concurrency

    func testConcurrentAccessIsSafe() throws {
        let (cached, _) = makeDeriver(maxCacheSize: 32)
        let counterparty = WalletCounterparty.publicKey(
            PublicKey.fromPrivateKey(PrivateKey.random()!)
        )

        // Fire 200 concurrent derivations across 50 distinct keys so some
        // calls hit the cache and some force eviction. This should not
        // crash or deadlock under TSan.
        final class ErrorBox: @unchecked Sendable {
            private let lock = NSLock()
            private var _error: Error?
            var error: Error? {
                lock.lock(); defer { lock.unlock() }
                return _error
            }
            func set(_ e: Error) {
                lock.lock(); defer { lock.unlock() }
                if _error == nil { _error = e }
            }
        }
        let errors = ErrorBox()

        let group = DispatchGroup()
        let queue = DispatchQueue.global(qos: .userInitiated)
        let proto = testProtocol
        for i in 0..<200 {
            group.enter()
            queue.async {
                defer { group.leave() }
                do {
                    _ = try cached.derivePublicKey(
                        protocolID: proto,
                        keyID: "key-\(i % 50)",
                        counterparty: counterparty
                    )
                } catch {
                    errors.set(error)
                }
            }
        }
        group.wait()
        XCTAssertNil(errors.error)
    }
}
