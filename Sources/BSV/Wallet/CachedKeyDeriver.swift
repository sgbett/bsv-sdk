import Foundation

/// A `KeyDeriver` wrapper that memoises derivation results in an in-memory LRU cache.
///
/// Useful when the same `(protocolID, keyID, counterparty)` triple is derived repeatedly,
/// since BRC-42 derivation is dominated by an ECDH scalar multiplication.
///
/// The cache is implemented as a dictionary plus a doubly-linked list, so
/// every get / set / eviction is O(1). The previous implementation used an
/// `Array<(String, CachedValue)>` with `firstIndex(where:) + remove + append`
/// which degraded to O(n) on every call at the default `maxCacheSize = 1000`.
///
/// This class is thread-safe via a single internal lock.
public final class CachedKeyDeriver: KeyDeriverAPI, @unchecked Sendable {
    public let rootKey: PrivateKey
    public let identityKey: PublicKey

    private let inner: KeyDeriver
    private let maxCacheSize: Int
    private let lock = NSLock()

    // O(1) LRU: a dictionary maps keys to nodes, and a doubly-linked list
    // tracks access order with head = least-recently-used, tail = most-recent.
    private final class Node {
        let key: String
        var value: CachedValue
        var prev: Node?
        var next: Node?

        init(key: String, value: CachedValue) {
            self.key = key
            self.value = value
        }
    }
    private var lookup: [String: Node] = [:]
    private var head: Node?   // least-recently-used
    private var tail: Node?   // most-recently-used

    private enum CachedValue {
        case publicKey(PublicKey)
        case privateKey(PrivateKey)
        case symmetricKey(SymmetricKey)
        case data(Data)
    }

    public init(rootKey: PrivateKey, maxCacheSize: Int = 1000) {
        self.rootKey = rootKey
        self.identityKey = PublicKey.fromPrivateKey(rootKey)
        self.inner = KeyDeriver(rootKey: rootKey)
        self.maxCacheSize = max(1, maxCacheSize)
    }

    // MARK: - KeyDeriverAPI

    public func derivePublicKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty,
        forSelf: Bool = false
    ) throws -> PublicKey {
        let key = "derivePublicKey|" + encodeProtocol(protocolID)
            + "|" + keyID
            + "|" + encodeCounterparty(counterparty)
            + "|" + (forSelf ? "1" : "0")
        if case .publicKey(let cached) = get(key) {
            return cached
        }
        let result = try inner.derivePublicKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            forSelf: forSelf
        )
        set(key, .publicKey(result))
        return result
    }

    public func derivePrivateKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty
    ) throws -> PrivateKey {
        let key = "derivePrivateKey|" + encodeProtocol(protocolID)
            + "|" + keyID
            + "|" + encodeCounterparty(counterparty)
        if case .privateKey(let cached) = get(key) {
            return cached
        }
        let result = try inner.derivePrivateKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty
        )
        set(key, .privateKey(result))
        return result
    }

    public func deriveSymmetricKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty
    ) throws -> SymmetricKey {
        let key = "deriveSymmetricKey|" + encodeProtocol(protocolID)
            + "|" + keyID
            + "|" + encodeCounterparty(counterparty)
        if case .symmetricKey(let cached) = get(key) {
            return cached
        }
        let result = try inner.deriveSymmetricKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty
        )
        set(key, .symmetricKey(result))
        return result
    }

    public func revealCounterpartySecret(counterparty: WalletCounterparty) throws -> Data {
        let key = "revealCounterpartySecret|" + encodeCounterparty(counterparty)
        if case .data(let cached) = get(key) {
            return cached
        }
        let result = try inner.revealCounterpartySecret(counterparty: counterparty)
        set(key, .data(result))
        return result
    }

    public func revealSpecificSecret(
        counterparty: WalletCounterparty,
        protocolID: WalletProtocol,
        keyID: String
    ) throws -> Data {
        let key = "revealSpecificSecret|" + encodeCounterparty(counterparty)
            + "|" + encodeProtocol(protocolID)
            + "|" + keyID
        if case .data(let cached) = get(key) {
            return cached
        }
        let result = try inner.revealSpecificSecret(
            counterparty: counterparty,
            protocolID: protocolID,
            keyID: keyID
        )
        set(key, .data(result))
        return result
    }

    // MARK: - Cache primitives

    private func get(_ key: String) -> CachedValue? {
        lock.lock()
        defer { lock.unlock() }
        guard let node = lookup[key] else { return nil }
        moveToTail(node)
        return node.value
    }

    private func set(_ key: String, _ value: CachedValue) {
        lock.lock()
        defer { lock.unlock() }
        if let node = lookup[key] {
            node.value = value
            moveToTail(node)
            return
        }
        let node = Node(key: key, value: value)
        lookup[key] = node
        appendToTail(node)
        if lookup.count > maxCacheSize, let victim = head {
            removeNode(victim)
            lookup.removeValue(forKey: victim.key)
        }
    }

    // MARK: - Linked-list helpers (O(1))

    private func appendToTail(_ node: Node) {
        node.prev = tail
        node.next = nil
        tail?.next = node
        tail = node
        if head == nil { head = node }
    }

    private func removeNode(_ node: Node) {
        let prev = node.prev
        let next = node.next
        prev?.next = next
        next?.prev = prev
        if head === node { head = next }
        if tail === node { tail = prev }
        node.prev = nil
        node.next = nil
    }

    private func moveToTail(_ node: Node) {
        if tail === node { return }
        removeNode(node)
        appendToTail(node)
    }

    // MARK: - Key serialisation

    /// All cache-key inputs come from a fixed set of strongly typed values,
    /// so encoding is exhaustive by construction — no `String(describing:)`
    /// fallback, which previously risked silently aliasing distinct values
    /// that happen to stringify identically.

    private func encodeProtocol(_ proto: WalletProtocol) -> String {
        "\(proto.securityLevel.rawValue):\(proto.protocol)"
    }

    private func encodeCounterparty(_ cp: WalletCounterparty) -> String {
        switch cp {
        case .`self`: return "self"
        case .anyone: return "anyone"
        case .publicKey(let pk): return "pk:\(pk.hex)"
        }
    }
}
