import Foundation

/// A `KeyDeriver` wrapper that memoises derivation results in an in-memory LRU cache.
///
/// Useful when the same `(protocolID, keyID, counterparty)` triple is derived repeatedly,
/// since BRC-42 derivation is dominated by an ECDH scalar multiplication.
///
/// This class is thread-safe via a single internal lock.
public final class CachedKeyDeriver: KeyDeriverAPI, @unchecked Sendable {
    public let rootKey: PrivateKey
    public let identityKey: PublicKey

    private let inner: KeyDeriver
    private let maxCacheSize: Int
    private let lock = NSLock()
    // An ordered dictionary implemented as an Array<(key, value)> — newest at the end.
    private var entries: [(String, CachedValue)] = []

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
        let cacheKey = cacheKey("derivePublicKey", protocolID, keyID, counterparty, forSelf)
        if case .publicKey(let cached) = get(cacheKey) {
            return cached
        }
        let result = try inner.derivePublicKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            forSelf: forSelf
        )
        set(cacheKey, .publicKey(result))
        return result
    }

    public func derivePrivateKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty
    ) throws -> PrivateKey {
        let cacheKey = cacheKey("derivePrivateKey", protocolID, keyID, counterparty)
        if case .privateKey(let cached) = get(cacheKey) {
            return cached
        }
        let result = try inner.derivePrivateKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty
        )
        set(cacheKey, .privateKey(result))
        return result
    }

    public func deriveSymmetricKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty
    ) throws -> SymmetricKey {
        let cacheKey = cacheKey("deriveSymmetricKey", protocolID, keyID, counterparty)
        if case .symmetricKey(let cached) = get(cacheKey) {
            return cached
        }
        let result = try inner.deriveSymmetricKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty
        )
        set(cacheKey, .symmetricKey(result))
        return result
    }

    public func revealCounterpartySecret(counterparty: WalletCounterparty) throws -> Data {
        let cacheKey = cacheKey("revealCounterpartySecret", counterparty)
        if case .data(let cached) = get(cacheKey) {
            return cached
        }
        let result = try inner.revealCounterpartySecret(counterparty: counterparty)
        set(cacheKey, .data(result))
        return result
    }

    public func revealSpecificSecret(
        counterparty: WalletCounterparty,
        protocolID: WalletProtocol,
        keyID: String
    ) throws -> Data {
        let cacheKey = cacheKey("revealSpecificSecret", counterparty, protocolID, keyID)
        if case .data(let cached) = get(cacheKey) {
            return cached
        }
        let result = try inner.revealSpecificSecret(
            counterparty: counterparty,
            protocolID: protocolID,
            keyID: keyID
        )
        set(cacheKey, .data(result))
        return result
    }

    // MARK: - Cache primitives

    private func get(_ key: String) -> CachedValue? {
        lock.lock()
        defer { lock.unlock() }
        if let index = entries.firstIndex(where: { $0.0 == key }) {
            let entry = entries.remove(at: index)
            entries.append(entry)
            return entry.1
        }
        return nil
    }

    private func set(_ key: String, _ value: CachedValue) {
        lock.lock()
        defer { lock.unlock() }
        if let index = entries.firstIndex(where: { $0.0 == key }) {
            entries.remove(at: index)
        }
        entries.append((key, value))
        while entries.count > maxCacheSize {
            entries.removeFirst()
        }
    }

    // MARK: - Key serialisation

    private func cacheKey(_ method: String, _ args: Any...) -> String {
        var parts: [String] = [method]
        for arg in args {
            parts.append(serialise(arg))
        }
        return parts.joined(separator: "|")
    }

    private func serialise(_ value: Any) -> String {
        switch value {
        case let pk as PublicKey:
            return pk.hex
        case let sk as PrivateKey:
            return sk.hex
        case let proto as WalletProtocol:
            return "\(proto.securityLevel.rawValue):\(proto.protocol)"
        case let cp as WalletCounterparty:
            switch cp {
            case .`self`: return "self"
            case .anyone: return "anyone"
            case .publicKey(let pk): return "pk:\(pk.hex)"
            }
        case let b as Bool:
            return b ? "true" : "false"
        case let s as String:
            return s
        default:
            return String(describing: value)
        }
    }
}
