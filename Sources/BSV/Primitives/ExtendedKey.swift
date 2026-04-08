import Foundation

/// BIP-32 Hierarchical Deterministic (HD) extended key.
///
/// Supports master key generation from seed, child derivation (normal and hardened),
/// path-based derivation, xprv/xpub serialisation, and public key neutering.
public struct ExtendedKey: Sendable, Equatable {

    // MARK: - Constants

    /// Index at which hardened derivation begins (2^31).
    public static let hardenedKeyStart: UInt32 = 0x80000000

    /// Minimum seed length in bytes (128 bits).
    public static let minSeedBytes = 16

    /// Maximum seed length in bytes (512 bits).
    public static let maxSeedBytes = 64

    /// Version bytes for mainnet xprv.
    static let xprvVersion = Data([0x04, 0x88, 0xAD, 0xE4])

    /// Version bytes for mainnet xpub.
    static let xpubVersion = Data([0x04, 0x88, 0xB2, 0x1E])

    /// HMAC key for master key derivation.
    private static let masterKey = "Bitcoin seed".data(using: .utf8)!

    /// Serialised key length (without checksum): 78 bytes.
    private static let serialisedKeyLen = 78

    // MARK: - Properties

    /// The raw key data: 32-byte private key scalar, or 33-byte compressed public key.
    public let key: Data

    /// The 32-byte chain code.
    public let chainCode: Data

    /// Derivation depth (0 for master).
    public let depth: UInt8

    /// Parent key fingerprint (first 4 bytes of Hash160 of parent's public key).
    public let parentFingerprint: Data

    /// Child index used to derive this key.
    public let childIndex: UInt32

    /// Whether this is a private extended key.
    public let isPrivate: Bool

    /// Version bytes (xprv or xpub).
    public let version: Data

    // MARK: - Cached public key bytes

    /// Compressed public key bytes (cached for private keys).
    private let _pubKeyBytes: Data

    // MARK: - Errors

    public enum Error: Swift.Error {
        case invalidSeedLength
        case unusableSeed
        case cannotDeriveHardenedFromPublic
        case invalidChild
        case maxDepthExceeded
        case invalidSerialisation
        case badChecksum
        case invalidPath
    }

    // MARK: - Initialisation

    /// Internal initialiser.
    init(
        key: Data,
        chainCode: Data,
        depth: UInt8,
        parentFingerprint: Data,
        childIndex: UInt32,
        isPrivate: Bool,
        version: Data
    ) {
        self.key = key
        self.chainCode = chainCode
        self.depth = depth
        self.parentFingerprint = parentFingerprint
        self.childIndex = childIndex
        self.isPrivate = isPrivate
        self.version = version

        if isPrivate {
            self._pubKeyBytes = Secp256k1.G.multiplied(by: key).compressed()
        } else {
            self._pubKeyBytes = key
        }
    }

    // MARK: - Master key from seed

    /// Create a master extended private key from a seed.
    ///
    /// - Parameter seed: Random seed data (16–64 bytes).
    /// - Returns: The master extended private key.
    public static func fromSeed(_ seed: Data) throws -> ExtendedKey {
        guard seed.count >= minSeedBytes, seed.count <= maxSeedBytes else {
            throw Error.invalidSeedLength
        }

        let hmac = Digest.hmacSha512(data: seed, key: masterKey)
        let secretKey = hmac.prefix(32)
        let chainCode = hmac.suffix(32)

        // Verify the key is valid (non-zero and less than curve order).
        guard !scalarIsZero(secretKey) else { throw Error.unusableSeed }
        guard scalarCompare(Data(secretKey), Secp256k1.N) < 0 else { throw Error.unusableSeed }

        return ExtendedKey(
            key: Data(secretKey),
            chainCode: Data(chainCode),
            depth: 0,
            parentFingerprint: Data([0, 0, 0, 0]),
            childIndex: 0,
            isPrivate: true,
            version: xprvVersion
        )
    }

    // MARK: - Child derivation

    /// Derive a child extended key at the given index.
    ///
    /// Indices >= 0x80000000 produce hardened children (private key only).
    public func deriveChild(index: UInt32) throws -> ExtendedKey {
        guard depth < 255 else { throw Error.maxDepthExceeded }

        let isHardened = index >= ExtendedKey.hardenedKeyStart

        if !isPrivate && isHardened {
            throw Error.cannotDeriveHardenedFromPublic
        }

        // Build HMAC data.
        var data = Data(capacity: 37)
        if isHardened {
            // 0x00 + 32-byte private key + 4-byte index
            data.append(0x00)
            data.append(paddedKey(key, length: 32))
        } else {
            // 33-byte compressed public key + 4-byte index
            data.append(pubKeyBytes)
        }
        data.append(contentsOf: withUnsafeBytes(of: index.bigEndian) { Array($0) })

        let hmac = Digest.hmacSha512(data: data, key: chainCode)
        let il = Data(hmac.prefix(32))
        let childChainCode = Data(hmac.suffix(32))

        // Verify IL is valid (< N and non-zero).
        guard scalarCompare(il, Secp256k1.N) < 0 else { throw Error.invalidChild }
        guard !scalarIsZero(il) else { throw Error.invalidChild }

        let fingerprint = Data(Digest.hash160(pubKeyBytes).prefix(4))

        if isPrivate {
            // childKey = (IL + parentKey) mod N
            let childKeyData = scalarAddModN(il, key)
            guard !scalarIsZero(childKeyData) else { throw Error.invalidChild }

            return ExtendedKey(
                key: childKeyData,
                chainCode: childChainCode,
                depth: depth + 1,
                parentFingerprint: fingerprint,
                childIndex: index,
                isPrivate: true,
                version: version
            )
        } else {
            // childPoint = point(IL) + parentPoint
            let ilPoint = Secp256k1.G.multiplied(by: il)
            guard !ilPoint.isInfinity else { throw Error.invalidChild }

            guard let parentPoint = CurvePoint.fromBytes(key) else {
                throw Error.invalidChild
            }

            let childPoint = ilPoint.adding(parentPoint)
            guard !childPoint.isInfinity else { throw Error.invalidChild }

            return ExtendedKey(
                key: childPoint.compressed(),
                chainCode: childChainCode,
                depth: depth + 1,
                parentFingerprint: fingerprint,
                childIndex: index,
                isPrivate: false,
                version: version
            )
        }
    }

    // MARK: - Path derivation

    /// Derive a child key from a BIP-32 path string.
    ///
    /// Format: `"m/44'/0'/0'/0/0"` where `'` or `h` denotes hardened derivation.
    /// The leading `m/` is optional.
    public func derivePath(_ path: String) throws -> ExtendedKey {
        var path = path.trimmingCharacters(in: .whitespaces)

        // Strip optional "m/" prefix.
        if path.hasPrefix("m/") {
            path = String(path.dropFirst(2))
        } else if path == "m" {
            return self
        }

        guard !path.isEmpty else { return self }

        var current = self
        let components = path.split(separator: "/")

        for component in components {
            var indexStr = String(component)
            var hardened = false

            if indexStr.hasSuffix("'") || indexStr.hasSuffix("h") || indexStr.hasSuffix("H") {
                hardened = true
                indexStr = String(indexStr.dropLast())
            }

            guard let index = UInt32(indexStr) else {
                throw Error.invalidPath
            }

            let childIndex = hardened ? index + ExtendedKey.hardenedKeyStart : index
            current = try current.deriveChild(index: childIndex)
        }

        return current
    }

    // MARK: - Neuter (private to public)

    /// Convert a private extended key to its public counterpart.
    ///
    /// Returns self if already public.
    public func neuter() -> ExtendedKey {
        if !isPrivate { return self }

        return ExtendedKey(
            key: pubKeyBytes,
            chainCode: chainCode,
            depth: depth,
            parentFingerprint: parentFingerprint,
            childIndex: childIndex,
            isPrivate: false,
            version: ExtendedKey.xpubVersion
        )
    }

    // MARK: - Key extraction

    /// The compressed public key bytes (33 bytes).
    public var pubKeyBytes: Data {
        _pubKeyBytes
    }

    /// Extract the private key. Returns nil if this is a public extended key.
    public func privateKey() -> PrivateKey? {
        guard isPrivate else { return nil }
        return PrivateKey(data: key)
    }

    /// Extract the public key.
    public func publicKey() -> PublicKey? {
        PublicKey(data: pubKeyBytes)
    }

    /// Bitcoin address derived from this key's public key.
    public func address() -> String {
        let hash = Digest.hash160(pubKeyBytes)
        var payload = Data([0x00])
        payload.append(hash)
        return Base58.checkEncode(payload)
    }

    // MARK: - Serialisation

    /// Serialise to Base58Check (xprv... or xpub...).
    public func serialise() -> String {
        var data = Data(capacity: 82)

        // Version (4 bytes)
        data.append(version)

        // Depth (1 byte)
        data.append(depth)

        // Parent fingerprint (4 bytes)
        data.append(parentFingerprint)

        // Child index (4 bytes, big-endian)
        withUnsafeBytes(of: childIndex.bigEndian) { data.append(contentsOf: $0) }

        // Chain code (32 bytes)
        data.append(chainCode)

        // Key data (33 bytes)
        if isPrivate {
            data.append(0x00)
            data.append(paddedKey(key, length: 32))
        } else {
            data.append(pubKeyBytes)
        }

        return Base58.checkEncode(data)
    }

    /// Deserialise from a Base58Check-encoded xprv/xpub string.
    public static func fromString(_ string: String) throws -> ExtendedKey {
        guard let decoded = Base58.checkDecode(string) else {
            throw Error.invalidSerialisation
        }

        guard decoded.count == serialisedKeyLen else {
            throw Error.invalidSerialisation
        }

        let version = Data(decoded[0..<4])
        let depth = decoded[4]
        let parentFP = Data(decoded[5..<9])
        let childIndex = UInt32(decoded[9]) << 24 | UInt32(decoded[10]) << 16 |
                          UInt32(decoded[11]) << 8 | UInt32(decoded[12])
        let chainCode = Data(decoded[13..<45])
        let keyData = Data(decoded[45..<78])

        let isPrivate = keyData[0] == 0x00

        if isPrivate {
            let keyBytes = Data(keyData[1..<33])
            guard !scalarIsZero(keyBytes) else { throw Error.unusableSeed }
            guard scalarCompare(keyBytes, Secp256k1.N) < 0 else { throw Error.unusableSeed }

            return ExtendedKey(
                key: keyBytes,
                chainCode: chainCode,
                depth: depth,
                parentFingerprint: parentFP,
                childIndex: childIndex,
                isPrivate: true,
                version: version
            )
        } else {
            // Verify public key parses correctly.
            guard CurvePoint.fromBytes(keyData) != nil else {
                throw Error.invalidSerialisation
            }

            return ExtendedKey(
                key: keyData,
                chainCode: chainCode,
                depth: depth,
                parentFingerprint: parentFP,
                childIndex: childIndex,
                isPrivate: false,
                version: version
            )
        }
    }

    // MARK: - Equatable

    public static func == (lhs: ExtendedKey, rhs: ExtendedKey) -> Bool {
        lhs.key == rhs.key &&
        lhs.chainCode == rhs.chainCode &&
        lhs.depth == rhs.depth &&
        lhs.parentFingerprint == rhs.parentFingerprint &&
        lhs.childIndex == rhs.childIndex &&
        lhs.isPrivate == rhs.isPrivate &&
        lhs.version == rhs.version
    }
}

// MARK: - Helpers

/// Zero-pad a key to the required length if shorter.
private func paddedKey(_ key: Data, length: Int) -> Data {
    if key.count >= length { return key }
    var padded = Data(count: length - key.count)
    padded.append(key)
    return padded
}
