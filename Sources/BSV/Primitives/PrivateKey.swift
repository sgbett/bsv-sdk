import Foundation
import Security

/// A secp256k1 private key.
public struct PrivateKey: Sendable, Equatable {
    /// The 32-byte private key scalar.
    let data: Data

    /// WIF version byte for mainnet.
    private static let wifVersion: UInt8 = 0x80
    /// Compression flag byte appended for compressed keys.
    private static let compressionFlag: UInt8 = 0x01

    // MARK: - Initialisation

    /// Create a private key from a 32-byte scalar.
    /// Returns nil if the scalar is zero or >= N.
    public init?(data: Data) {
        guard data.count == 32 else { return nil }
        guard !scalarIsZero(data) else { return nil }
        guard scalarCompare(data, Secp256k1.N) < 0 else { return nil }
        self.data = data
    }

    /// Create a private key from a hex string.
    public init?(hex: String) {
        guard let d = Data(hex: hex), d.count == 32 else { return nil }
        self.init(data: d)
    }

    /// Create a private key from WIF (Wallet Import Format).
    ///
    /// WIF encoding: Base58Check(0x80 + 32-byte key [+ 0x01 for compressed])
    public init?(wif: String) {
        guard let decoded = Base58.checkDecode(wif) else { return nil }
        guard decoded.count == 33 || decoded.count == 34 else { return nil }
        guard decoded[0] == PrivateKey.wifVersion else { return nil }

        let keyBytes = Data(decoded[1..<33])

        if decoded.count == 34 {
            guard decoded[33] == PrivateKey.compressionFlag else { return nil }
        }

        self.init(data: keyBytes)
    }

    /// Generate a random private key.
    public static func random() -> PrivateKey? {
        var bytes = Data(count: 32)
        for _ in 0..<100 {
            let status = bytes.withUnsafeMutableBytes { ptr in
                SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
            }
            guard status == errSecSuccess else { continue }
            if let key = PrivateKey(data: bytes) {
                return key
            }
        }
        return nil
    }

    // MARK: - Serialisation

    /// The raw 32-byte key.
    public func toBytes() -> Data { data }

    /// Hex string representation.
    public var hex: String { data.hex }

    /// Encode as WIF (compressed).
    public func toWIF() -> String {
        var payload = Data([PrivateKey.wifVersion])
        payload.append(data)
        payload.append(PrivateKey.compressionFlag)
        return Base58.checkEncode(payload)
    }

    // MARK: - Derived public key

    /// Compute the corresponding public key.
    func publicKey() -> CurvePoint {
        Secp256k1.G.multiplied(by: data)
    }

    // MARK: - Signing

    /// Sign a 32-byte hash.
    func sign(hash: Data, forceLowS: Bool = true) -> Signature? {
        guard let result = ECDSA.sign(hash: hash, privateKey: data, forceLowS: forceLowS) else {
            return nil
        }
        return Signature(r: result.r, s: result.s)
    }
}
