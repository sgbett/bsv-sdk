import Foundation

/// A secp256k1 public key.
public struct PublicKey: Sendable, Equatable {
    /// The underlying curve point.
    let point: CurvePoint

    // MARK: - Initialisation

    /// Create a public key from a curve point.
    /// Returns nil if the point is at infinity or not on the curve.
    init?(point: CurvePoint) {
        guard !point.isInfinity, point.isOnCurve() else { return nil }
        self.point = point
    }

    /// Derive the public key from a private key.
    static func fromPrivateKey(_ privateKey: PrivateKey) -> PublicKey {
        let point = privateKey.publicKey()
        // A valid private key always produces a valid public key.
        return PublicKey(point: point)!
    }

    /// Create a public key from compressed (33 bytes) or uncompressed (65 bytes) encoding.
    public init?(data: Data) {
        guard let pt = CurvePoint.fromBytes(data) else { return nil }
        guard !pt.isInfinity, pt.isOnCurve() else { return nil }
        self.point = pt
    }

    /// Create a public key from a hex string (compressed or uncompressed).
    public init?(hex: String) {
        guard let d = Data(hex: hex) else { return nil }
        self.init(data: d)
    }

    // MARK: - Serialisation

    /// Compressed encoding (33 bytes: 02/03 prefix + x).
    public func toCompressed() -> Data {
        point.compressed()
    }

    /// Uncompressed encoding (65 bytes: 04 prefix + x + y).
    public func toUncompressed() -> Data {
        point.uncompressed()
    }

    /// Compressed hex string (the default serialisation used in Bitcoin).
    public var hex: String {
        toCompressed().hex
    }

    /// DER encoding (same as compressed for secp256k1).
    public func toDER() -> Data {
        toCompressed()
    }

    /// DER hex string.
    public var derHex: String {
        toDER().hex
    }

    // MARK: - Hashing

    /// Hash160 of the compressed public key (SHA-256 then RIPEMD-160).
    /// Used for Bitcoin address generation.
    public func hash160() -> Data {
        Digest.hash160(toCompressed())
    }

    // MARK: - Address

    /// Bitcoin address version byte for mainnet (P2PKH).
    private static let addressVersion: UInt8 = 0x00

    /// Generate a P2PKH address from this public key.
    ///
    /// Format: Base58Check(version + hash160(compressedPubKey))
    public func toAddress() -> String {
        var payload = Data([PublicKey.addressVersion])
        payload.append(hash160())
        return Base58.checkEncode(payload)
    }

    // MARK: - Verification

    /// Verify an ECDSA signature against a 32-byte hash.
    func verify(hash: Data, signature: Signature) -> Bool {
        ECDSA.verify(hash: hash, r: signature.r, s: signature.s, publicKey: point)
    }

    // MARK: - Equatable

    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        lhs.point == rhs.point
    }
}
