import Foundation

/// Bitcoin Signed Messages (BSM).
///
/// Implements the message signing/verification format popularised by Bitcoin
/// Core (bitcoin#524) and used across wallets. A message is prefixed with the
/// magic string "Bitcoin Signed Message:\n", each field length-prefixed with
/// a VarInt, and SHA-256d hashed. The resulting hash is signed with ECDSA,
/// producing a 65-byte compact signature that encodes both the (r, s) pair
/// and a recovery flag used to derive the signer's public key during
/// verification.
public enum BSM {

    public enum Error: Swift.Error {
        case signingFailed
        case invalidSignatureLength
        case invalidSignatureHeader
        case recoveryFailed
    }

    /// Magic prefix for Bitcoin Signed Messages.
    static let magic = "Bitcoin Signed Message:\n"

    // MARK: - Magic hash

    /// Compute the SHA-256d magic hash of a message.
    ///
    /// Format: VarInt(magic.length) || magic || VarInt(message.length) || message
    public static func magicHash(_ message: Data) -> Data {
        let magicBytes = magic.data(using: .utf8)!
        var buffer = Data()
        buffer.append(VarInt.encode(UInt64(magicBytes.count)))
        buffer.append(magicBytes)
        buffer.append(VarInt.encode(UInt64(message.count)))
        buffer.append(message)
        return Digest.sha256d(buffer)
    }

    // MARK: - Sign

    /// Sign a message with a private key, producing a compact recoverable signature.
    ///
    /// - Parameters:
    ///   - message: The message bytes to sign.
    ///   - privateKey: The signing private key.
    ///   - compressed: Whether the signature should reference a compressed
    ///     public key (affects the header byte). Defaults to true.
    /// - Returns: A 65-byte compact signature: header(1) || r(32) || s(32).
    public static func sign(
        message: Data,
        privateKey: PrivateKey,
        compressed: Bool = true
    ) throws -> Data {
        let hash = magicHash(message)

        guard let sig = ECDSA.sign(hash: hash, privateKey: privateKey.data) else {
            throw Error.signingFailed
        }

        // Header byte: 27 + recoveryId + (compressed ? 4 : 0)
        var header: UInt8 = 27 + UInt8(sig.recoveryId)
        if compressed { header += 4 }

        var result = Data([header])
        result.append(sig.r)
        result.append(sig.s)
        return result
    }

    /// Sign a UTF-8 string message.
    public static func sign(
        message: String,
        privateKey: PrivateKey,
        compressed: Bool = true
    ) throws -> Data {
        try sign(
            message: message.data(using: .utf8)!,
            privateKey: privateKey,
            compressed: compressed
        )
    }

    /// Sign and Base64-encode the signature for transport.
    public static func signBase64(
        message: String,
        privateKey: PrivateKey,
        compressed: Bool = true
    ) throws -> String {
        let sig = try sign(message: message, privateKey: privateKey, compressed: compressed)
        return sig.base64EncodedString()
    }

    // MARK: - Recover

    /// Recover the public key that produced a BSM signature.
    ///
    /// - Returns: Tuple of recovered `PublicKey` and whether it should be
    ///   treated as compressed (controls which address matches).
    public static func recoverPublicKey(
        signature: Data,
        message: Data
    ) throws -> (publicKey: PublicKey, compressed: Bool) {
        guard signature.count == 65 else {
            throw Error.invalidSignatureLength
        }

        let header = signature[0]
        guard header >= 27, header <= 34 else {
            throw Error.invalidSignatureHeader
        }

        let compressed = header >= 31
        let recoveryId = Int((header - 27) & 3)

        let r = signature.subdata(in: 1..<33)
        let s = signature.subdata(in: 33..<65)

        let hash = magicHash(message)

        guard let point = ECDSA.recover(hash: hash, r: r, s: s, recoveryId: recoveryId),
              let pubKey = PublicKey(point: point) else {
            throw Error.recoveryFailed
        }

        return (pubKey, compressed)
    }

    // MARK: - Verify

    /// Verify a BSM signature against a Bitcoin address.
    ///
    /// Recovers the public key from the signature and compares the derived
    /// P2PKH address to `address`.
    public static func verify(
        message: Data,
        signature: Data,
        address: String
    ) -> Bool {
        guard let (pubKey, compressed) = try? recoverPublicKey(signature: signature, message: message) else {
            return false
        }

        // BSM uses compressed or uncompressed pubkey hash depending on the header bit.
        let hash: Data
        if compressed {
            hash = Digest.hash160(pubKey.toCompressed())
        } else {
            hash = Digest.hash160(pubKey.toUncompressed())
        }
        var payload = Data([0x00])
        payload.append(hash)
        let derivedAddress = Base58.checkEncode(payload)

        return derivedAddress == address
    }

    /// Verify a BSM signature against a UTF-8 message string and address.
    public static func verify(
        message: String,
        signature: Data,
        address: String
    ) -> Bool {
        verify(
            message: message.data(using: .utf8)!,
            signature: signature,
            address: address
        )
    }

    /// Verify a Base64-encoded BSM signature.
    public static func verify(
        message: String,
        base64Signature: String,
        address: String
    ) -> Bool {
        guard let sig = Data(base64Encoded: base64Signature) else { return false }
        return verify(message: message, signature: sig, address: address)
    }
}
