import Foundation

/// Metadata wrapper for a BRC-77 signed message envelope.
///
/// Wire format:
///
///     version(4) || signerPubKey(33) || verifier(33 or 1) || keyID(32) || DER signature
///
/// When the verifier byte is 0x00, the signature is open ("verifiable by
/// anyone"); otherwise the verifier field is a 33-byte compressed public key
/// identifying the intended recipient. As with `EncryptedMessage`, the full
/// sign/verify protocol depends on BRC-42 child key derivation, which has
/// not yet landed in this Swift SDK — this type currently represents the
/// envelope structure only.
public struct SignedMessage: Sendable, Equatable {

    public enum Error: Swift.Error {
        case invalidLength
        case versionMismatch
        case invalidPublicKey
    }

    /// BRC-77 protocol version magic bytes.
    public static let version: Data = Data([0x42, 0x42, 0x33, 0x01])

    /// The signer's identity public key.
    public let signerPublicKey: PublicKey

    /// The intended verifier's public key, or `nil` for open signatures.
    public let verifierPublicKey: PublicKey?

    /// 32-byte random key identifier.
    public let keyID: Data

    /// DER-encoded ECDSA signature.
    public let signature: Data

    // MARK: - Initialisation

    public init(
        signerPublicKey: PublicKey,
        verifierPublicKey: PublicKey?,
        keyID: Data,
        signature: Data
    ) {
        self.signerPublicKey = signerPublicKey
        self.verifierPublicKey = verifierPublicKey
        self.keyID = keyID
        self.signature = signature
    }

    // MARK: - Serialisation

    /// Encode the envelope to its wire format.
    public func toBytes() -> Data {
        var data = Data()
        data.append(SignedMessage.version)
        data.append(signerPublicKey.toCompressed())
        if let verifier = verifierPublicKey {
            data.append(verifier.toCompressed())
        } else {
            data.append(0x00)
        }
        data.append(keyID)
        data.append(signature)
        return data
    }

    /// Parse a wire-format envelope.
    public static func fromBytes(_ data: Data) throws -> SignedMessage {
        // Minimum length: 4 (version) + 33 (signer) + 1 (verifier marker) + 32 (keyID)
        guard data.count >= 70 else { throw Error.invalidLength }

        let versionBytes = data.subdata(in: 0..<4)
        guard versionBytes == version else { throw Error.versionMismatch }

        let signerBytes = data.subdata(in: 4..<37)
        guard let signer = PublicKey(data: signerBytes) else {
            throw Error.invalidPublicKey
        }

        // Verifier: either 0x00 (anyone) or a 33-byte compressed pubkey.
        let verifierFirst = data[37]
        var verifier: PublicKey?
        var cursor: Int

        if verifierFirst == 0 {
            verifier = nil
            cursor = 38
        } else {
            guard data.count >= 70 + 32 else { throw Error.invalidLength }
            let verifierBytes = data.subdata(in: 37..<70)
            guard let v = PublicKey(data: verifierBytes) else {
                throw Error.invalidPublicKey
            }
            verifier = v
            cursor = 70
        }

        guard data.count >= cursor + 32 else { throw Error.invalidLength }
        let keyID = data.subdata(in: cursor..<(cursor + 32))
        let signature = data.subdata(in: (cursor + 32)..<data.count)

        return SignedMessage(
            signerPublicKey: signer,
            verifierPublicKey: verifier,
            keyID: keyID,
            signature: signature
        )
    }
}
