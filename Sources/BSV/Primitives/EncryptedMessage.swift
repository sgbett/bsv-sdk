import Foundation

/// Metadata wrapper for an encrypted message exchanged between two parties.
///
/// This type represents the structural envelope of the BRC-78 message
/// encryption format used across the BSV SDK family:
///
///     version(4) || senderPubKey(33) || recipientPubKey(33) || keyID(32) || ciphertext
///
/// The full encrypt/decrypt protocol depends on BRC-42 key derivation
/// (sender/recipient invoice-numbered child keys plus a shared-secret
/// derivation). That derivation is not yet implemented in this Swift SDK,
/// so this type currently provides parsing and serialisation only — the
/// transform between plaintext and the `ciphertext` field will be added
/// once BRC-42 derivation lands.
public struct EncryptedMessage: Sendable, Equatable {

    public enum Error: Swift.Error {
        case invalidLength
        case versionMismatch
        case invalidPublicKey
    }

    /// BRC-78 protocol version magic bytes.
    public static let version: Data = Data([0x42, 0x42, 0x10, 0x33])

    /// The sender's identity public key (compressed, 33 bytes).
    public let senderPublicKey: PublicKey

    /// The intended recipient's identity public key (compressed, 33 bytes).
    public let recipientPublicKey: PublicKey

    /// 32-byte random key identifier (used as the BRC-42 invoice number suffix).
    public let keyID: Data

    /// The opaque encrypted payload.
    public let ciphertext: Data

    // MARK: - Initialisation

    public init(
        senderPublicKey: PublicKey,
        recipientPublicKey: PublicKey,
        keyID: Data,
        ciphertext: Data
    ) {
        self.senderPublicKey = senderPublicKey
        self.recipientPublicKey = recipientPublicKey
        self.keyID = keyID
        self.ciphertext = ciphertext
    }

    // MARK: - Serialisation

    /// Encode the envelope to its wire format.
    public func toBytes() -> Data {
        var data = Data()
        data.append(EncryptedMessage.version)
        data.append(senderPublicKey.toCompressed())
        data.append(recipientPublicKey.toCompressed())
        data.append(keyID)
        data.append(ciphertext)
        return data
    }

    /// Parse a wire-format envelope.
    public static func fromBytes(_ data: Data) throws -> EncryptedMessage {
        // Minimum length: 4 (version) + 33 (sender) + 33 (recipient) + 32 (keyID)
        guard data.count >= 102 else { throw Error.invalidLength }

        let versionBytes = data.subdata(in: 0..<4)
        guard versionBytes == version else { throw Error.versionMismatch }

        let senderBytes = data.subdata(in: 4..<37)
        guard let sender = PublicKey(data: senderBytes) else {
            throw Error.invalidPublicKey
        }

        let recipientBytes = data.subdata(in: 37..<70)
        guard let recipient = PublicKey(data: recipientBytes) else {
            throw Error.invalidPublicKey
        }

        let keyID = data.subdata(in: 70..<102)
        let ciphertext = data.subdata(in: 102..<data.count)

        return EncryptedMessage(
            senderPublicKey: sender,
            recipientPublicKey: recipient,
            keyID: keyID,
            ciphertext: ciphertext
        )
    }
}
