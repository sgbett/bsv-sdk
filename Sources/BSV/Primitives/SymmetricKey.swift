import Foundation
import CryptoKit
import Security

/// 256-bit symmetric key for AES-GCM authenticated encryption.
///
/// Compatible with the BSV TS SDK's `SymmetricKey` format:
///   ciphertext = IV(32) || AES-GCM ciphertext || auth tag(16)
///
/// Note: the BSV SDK family uses a 32-byte IV (rather than the more
/// conventional 12) for cross-SDK consistency. AES-GCM supports
/// arbitrary IV lengths via GHASH-based nonce derivation.
public struct SymmetricKey: Sendable, Equatable {

    public enum Error: Swift.Error {
        case invalidKeyLength
        case ciphertextTooShort
        case decryptionFailed
        case encryptionFailed
    }

    /// IV length in bytes used by the BSV SDK family.
    public static let ivLength = 32
    /// AES-GCM authentication tag length in bytes.
    public static let tagLength = 16
    /// Required key length in bytes (256 bits).
    public static let keyLength = 32

    /// The 32-byte raw key material.
    public let key: Data

    // MARK: - Initialisation

    /// Create a symmetric key from raw 32-byte data.
    public init?(key: Data) {
        guard key.count == SymmetricKey.keyLength else { return nil }
        self.key = key
    }

    /// Generate a random symmetric key.
    public static func random() -> SymmetricKey {
        var bytes = Data(count: keyLength)
        let status = bytes.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, keyLength, ptr.baseAddress!)
        }
        precondition(status == errSecSuccess, "failed to generate random bytes")
        return SymmetricKey(key: bytes)!
    }

    // MARK: - Encryption

    /// Encrypt a plaintext message.
    ///
    /// Output format: IV(32) || ciphertext || tag(16)
    public func encrypt(_ plaintext: Data) throws -> Data {
        // Generate a random 32-byte IV.
        var iv = Data(count: SymmetricKey.ivLength)
        let status = iv.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, SymmetricKey.ivLength, ptr.baseAddress!)
        }
        guard status == errSecSuccess else { throw Error.encryptionFailed }

        return try encrypt(plaintext, iv: iv)
    }

    /// Encrypt with a caller-supplied IV (for testing or deterministic use).
    public func encrypt(_ plaintext: Data, iv: Data) throws -> Data {
        let cryptoKey = CryptoKit.SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: iv)

        let sealed = try AES.GCM.seal(plaintext, using: cryptoKey, nonce: nonce)

        // Format: iv || ciphertext || tag
        var result = Data()
        result.append(iv)
        result.append(sealed.ciphertext)
        result.append(sealed.tag)
        return result
    }

    // MARK: - Decryption

    /// Decrypt a ciphertext produced by `encrypt`.
    public func decrypt(_ ciphertext: Data) throws -> Data {
        guard ciphertext.count >= SymmetricKey.ivLength + SymmetricKey.tagLength else {
            throw Error.ciphertextTooShort
        }

        let iv = ciphertext.subdata(in: 0..<SymmetricKey.ivLength)
        let tagStart = ciphertext.count - SymmetricKey.tagLength
        let cipherBytes = ciphertext.subdata(in: SymmetricKey.ivLength..<tagStart)
        let tag = ciphertext.subdata(in: tagStart..<ciphertext.count)

        let cryptoKey = CryptoKit.SymmetricKey(data: key)

        do {
            let nonce = try AES.GCM.Nonce(data: iv)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: cipherBytes, tag: tag)
            return try AES.GCM.open(sealed, using: cryptoKey)
        } catch {
            throw Error.decryptionFailed
        }
    }
}
