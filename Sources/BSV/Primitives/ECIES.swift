import Foundation
import CommonCrypto

/// Electrum-compatible ECIES (BIE1) encryption.
///
/// BIE1 is the ECIES flavour used by the Electrum SV wallet and the rest of
/// the BSV SDK family. Messages are encrypted with a shared secret derived
/// from ECDH and an ephemeral keypair, authenticated with HMAC-SHA256.
///
/// Format (encrypt, with ephemeral key):
///     "BIE1" (4) | ephemeralPubKey (33) | AES-128-CBC ciphertext | HMAC-SHA256 (32)
///
/// The IV, AES key and MAC key are derived as follows:
///     SHA-512(compressedSharedPoint) → iv(16) | keyE(16) | keyM(32)
public enum ECIES {

    public enum Error: Swift.Error {
        case invalidCiphertext
        case invalidMagic
        case invalidEphemeralPublicKey
        case hmacMismatch
        case encryptionFailed
        case decryptionFailed
        case invalidPadding
    }

    /// BIE1 magic bytes.
    public static let magic: Data = "BIE1".data(using: .ascii)!

    // MARK: - Encrypt

    /// Encrypt a message for a recipient's public key.
    ///
    /// - Parameters:
    ///   - message: Plaintext message bytes.
    ///   - toPublicKey: Recipient's public key.
    ///   - fromPrivateKey: Optional sender private key. If nil, a fresh
    ///     ephemeral keypair is generated.
    /// - Returns: The encrypted BIE1 payload.
    public static func encrypt(
        message: Data,
        toPublicKey: PublicKey,
        fromPrivateKey: PrivateKey? = nil
    ) throws -> Data {
        // Use provided key or generate a random ephemeral keypair.
        let senderKey: PrivateKey
        if let k = fromPrivateKey {
            senderKey = k
        } else {
            guard let k = PrivateKey.random() else {
                throw Error.encryptionFailed
            }
            senderKey = k
        }

        // ECDH: shared = toPublicKey * senderPrivateKey (compressed).
        let sharedPoint = toPublicKey.point.multiplied(by: senderKey.data)
        guard !sharedPoint.isInfinity else { throw Error.encryptionFailed }
        let shared = sharedPoint.compressed()

        // Key derivation: SHA-512(shared) → iv | keyE | keyM.
        let keyMaterial = Digest.sha512(shared)
        let iv = keyMaterial.subdata(in: 0..<16)
        let keyE = keyMaterial.subdata(in: 16..<32)
        let keyM = keyMaterial.subdata(in: 32..<64)

        // AES-128-CBC encrypt with PKCS7 padding.
        guard let cipherText = aesCbcCrypt(data: message, key: keyE, iv: iv, encrypt: true) else {
            throw Error.encryptionFailed
        }

        // Ephemeral public key (sender's public key, compressed).
        let ephemeralPub = PublicKey.fromPrivateKey(senderKey).toCompressed()

        // Assemble: "BIE1" | ephemeralPubKey | cipherText
        var encrypted = Data()
        encrypted.append(magic)
        encrypted.append(ephemeralPub)
        encrypted.append(cipherText)

        // HMAC-SHA256 over everything so far.
        let mac = Digest.hmacSha256(data: encrypted, key: keyM)
        encrypted.append(mac)

        return encrypted
    }

    // MARK: - Decrypt

    /// Decrypt a BIE1 payload.
    ///
    /// - Parameters:
    ///   - encryptedData: The BIE1-formatted ciphertext.
    ///   - toPrivateKey: The recipient's private key.
    ///   - fromPublicKey: Optional sender public key. If nil, the ephemeral
    ///     public key is read from the payload (standard BIE1).
    /// - Returns: The decrypted plaintext bytes.
    public static func decrypt(
        encryptedData: Data,
        toPrivateKey: PrivateKey,
        fromPublicKey: PublicKey? = nil
    ) throws -> Data {
        // Minimum length: 4 (magic) + 33 (pubkey) + 16 (cipher) + 32 (mac) = 85
        guard encryptedData.count >= 85 else {
            throw Error.invalidCiphertext
        }

        // Verify magic bytes.
        guard encryptedData.prefix(4) == magic else {
            throw Error.invalidMagic
        }

        // Extract ephemeral public key.
        let ephemeralPubBytes = encryptedData.subdata(in: 4..<37)
        guard let ephemeralPub = PublicKey(data: ephemeralPubBytes) else {
            throw Error.invalidEphemeralPublicKey
        }

        // Determine which public key to use for ECDH.
        let peerPub = fromPublicKey ?? ephemeralPub
        let sharedPoint = peerPub.point.multiplied(by: toPrivateKey.data)
        guard !sharedPoint.isInfinity else { throw Error.decryptionFailed }
        let shared = sharedPoint.compressed()

        // Key derivation.
        let keyMaterial = Digest.sha512(shared)
        let iv = keyMaterial.subdata(in: 0..<16)
        let keyE = keyMaterial.subdata(in: 16..<32)
        let keyM = keyMaterial.subdata(in: 32..<64)

        // Verify HMAC.
        let macOffset = encryptedData.count - 32
        let macData = encryptedData.subdata(in: 0..<macOffset)
        let mac = encryptedData.subdata(in: macOffset..<encryptedData.count)
        let expectedMac = Digest.hmacSha256(data: macData, key: keyM)
        guard mac == expectedMac else {
            throw Error.hmacMismatch
        }

        // Extract ciphertext (between ephemeral pubkey and MAC).
        let cipherText = encryptedData.subdata(in: 37..<macOffset)

        // AES-128-CBC decrypt.
        guard let plaintext = aesCbcCrypt(data: cipherText, key: keyE, iv: iv, encrypt: false) else {
            throw Error.decryptionFailed
        }

        return plaintext
    }
}

// MARK: - AES-128-CBC helper

/// Perform AES-128-CBC encrypt or decrypt with PKCS7 padding via CommonCrypto.
private func aesCbcCrypt(data: Data, key: Data, iv: Data, encrypt: Bool) -> Data? {
    precondition(key.count == 16, "AES-128 requires a 16-byte key")
    precondition(iv.count == 16, "AES-CBC requires a 16-byte IV")

    let operation = encrypt ? kCCEncrypt : kCCDecrypt
    // Output buffer needs room for one extra block of padding.
    let bufferSize = data.count + kCCBlockSizeAES128
    var buffer = Data(count: bufferSize)
    var numBytesOut = 0

    let status = buffer.withUnsafeMutableBytes { bufferPtr in
        data.withUnsafeBytes { dataPtr in
            key.withUnsafeBytes { keyPtr in
                iv.withUnsafeBytes { ivPtr in
                    CCCrypt(
                        CCOperation(operation),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyPtr.baseAddress, key.count,
                        ivPtr.baseAddress,
                        dataPtr.baseAddress, data.count,
                        bufferPtr.baseAddress, bufferSize,
                        &numBytesOut
                    )
                }
            }
        }
    }

    guard status == kCCSuccess else { return nil }
    return buffer.prefix(numBytesOut)
}
