import Foundation
import CryptoKit
import CommonCrypto

/// Cryptographic hash and MAC functions used throughout the BSV protocol.
public enum Digest {

    /// SHA-256 hash.
    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// Double SHA-256 hash (SHA-256d), used extensively in Bitcoin.
    public static func sha256d(_ data: Data) -> Data {
        sha256(sha256(data))
    }

    /// SHA-512 hash.
    public static func sha512(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    /// SHA-1 hash.
    public static func sha1(_ data: Data) -> Data {
        Data(Insecure.SHA1.hash(data: data))
    }

    /// RIPEMD-160 hash.
    public static func ripemd160(_ data: Data) -> Data {
        RIPEMD160.hash(data)
    }

    /// Hash160: SHA-256 followed by RIPEMD-160. Used for Bitcoin addresses.
    public static func hash160(_ data: Data) -> Data {
        ripemd160(sha256(data))
    }

    /// HMAC-SHA256.
    public static func hmacSha256(data: Data, key: Data) -> Data {
        let hmacKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: hmacKey)
        return Data(mac)
    }

    /// HMAC-SHA512.
    public static func hmacSha512(data: Data, key: Data) -> Data {
        let hmacKey = SymmetricKey(data: key)
        let mac = HMAC<SHA512>.authenticationCode(for: data, using: hmacKey)
        return Data(mac)
    }

    /// PBKDF2 with HMAC-SHA512.
    ///
    /// - Parameters:
    ///   - password: The password data.
    ///   - salt: The salt data.
    ///   - iterations: Number of iterations.
    ///   - keyLength: Desired derived key length in bytes.
    /// - Returns: The derived key, or `nil` if derivation fails.
    public static func pbkdf2HmacSha512(
        password: Data,
        salt: Data,
        iterations: Int,
        keyLength: Int
    ) -> Data? {
        var derivedKey = Data(count: keyLength)
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            password.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress,
                        password.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        UInt32(iterations),
                        derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        keyLength
                    )
                }
            }
        }
        return result == kCCSuccess ? derivedKey : nil
    }
}
