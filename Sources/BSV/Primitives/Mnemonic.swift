import Foundation
import Security

/// BIP-39 mnemonic code for generating deterministic keys.
///
/// A mnemonic encodes a random entropy value as a sequence of words from a
/// fixed dictionary, which humans can more easily record and transcribe.
/// The mnemonic can be converted to a seed suitable for BIP-32 HD wallets.
public enum Mnemonic {

    public enum Error: Swift.Error {
        case invalidEntropyLength
        case invalidWordCount
        case invalidWord(String)
        case invalidChecksum
    }

    /// Valid entropy lengths in bits (128, 160, 192, 224, 256).
    public static let validEntropyBits: [Int] = [128, 160, 192, 224, 256]

    // MARK: - Generation

    /// Generate a new random mnemonic of the given strength (entropy bits).
    ///
    /// - Parameter strength: Entropy strength in bits. Must be one of
    ///   128, 160, 192, 224, 256. Defaults to 128 (12 words).
    /// - Returns: A space-separated mnemonic string.
    public static func generate(strength: Int = 128) throws -> String {
        guard validEntropyBits.contains(strength) else {
            throw Error.invalidEntropyLength
        }

        var entropy = Data(count: strength / 8)
        let status = entropy.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, ptr.count, ptr.baseAddress!)
        }
        precondition(status == errSecSuccess, "failed to generate random entropy")

        return try fromEntropy(entropy)
    }

    /// Convert raw entropy bytes to a mnemonic phrase.
    public static func fromEntropy(_ entropy: Data) throws -> String {
        let entropyBits = entropy.count * 8
        guard validEntropyBits.contains(entropyBits) else {
            throw Error.invalidEntropyLength
        }

        // Checksum: first entropyBits/32 bits of SHA-256(entropy).
        let checksumBits = entropyBits / 32
        let hash = Digest.sha256(entropy)

        // Build a bit string of entropy + checksum.
        var bits = bytesToBits(entropy)
        let hashBits = bytesToBits(hash)
        bits += hashBits.prefix(checksumBits)

        // Split into 11-bit groups and look up words.
        var words: [String] = []
        for i in stride(from: 0, to: bits.count, by: 11) {
            let group = bits[i..<i+11]
            var index = 0
            for bit in group {
                index = (index << 1) | Int(bit)
            }
            words.append(BIP39Wordlist.english[index])
        }

        return words.joined(separator: " ")
    }

    // MARK: - Validation

    /// Validate a mnemonic phrase: word count, word membership, and checksum.
    public static func validate(_ mnemonic: String) throws {
        let words = normalisedWords(from: mnemonic)

        let validCounts = [12, 15, 18, 21, 24]
        guard validCounts.contains(words.count) else {
            throw Error.invalidWordCount
        }

        // Convert words to 11-bit indices.
        var bits: [UInt8] = []
        for word in words {
            guard let index = BIP39Wordlist.english.firstIndex(of: word) else {
                throw Error.invalidWord(word)
            }
            for bit in stride(from: 10, through: 0, by: -1) {
                bits.append(UInt8((index >> bit) & 1))
            }
        }

        let entropyBits = (bits.count * 32) / 33
        let checksumBits = bits.count - entropyBits

        // Reconstruct entropy bytes.
        let entropyBitSlice = Array(bits.prefix(entropyBits))
        let entropy = bitsToBytes(entropyBitSlice)

        // Recompute the checksum.
        let hash = Digest.sha256(entropy)
        let expectedChecksum = Array(bytesToBits(hash).prefix(checksumBits))
        let actualChecksum = Array(bits.suffix(checksumBits))

        guard expectedChecksum == actualChecksum else {
            throw Error.invalidChecksum
        }
    }

    /// Convenience: returns true if the mnemonic is valid.
    public static func isValid(_ mnemonic: String) -> Bool {
        (try? validate(mnemonic)) != nil
    }

    /// Extract the raw entropy from a validated mnemonic phrase.
    public static func toEntropy(_ mnemonic: String) throws -> Data {
        try validate(mnemonic)

        let words = normalisedWords(from: mnemonic)
        var bits: [UInt8] = []
        for word in words {
            let index = BIP39Wordlist.english.firstIndex(of: word)!
            for bit in stride(from: 10, through: 0, by: -1) {
                bits.append(UInt8((index >> bit) & 1))
            }
        }
        let entropyBits = (bits.count * 32) / 33
        return bitsToBytes(Array(bits.prefix(entropyBits)))
    }

    // MARK: - Seed derivation

    /// Convert a mnemonic to a 64-byte seed via PBKDF2-HMAC-SHA512.
    ///
    /// The mnemonic is validated first. The salt is `"mnemonic" + passphrase`,
    /// and PBKDF2 runs for 2048 iterations producing 64 bytes of output.
    ///
    /// - Parameters:
    ///   - mnemonic: Space-separated mnemonic phrase.
    ///   - passphrase: Optional passphrase to protect the seed.
    /// - Returns: A 64-byte seed suitable for BIP-32 master key derivation.
    public static func toSeed(_ mnemonic: String, passphrase: String = "") throws -> Data {
        try validate(mnemonic)

        let words = normalisedWords(from: mnemonic)
        let normalisedMnemonic = words.joined(separator: " ")

        let password = normalisedMnemonic.data(using: .utf8)!
        let salt = ("mnemonic" + passphrase).data(using: .utf8)!

        guard let seed = Digest.pbkdf2HmacSha512(
            password: password,
            salt: salt,
            iterations: 2048,
            keyLength: 64
        ) else {
            preconditionFailure("PBKDF2 derivation failed")
        }

        return seed
    }

    // MARK: - Helpers

    private static func normalisedWords(from mnemonic: String) -> [String] {
        mnemonic
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .split(whereSeparator: { $0.isWhitespace })
            .map(String.init)
    }
}

// MARK: - Bit/byte conversion

private func bytesToBits(_ bytes: Data) -> [UInt8] {
    var bits: [UInt8] = []
    bits.reserveCapacity(bytes.count * 8)
    for byte in bytes {
        for i in stride(from: 7, through: 0, by: -1) {
            bits.append((byte >> i) & 1)
        }
    }
    return bits
}

private func bitsToBytes(_ bits: [UInt8]) -> Data {
    precondition(bits.count % 8 == 0, "bit count must be multiple of 8")
    var bytes = Data(count: bits.count / 8)
    for i in 0..<bits.count {
        if bits[i] != 0 {
            bytes[i / 8] |= UInt8(1 << (7 - (i % 8)))
        }
    }
    return bytes
}
