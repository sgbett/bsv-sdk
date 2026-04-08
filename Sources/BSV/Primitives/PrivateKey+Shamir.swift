import Foundation
import Security

// MARK: - Shamir namespace

/// Namespace for Shamir Secret Sharing errors and internal helpers.
public enum Shamir {

    public enum Error: Swift.Error, Equatable {
        /// Threshold must be at least 2.
        case thresholdTooLow
        /// Total shares must be at least 2.
        case totalSharesTooLow
        /// Threshold cannot exceed total shares.
        case thresholdExceedsTotal
        /// Not enough shares supplied to reconstruct the key.
        case insufficientShares(required: Int, got: Int)
        /// Two shares had the same x coordinate.
        case duplicateShare
        /// A share string was malformed.
        case invalidShareFormat
        /// Shares did not agree on threshold.
        case thresholdMismatch
        /// Shares did not agree on integrity tag.
        case integrityMismatch
        /// Reconstructed private key failed the integrity check.
        case integrityHashMismatch
        /// The system RNG failed while generating a random scalar.
        case randomGenerationFailed
        /// Failed to produce a unique share x coordinate after repeated attempts.
        case uniqueXGenerationFailed
        /// Reconstructed value is not a valid private key (zero or >= N).
        case invalidReconstructedKey
    }

    /// Generate a 32-byte cryptographically secure random value.
    static func randomBytes(_ count: Int) throws -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw Error.randomGenerationFailed
        }
        return bytes
    }

    /// Generate a random scalar reduced mod P.
    static func randomScalar() throws -> Data {
        let bytes = try randomBytes(32)
        return FieldP.reduce(bytes)
    }
}

// MARK: - PrivateKey Shamir extension

public extension PrivateKey {

    /// Split this private key into `totalShares` Shamir shares of which any
    /// `threshold` can be used to reconstruct it.
    ///
    /// Matches ts-sdk's `toKeyShares` and go-sdk's `ToKeyShares`.
    ///
    /// - Parameters:
    ///   - threshold: Minimum number of shares required to recover the key (≥ 2).
    ///   - totalShares: Total number of shares to produce (≥ `threshold`, ≥ 2).
    /// - Returns: A `KeyShares` bundle containing `totalShares` shares plus the
    ///   integrity tag.
    /// - Throws: `Shamir.Error` for invalid parameters or RNG failures.
    func toKeyShares(threshold: Int, totalShares: Int) throws -> KeyShares {
        if threshold < 2 { throw Shamir.Error.thresholdTooLow }
        if totalShares < 2 { throw Shamir.Error.totalSharesTooLow }
        if threshold > totalShares { throw Shamir.Error.thresholdExceedsTotal }

        let poly = try Polynomial.fromPrivateKey(self, threshold: threshold)

        var points: [PointInFiniteField] = []
        var usedX = Set<Data>()

        // x-coordinate generation: HMAC-SHA512 over a per-share counter seeded with
        // 64 fresh random bytes, matching the ts-sdk/go-sdk strategy for deriving
        // unique non-zero share x values.
        let seed = try Shamir.randomBytes(64)
        for i in 0..<totalShares {
            var attempts: UInt32 = 0
            var x: Data
            repeat {
                if attempts > 5 {
                    throw Shamir.Error.uniqueXGenerationFailed
                }
                var counter = Data()
                counter.append(contentsOf: withUnsafeBytes(of: UInt32(i).bigEndian, Array.init))
                counter.append(contentsOf: withUnsafeBytes(of: attempts.bigEndian, Array.init))
                counter.append(try Shamir.randomBytes(32))
                let h = Digest.hmacSha512(data: counter, key: seed)
                x = FieldP.reduce(h) // h is 64 bytes; reduce wide to 32 bytes mod P
                attempts += 1
            } while scalarIsZero(x) || usedX.contains(x)

            usedX.insert(x)
            let y = poly.valueAt(x)
            points.append(PointInFiniteField(x: x, y: y))
        }

        let pubKey = PublicKey.fromPrivateKey(self)
        let fullHashHex = pubKey.hash160().hex
        let integrity = String(fullHashHex.prefix(8))
        return KeyShares(points: points, threshold: threshold, integrity: integrity)
    }

    /// Alias for `toKeyShares(threshold:totalShares:)` matching the Swift naming
    /// suggested in the Phase 8 task brief.
    func split(threshold: Int, totalShares: Int) throws -> KeyShares {
        try toKeyShares(threshold: threshold, totalShares: totalShares)
    }

    /// Serialise the private key as an array of backup share strings.
    ///
    /// Convenience wrapper over `toKeyShares(...).toBackupFormat()`.
    func toBackupShares(threshold: Int, totalShares: Int) throws -> [String] {
        try toKeyShares(threshold: threshold, totalShares: totalShares).toBackupFormat()
    }

    /// Reconstruct a private key from a set of Shamir shares using Lagrange
    /// interpolation at x = 0.
    ///
    /// Matches ts-sdk's `fromKeyShares` and go-sdk's `PrivateKeyFromKeyShares`.
    ///
    /// - Parameter shares: The share bundle.
    /// - Throws: `Shamir.Error` if too few shares are supplied, if any duplicate
    ///   x coordinate is detected, or if the integrity check fails.
    static func fromKeyShares(_ shares: KeyShares) throws -> PrivateKey {
        if shares.threshold < 2 { throw Shamir.Error.thresholdTooLow }
        if shares.points.count < shares.threshold {
            throw Shamir.Error.insufficientShares(required: shares.threshold, got: shares.points.count)
        }

        // Check for duplicate x coordinates among the points used for reconstruction.
        for i in 0..<shares.threshold {
            for j in (i + 1)..<shares.threshold {
                if shares.points[i].x == shares.points[j].x {
                    throw Shamir.Error.duplicateShare
                }
            }
        }

        let poly = Polynomial(points: shares.points, threshold: shares.threshold)
        let secret = poly.valueAt(Data(count: 32))
        guard let privateKey = PrivateKey(data: secret) else {
            throw Shamir.Error.invalidReconstructedKey
        }

        let pubKey = PublicKey.fromPrivateKey(privateKey)
        let integrity = String(pubKey.hash160().hex.prefix(8))
        guard integrity == shares.integrity else {
            throw Shamir.Error.integrityHashMismatch
        }
        return privateKey
    }

    /// Reconstruct a private key from an array of backup share strings.
    static func fromBackupShares(_ shares: [String]) throws -> PrivateKey {
        let keyShares = try KeyShares.fromBackupFormat(shares)
        return try fromKeyShares(keyShares)
    }
}
