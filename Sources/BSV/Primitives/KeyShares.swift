import Foundation

/// A bundle of Shamir Secret Sharing shares for a private key.
///
/// Each share is a `PointInFiniteField` — an (x, y) pair on a polynomial over
/// GF(P). Any `threshold` shares are sufficient to reconstruct the original
/// private key via Lagrange interpolation at x = 0.
///
/// `integrity` is the first 8 hex characters of the HASH160 of the compressed
/// public key of the original private key, used to detect corruption or
/// mismatched share bundles during reconstruction.
///
/// This type is interoperable with the ts-sdk and go-sdk share formats.
public struct KeyShares: Sendable, Equatable {

    /// The shares (polynomial points).
    public let points: [PointInFiniteField]

    /// The number of shares required to reconstruct the private key.
    public let threshold: Int

    /// Integrity tag derived from the source private key's public key hash.
    public let integrity: String

    // MARK: - Initialisation

    public init(points: [PointInFiniteField], threshold: Int, integrity: String) {
        self.points = points
        self.threshold = threshold
        self.integrity = integrity
    }

    // MARK: - Backup format

    /// Serialise the share bundle to an array of strings in the form
    /// `<base58(x)>.<base58(y)>.<threshold>.<integrity>`.
    ///
    /// Each element can be stored or transmitted independently. The format is
    /// shared with ts-sdk and go-sdk.
    public func toBackupFormat() -> [String] {
        points.map { point in
            "\(point.toString()).\(threshold).\(integrity)"
        }
    }

    /// Parse a set of backup-format strings into a `KeyShares` bundle.
    ///
    /// All shares must report the same threshold and integrity tag.
    ///
    /// - Throws: `Shamir.Error.invalidShareFormat`, `.thresholdMismatch`, or
    ///   `.integrityMismatch` if the strings are malformed or inconsistent.
    public static func fromBackupFormat(_ shares: [String]) throws -> KeyShares {
        var threshold = 0
        var integrity = ""
        var points: [PointInFiniteField] = []

        for (idx, share) in shares.enumerated() {
            let parts = share.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 4 else {
                throw Shamir.Error.invalidShareFormat
            }
            guard let t = Int(parts[2]) else {
                throw Shamir.Error.invalidShareFormat
            }
            let i = parts[3]
            if idx != 0 {
                guard threshold == t else {
                    throw Shamir.Error.thresholdMismatch
                }
                guard integrity == i else {
                    throw Shamir.Error.integrityMismatch
                }
            }
            threshold = t
            integrity = i
            let point = try PointInFiniteField.fromString(parts[0] + "." + parts[1])
            points.append(point)
        }

        return KeyShares(points: points, threshold: threshold, integrity: integrity)
    }
}
