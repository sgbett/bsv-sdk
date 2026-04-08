import Foundation

/// A point (x, y) in the secp256k1 finite field used by Shamir's Secret Sharing.
///
/// Both coordinates are scalars reduced modulo the field prime P. Used as evaluations
/// of the Shamir polynomial — the constant term encodes a private key, and additional
/// points are generated during splitting.
///
/// Matches the `PointInFiniteField` type in the ts-sdk and go-sdk so that share
/// bundles are interoperable across SDKs.
public struct PointInFiniteField: Sendable, Equatable {

    /// The x coordinate as a 32-byte big-endian scalar (reduced mod P).
    public let x: Data

    /// The y coordinate as a 32-byte big-endian scalar (reduced mod P).
    public let y: Data

    // MARK: - Initialisation

    /// Create a point from 32-byte big-endian scalars. Each coordinate is
    /// reduced mod P on entry.
    public init(x: Data, y: Data) {
        self.x = FieldP.reduce(FieldP.pad(x))
        self.y = FieldP.reduce(FieldP.pad(y))
    }

    // MARK: - Serialisation

    /// Encode as `<base58(x)>.<base58(y)>` matching the ts-sdk format.
    ///
    /// The x and y coordinates are serialised as their minimal big-endian byte
    /// representation (with leading zeros stripped) before base58 encoding.
    public func toString() -> String {
        Base58.encode(PointInFiniteField.minimalBytes(x)) + "." + Base58.encode(PointInFiniteField.minimalBytes(y))
    }

    /// Decode a point from `<base58(x)>.<base58(y)>` format.
    /// - Throws: `Shamir.Error.invalidShareFormat` if the string is malformed or decoding fails.
    public static func fromString(_ str: String) throws -> PointInFiniteField {
        let parts = str.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2 else {
            throw Shamir.Error.invalidShareFormat
        }
        guard let xBytes = Base58.decode(parts[0]),
              let yBytes = Base58.decode(parts[1]) else {
            throw Shamir.Error.invalidShareFormat
        }
        return PointInFiniteField(x: xBytes, y: yBytes)
    }

    // MARK: - Helpers

    /// Strip leading zero bytes, producing the minimal big-endian encoding.
    /// A zero value becomes a single zero byte (matching ts-sdk BigNumber.toArray()).
    static func minimalBytes(_ data: Data) -> Data {
        var start = 0
        while start < data.count - 1 && data[data.startIndex + start] == 0 {
            start += 1
        }
        return Data(data[data.startIndex + start ..< data.endIndex])
    }
}
