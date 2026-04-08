import Foundation

/// A polynomial over the secp256k1 finite field (mod P).
///
/// Used by Shamir's Secret Sharing to split a private key into shares. The
/// constant term encodes the secret; all arithmetic is performed modulo the
/// secp256k1 field prime P — matching the ts-sdk and go-sdk implementations so
/// that share bundles are interoperable across SDKs.
///
/// The polynomial is represented by its defining points (not by explicit
/// coefficients): given any `threshold` points, `valueAt(x:)` uses Lagrange
/// interpolation to evaluate the unique polynomial of degree `threshold - 1`
/// that passes through them.
public struct Polynomial: Sendable, Equatable {

    /// The points defining the polynomial.
    public let points: [PointInFiniteField]

    /// The number of points required to reconstruct the polynomial.
    public let threshold: Int

    // MARK: - Initialisation

    /// Create a polynomial from a set of defining points.
    ///
    /// - Parameters:
    ///   - points: Points lying on the polynomial.
    ///   - threshold: Number of points required for reconstruction. Defaults
    ///     to `points.count`.
    public init(points: [PointInFiniteField], threshold: Int? = nil) {
        self.points = points
        self.threshold = threshold ?? points.count
    }

    /// Construct a polynomial of the given threshold whose constant term is a
    /// private key.
    ///
    /// The first point is `(0, key)`. The remaining `threshold - 1` points are
    /// generated from cryptographically secure randomness, producing a unique
    /// polynomial of degree `threshold - 1` each time it is called.
    ///
    /// - Throws: `Shamir.Error.randomGenerationFailed` if secure random bytes
    ///   cannot be obtained.
    public static func fromPrivateKey(_ key: PrivateKey, threshold: Int) throws -> Polynomial {
        var points: [PointInFiniteField] = []
        let zero = Data(count: 32)
        points.append(PointInFiniteField(x: zero, y: key.toBytes()))

        for _ in 1..<threshold {
            let rx = try Shamir.randomScalar()
            let ry = try Shamir.randomScalar()
            points.append(PointInFiniteField(x: rx, y: ry))
        }
        return Polynomial(points: points, threshold: threshold)
    }

    // MARK: - Evaluation

    /// Evaluate the polynomial at `x` using Lagrange interpolation over GF(P).
    ///
    /// Only the first `threshold` points are used. The caller is responsible
    /// for ensuring there are enough distinct points.
    public func valueAt(_ x: Data) -> Data {
        let xs = FieldP.pad(x)
        var y = Data(count: 32) // y = 0
        for i in 0..<threshold {
            var term = FieldP.pad(points[i].y)
            for j in 0..<threshold {
                if i == j { continue }
                let xj = FieldP.pad(points[j].x)
                let xi = FieldP.pad(points[i].x)

                let numerator = FieldP.sub(xs, xj)
                let denominator = FieldP.sub(xi, xj)
                let denominatorInverse = FieldP.inverse(denominator)

                let fraction = FieldP.mul(numerator, denominatorInverse)
                term = FieldP.mul(term, fraction)
            }
            y = FieldP.add(y, term)
        }
        return y
    }
}
