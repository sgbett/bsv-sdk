import Foundation

/// Scalar arithmetic modulo the secp256k1 field prime P.
///
/// Thin Data-oriented facade around `FieldElement`, which implements fast
/// secp256k1-specific modular reduction. These helpers are used by Shamir
/// Secret Sharing, which operates on polynomials over GF(P) to match the
/// ts-sdk/go-sdk split/recombine format.
///
/// All inputs and outputs are 32-byte big-endian `Data` values reduced
/// modulo P.
enum FieldP {

    // MARK: - Padding / reduction

    /// Left-pad a byte string to 32 bytes, or return the last 32 bytes if longer.
    /// Does not reduce modulo P.
    static func pad(_ data: Data) -> Data {
        if data.count == 32 { return Data(data) }
        if data.count < 32 {
            var padded = Data(count: 32 - data.count)
            padded.append(data)
            return padded
        }
        return Data(data.suffix(32))
    }

    /// Reduce a byte string of up to 64 bytes to a 32-byte value mod P.
    ///
    /// For 32-byte (or shorter) inputs, this is a single normalise step. For
    /// 33–64 byte inputs (e.g. HMAC-SHA512 outputs), the value is split into a
    /// high half and low half and folded via the identity
    /// `2^256 ≡ 2^32 + 977 (mod P)`.
    static func reduce(_ data: Data) -> Data {
        if data.count <= 32 {
            return normalise32(pad(data))
        }
        // Split into high and low 32-byte halves.
        let high = Data(data.prefix(data.count - 32))
        let low = Data(data.suffix(32))
        // Normalise both halves into FieldElements mod P.
        let highNorm = normalise32(pad(high))
        let lowNorm = normalise32(pad(low))
        // Compute (high * 2^256 + low) mod P = (high * c + low) mod P,
        // where c = 2^32 + 977.
        let prod = mul(highNorm, c32Data)
        return add(prod, lowNorm)
    }

    // MARK: - Core arithmetic

    /// Add two 32-byte scalars modulo P.
    static func add(_ a: Data, _ b: Data) -> Data {
        var fa = FieldElement(bytes: normalise32(pad(a)))
        let fb = FieldElement(bytes: normalise32(pad(b)))
        fa.add(fb)
        fa.normalise()
        return fa.toBytes()
    }

    /// Subtract `b` from `a` modulo P.
    static func sub(_ a: Data, _ b: Data) -> Data {
        var fa = FieldElement(bytes: normalise32(pad(a)))
        let fb = FieldElement(bytes: normalise32(pad(b)))
        let negFb = fb.negated(magnitude: 1)
        fa.add(negFb)
        fa.normalise()
        return fa.toBytes()
    }

    /// Multiply two 32-byte scalars modulo P.
    static func mul(_ a: Data, _ b: Data) -> Data {
        let fa = FieldElement(bytes: normalise32(pad(a)))
        let fb = FieldElement(bytes: normalise32(pad(b)))
        var r = FieldElement.mul(fa, fb)
        r.normalise()
        return r.toBytes()
    }

    /// Modular inverse a^(-1) mod P using the fast secp256k1-specific
    /// exponentiation chain in `FieldElement.inversed()`.
    static func inverse(_ a: Data) -> Data {
        let fa = FieldElement(bytes: normalise32(pad(a)))
        var inv = fa.inversed()
        inv.normalise()
        return inv.toBytes()
    }

    // MARK: - Private helpers

    /// Reduce a 32-byte value mod P via `FieldElement.normalise`. Handles
    /// inputs that slightly exceed P (up to 2^256 - 1).
    private static func normalise32(_ a: Data) -> Data {
        var fe = FieldElement(bytes: a)
        fe.normalise()
        return fe.toBytes()
    }

    /// The constant c = 2^32 + 977 as a 32-byte big-endian value.
    /// Used by `reduce(...)` to fold high halves into low via
    /// `2^256 ≡ 2^32 + 977 (mod P)`.
    private static let c32Data: Data = {
        var d = Data(count: 32)
        // 2^32 + 977 = 0x1_0000_03D1
        d[31] = 0xD1
        d[30] = 0x03
        d[29] = 0x00
        d[28] = 0x00
        d[27] = 0x01
        return d
    }()
}
