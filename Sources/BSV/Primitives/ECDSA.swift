import Foundation

/// ECDSA signing, verification, and public key recovery for secp256k1.
enum ECDSA {

    // MARK: - Signing

    /// Sign a 32-byte hash with a private key.
    ///
    /// - Parameters:
    ///   - hash: The 32-byte message hash to sign.
    ///   - privateKey: The 32-byte private key scalar.
    ///   - forceLowS: Enforce BIP-62 low-S normalisation (default true).
    /// - Returns: Tuple of (r, s) as 32-byte big-endian Data, and the recovery ID (0 or 1).
    static func sign(hash: Data, privateKey: Data, forceLowS: Bool = true) -> (r: Data, s: Data, recoveryId: Int)? {
        guard hash.count == 32, privateKey.count == 32 else { return nil }
        guard !scalarIsZero(privateKey) else { return nil }
        guard scalarCompare(privateKey, Secp256k1.N) < 0 else { return nil }

        // RFC 6979 deterministic k generation.
        let k = rfc6979K(hash: hash, privateKey: privateKey)
        guard let k = k else { return nil }

        return signWithK(hash: hash, privateKey: privateKey, k: k, forceLowS: forceLowS)
    }

    /// Sign using a specific k value (used internally and for testing with known vectors).
    static func signWithK(hash: Data, privateKey: Data, k: Data, forceLowS: Bool = true) -> (r: Data, s: Data, recoveryId: Int)? {
        // R = k * G
        let R = Secp256k1.G.multiplied(by: k)
        guard !R.isInfinity else { return nil }

        let (rx, ry) = R.affine()

        // r = R.x mod N
        var rBytes = rx.toBytes()
        rBytes = scalarModN(rBytes)
        guard !scalarIsZero(rBytes) else { return nil }

        // Recovery ID based on y parity.
        var recoveryId = ry.isOdd ? 1 : 0

        // s = k^(-1) * (hash + r * privateKey) mod N
        let rTimesPriv = scalarMulModN(rBytes, privateKey)
        let hashPlusRPriv = scalarAddModN(hash, rTimesPriv)
        let kInv = scalarInvModN(k)
        var sBytes = scalarMulModN(kInv, hashPlusRPriv)
        guard !scalarIsZero(sBytes) else { return nil }

        // Low-S normalisation.
        if forceLowS && scalarCompare(sBytes, Secp256k1.halfN) > 0 {
            sBytes = scalarSubN(Secp256k1.N, sBytes)
            recoveryId ^= 1
        }

        return (r: rBytes, s: sBytes, recoveryId: recoveryId)
    }

    // MARK: - Verification

    /// Verify an ECDSA signature against a hash and public key point.
    ///
    /// - Parameters:
    ///   - hash: The 32-byte message hash.
    ///   - r: The signature r component (32 bytes).
    ///   - s: The signature s component (32 bytes).
    ///   - publicKey: The public key as a CurvePoint.
    /// - Returns: True if the signature is valid.
    static func verify(hash: Data, r: Data, s: Data, publicKey: CurvePoint) -> Bool {
        guard hash.count == 32, r.count == 32, s.count == 32 else { return false }

        // r and s must be in [1, N-1].
        guard !scalarIsZero(r), scalarCompare(r, Secp256k1.N) < 0 else { return false }
        guard !scalarIsZero(s), scalarCompare(s, Secp256k1.N) < 0 else { return false }
        guard !publicKey.isInfinity else { return false }

        // w = s^(-1) mod N
        let w = scalarInvModN(s)

        // u1 = hash * w mod N
        let u1 = scalarMulModN(hash, w)

        // u2 = r * w mod N
        let u2 = scalarMulModN(r, w)

        // R = u1*G + u2*pubKey
        let p1 = Secp256k1.G.multiplied(by: u1)
        let p2 = publicKey.multiplied(by: u2)
        let R = p1.adding(p2)
        guard !R.isInfinity else { return false }

        // v = R.x mod N
        let (rx, _) = R.affine()
        let v = scalarModN(rx.toBytes())

        return v == r
    }

    // MARK: - Recovery

    /// Recover a public key from a signature and recovery ID.
    ///
    /// - Parameters:
    ///   - hash: The 32-byte message hash.
    ///   - r: The signature r component (32 bytes).
    ///   - s: The signature s component (32 bytes).
    ///   - recoveryId: The recovery flag (0 or 1).
    /// - Returns: The recovered public key point, or nil if recovery fails.
    static func recover(hash: Data, r: Data, s: Data, recoveryId: Int) -> CurvePoint? {
        guard hash.count == 32, r.count == 32, s.count == 32 else { return nil }
        guard recoveryId == 0 || recoveryId == 1 else { return nil }
        guard !scalarIsZero(r), scalarCompare(r, Secp256k1.N) < 0 else { return nil }
        guard !scalarIsZero(s), scalarCompare(s, Secp256k1.N) < 0 else { return nil }

        // Reconstruct R from r and the recovery ID.
        var rx = FieldElement(bytes: r)
        rx.normalise()

        // y² = x³ + 7
        var x3 = rx.squared()
        x3.mul(rx)
        x3.addInt(Secp256k1.b)
        x3.normalise()

        var ry = x3.squareRoot()
        ry.normalise()

        // Verify the square root.
        var y2check = ry.squared()
        y2check.normalise()
        guard y2check == x3 else { return nil }

        // Choose correct y parity.
        let wantOdd = recoveryId == 1
        if ry.isOdd != wantOdd {
            ry.negate(magnitude: 1)
            ry.normalise()
        }

        let R = CurvePoint(x: rx, y: ry, z: FieldElement(1))
        guard R.isOnCurve() else { return nil }

        // rInv = r^(-1) mod N
        let rInv = scalarInvModN(r)

        // pubKey = rInv * (s*R - hash*G)
        let sR = R.multiplied(by: s)
        let hashG = Secp256k1.G.multiplied(by: hash)

        // Negate hashG: negate the y-coordinate.
        let (hgx, hgy) = hashG.affine()
        var negHgy = hgy
        negHgy.negate(magnitude: 1)
        negHgy.normalise()
        let negHashG = CurvePoint(x: hgx, y: negHgy, z: FieldElement(1))

        let sRMinusHG = sR.adding(negHashG)
        let pubKey = sRMinusHG.multiplied(by: rInv)

        guard !pubKey.isInfinity, pubKey.isOnCurve() else { return nil }
        return pubKey
    }

    // MARK: - RFC 6979

    /// Generate a deterministic nonce k per RFC 6979 using HMAC-SHA256.
    static func rfc6979K(hash: Data, privateKey: Data) -> Data? {
        let qlen = 32 // byte length of N

        // Step b: V = 0x01 0x01 ... (32 bytes)
        var v = Data(repeating: 0x01, count: 32)
        // Step c: K = 0x00 0x00 ... (32 bytes)
        var k = Data(repeating: 0x00, count: 32)

        // Step d: K = HMAC_K(V || 0x00 || privateKey || hash)
        var seed = v
        seed.append(0x00)
        seed.append(privateKey)
        seed.append(hash)
        k = Digest.hmacSha256(data: seed, key: k)

        // Step e: V = HMAC_K(V)
        v = Digest.hmacSha256(data: v, key: k)

        // Step f: K = HMAC_K(V || 0x01 || privateKey || hash)
        seed = v
        seed.append(0x01)
        seed.append(privateKey)
        seed.append(hash)
        k = Digest.hmacSha256(data: seed, key: k)

        // Step g: V = HMAC_K(V)
        v = Digest.hmacSha256(data: v, key: k)

        // Step h: Generate candidates.
        for _ in 0..<100 {
            var t = Data()
            while t.count < qlen {
                v = Digest.hmacSha256(data: v, key: k)
                t.append(v)
            }
            let candidate = Data(t.prefix(qlen))

            // candidate must be in [1, N-1]
            if !scalarIsZero(candidate) && scalarCompare(candidate, Secp256k1.N) < 0 {
                return candidate
            }

            // Update K and V for next iteration.
            seed = v
            seed.append(0x00)
            k = Digest.hmacSha256(data: seed, key: k)
            v = Digest.hmacSha256(data: v, key: k)
        }

        return nil
    }
}

// MARK: - Scalar arithmetic modulo N

/// These operate on 32-byte big-endian scalars modulo the curve order N.
/// They use a simple big-integer approach since they're not on the hot path.

/// Reduce a 32-byte value modulo N.
func scalarModN(_ a: Data) -> Data {
    if scalarCompare(a, Secp256k1.N) >= 0 {
        return scalarSubN(a, Secp256k1.N)
    }
    return a
}

/// Subtract b from a (a >= b assumed), returning 32-byte result.
func scalarSubN(_ a: Data, _ b: Data) -> Data {
    var result = Data(count: 32)
    var borrow: Int = 0
    for i in stride(from: 31, through: 0, by: -1) {
        let diff = Int(a[i]) - Int(b[i]) - borrow
        if diff < 0 {
            result[i] = UInt8((diff + 256) & 0xFF)
            borrow = 1
        } else {
            result[i] = UInt8(diff & 0xFF)
            borrow = 0
        }
    }
    return result
}

/// Add two 32-byte scalars modulo N.
func scalarAddModN(_ a: Data, _ b: Data) -> Data {
    var result = Data(count: 32)
    var carry: UInt = 0
    for i in stride(from: 31, through: 0, by: -1) {
        let sum = UInt(a[i]) + UInt(b[i]) + carry
        result[i] = UInt8(sum & 0xFF)
        carry = sum >> 8
    }
    // Reduce mod N if needed.
    if carry > 0 || scalarCompare(result, Secp256k1.N) >= 0 {
        result = scalarSubN(result, Secp256k1.N)
    }
    return result
}

/// Multiply two 32-byte scalars modulo N.
///
/// Uses 4 x UInt64 limbs (little-endian limb order) with schoolbook
/// multiplication into a 512-bit product, then reduces modulo N.
func scalarMulModN(_ a: Data, _ b: Data) -> Data {
    let aLimbs = dataToLimbs(a)
    let bLimbs = dataToLimbs(b)

    // Full 512-bit product as 8 UInt64 limbs (little-endian).
    var product = [UInt64](repeating: 0, count: 8)
    for i in 0..<4 {
        var carry: UInt64 = 0
        for j in 0..<4 {
            let (hi, lo) = aLimbs[i].multipliedFullWidth(by: bLimbs[j])
            let sum1 = product[i + j].addingReportingOverflow(lo)
            let sum2 = sum1.partialValue.addingReportingOverflow(carry)
            product[i + j] = sum2.partialValue
            carry = hi &+ (sum1.overflow ? 1 : 0) &+ (sum2.overflow ? 1 : 0)
        }
        product[i + 4] = carry
    }

    // Reduce mod N.
    let result = reduceLimbsModN(product)
    return limbsToData(result)
}

/// Convert 32-byte big-endian Data to 4 UInt64 limbs (little-endian limb order).
private func dataToLimbs(_ d: Data) -> [UInt64] {
    precondition(d.count == 32)
    var limbs = [UInt64](repeating: 0, count: 4)
    for i in 0..<4 {
        let offset = 24 - i * 8
        for j in 0..<8 {
            limbs[i] |= UInt64(d[offset + j]) << UInt64((7 - j) * 8)
        }
    }
    return limbs
}

/// Convert 4 UInt64 limbs (little-endian limb order) back to 32-byte big-endian Data.
private func limbsToData(_ limbs: [UInt64]) -> Data {
    var result = Data(count: 32)
    for i in 0..<4 {
        let offset = 24 - i * 8
        for j in 0..<8 {
            result[offset + j] = UInt8((limbs[i] >> UInt64((7 - j) * 8)) & 0xFF)
        }
    }
    return result
}

/// Reduce an 8-limb (512-bit, little-endian) number modulo N (256-bit).
///
/// Uses a shift-and-subtract approach processing one bit at a time from
/// the most significant bit downward.
private func reduceLimbsModN(_ product: [UInt64]) -> [UInt64] {
    let nLimbs = dataToLimbs(Secp256k1.N)

    // We build the remainder bit by bit from the MSB of the product.
    // remainder starts at 0, then for each bit (MSB first) of the product:
    //   remainder = (remainder << 1) | bit
    //   if remainder >= N: remainder -= N
    var rem = [UInt64](repeating: 0, count: 4)

    // Find the highest set bit.
    var highBit = -1
    for i in stride(from: 7, through: 0, by: -1) {
        if product[i] != 0 {
            highBit = i * 64 + 63 - product[i].leadingZeroBitCount
            break
        }
    }

    if highBit < 0 {
        return rem
    }

    for bitPos in stride(from: highBit, through: 0, by: -1) {
        // Shift remainder left by 1.
        let topBit = rem[3] >> 63
        rem[3] = (rem[3] << 1) | (rem[2] >> 63)
        rem[2] = (rem[2] << 1) | (rem[1] >> 63)
        rem[1] = (rem[1] << 1) | (rem[0] >> 63)
        rem[0] = rem[0] << 1

        // Bring in the current bit from the product.
        let limbIdx = bitPos / 64
        let bitIdx = bitPos % 64
        let bit = (product[limbIdx] >> UInt64(bitIdx)) & 1
        rem[0] |= bit

        // If remainder >= N or there was overflow (topBit), subtract N.
        if topBit != 0 || limbsCompare(rem, nLimbs) >= 0 {
            var borrow: UInt64 = 0
            for i in 0..<4 {
                let (d1, b1) = rem[i].subtractingReportingOverflow(nLimbs[i])
                let (d2, b2) = d1.subtractingReportingOverflow(borrow)
                rem[i] = d2
                borrow = (b1 ? 1 : 0) + (b2 ? 1 : 0)
            }
        }
    }

    return rem
}

/// Compare two 4-limb numbers (little-endian limb order).
private func limbsCompare(_ a: [UInt64], _ b: [UInt64]) -> Int {
    for i in stride(from: 3, through: 0, by: -1) {
        if a[i] < b[i] { return -1 }
        if a[i] > b[i] { return 1 }
    }
    return 0
}

/// Compute the modular inverse of a 32-byte scalar modulo N using Fermat's little theorem.
/// a^(-1) = a^(N-2) mod N
func scalarInvModN(_ a: Data) -> Data {
    // N - 2
    let nMinus2 = scalarSubN(Secp256k1.N, Data(repeating: 0, count: 31) + Data([2]))

    // Square-and-multiply exponentiation.
    var result = Data(count: 32)
    result[31] = 1 // result = 1

    var base = a

    for byteIndex in stride(from: 31, through: 0, by: -1) {
        let byte = nMinus2[byteIndex]
        for bit in 0..<8 {
            if byte & (1 << bit) != 0 {
                result = scalarMulModN(result, base)
            }
            base = scalarMulModN(base, base)
        }
    }

    return result
}
