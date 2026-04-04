import Foundation

/// A point on the secp256k1 elliptic curve in Jacobian coordinates.
///
/// Affine coordinates (x, y) relate to Jacobian (X, Y, Z) as:
///   x = X / Z²
///   y = Y / Z³
///
/// The point at infinity is represented by Z = 0.
struct CurvePoint: Sendable, Equatable {
    var x: FieldElement
    var y: FieldElement
    var z: FieldElement

    /// The point at infinity (identity element).
    static let infinity = CurvePoint(x: FieldElement(), y: FieldElement(), z: FieldElement())

    /// Whether this is the point at infinity.
    var isInfinity: Bool {
        z.normalised().isZero
    }

    /// Convert from Jacobian to affine coordinates.
    /// Returns (x, y) as normalised field elements.
    func affine() -> (x: FieldElement, y: FieldElement) {
        if isInfinity {
            return (FieldElement(), FieldElement())
        }

        var zInv = z
        zInv.inverse()
        let zInv2 = zInv.squared()
        let zInv3 = FieldElement.mul(zInv2, zInv)

        var ax = FieldElement.mul(x, zInv2)
        ax.normalise()
        var ay = FieldElement.mul(y, zInv3)
        ay.normalise()
        return (ax, ay)
    }

    /// Check whether the affine point is on the curve: y² = x³ + 7.
    func isOnCurve() -> Bool {
        if isInfinity { return true }
        let (ax, ay) = affine()
        var y2 = ay.squared()
        y2.normalise()
        var x3 = ax.squared()
        x3.mul(ax)
        x3.addInt(Secp256k1.b)
        x3.normalise()
        return y2 == x3
    }

    /// Equality checks affine coordinates after normalisation.
    static func == (lhs: CurvePoint, rhs: CurvePoint) -> Bool {
        if lhs.isInfinity && rhs.isInfinity { return true }
        if lhs.isInfinity || rhs.isInfinity { return false }
        let (lx, ly) = lhs.affine()
        let (rx, ry) = rhs.affine()
        return lx == rx && ly == ry
    }

    // MARK: - Point doubling

    /// Double this point in Jacobian coordinates.
    ///
    /// Uses the formula for a = 0 (secp256k1):
    ///   A = X1², B = Y1², C = B²
    ///   D = 2*((X1+B)² - A - C)
    ///   E = 3*A, F = E²
    ///   X3 = F - 2*D
    ///   Y3 = E*(D - X3) - 8*C
    ///   Z3 = 2*Y1*Z1
    func doubled() -> CurvePoint {
        // Doubling infinity or a point with Y=0 yields infinity.
        let yn = y.normalised()
        if yn.isZero || z.normalised().isZero {
            return .infinity
        }

        let a = x.squared()                        // A = X1²
        let b = y.squared()                        // B = Y1²
        var c = b.squared()                        // C = B²

        // D = 2*((X1+B)² - A - C)
        var d = x
        d.add(b)
        d.square()
        var ac = FieldElement.add(a, c)
        ac.negate(magnitude: 2)
        d.add(ac)
        d.mulInt(2)

        // E = 3*A
        var e = a
        e.mulInt(3)

        // F = E²
        let f = e.squared()

        // X3 = F - 2*D
        var x3 = d
        x3.mulInt(2)
        x3.negate(magnitude: 16)
        x3.add(f)
        x3.normalise()

        // Y3 = E*(D - X3) - 8*C
        let negX3 = x3.negated(magnitude: 1)
        var dMinusX3 = d
        dMinusX3.add(negX3)
        dMinusX3.normalise()
        var y3 = FieldElement.mul(e, dMinusX3)
        c.mulInt(8)
        c.negate(magnitude: 8)
        y3.add(c)
        y3.normalise()

        // Z3 = 2*Y1*Z1
        var z3 = FieldElement.mul(y, z)
        z3.mulInt(2)
        z3.normalise()

        return CurvePoint(x: x3, y: y3, z: z3)
    }

    // MARK: - Point addition

    /// Add two points in Jacobian coordinates.
    ///
    /// Generic formula from hyperelliptic.org:
    ///   Z1Z1=Z1², Z2Z2=Z2², U1=X1*Z2Z2, U2=X2*Z1Z1
    ///   S1=Y1*Z2*Z2Z2, S2=Y2*Z1*Z1Z1
    ///   H=U2-U1, I=(2*H)², J=H*I, r=2*(S2-S1), V=U1*I
    ///   X3=r²-J-2*V, Y3=r*(V-X3)-2*S1*J, Z3=((Z1+Z2)²-Z1Z1-Z2Z2)*H
    func adding(_ other: CurvePoint) -> CurvePoint {
        // Identity handling.
        if self.isInfinity { return other }
        if other.isInfinity { return self }

        let z1z1 = z.squared()
        let z2z2 = other.z.squared()

        var u1 = FieldElement.mul(x, z2z2)
        u1.normalise()
        var u2 = FieldElement.mul(other.x, z1z1)
        u2.normalise()

        var s1 = FieldElement.mul(y, z2z2)
        s1.mul(other.z)
        s1.normalise()
        var s2 = FieldElement.mul(other.y, z1z1)
        s2.mul(z)
        s2.normalise()

        if u1 == u2 {
            if s1 == s2 {
                return doubled()
            }
            return .infinity
        }

        // H = U2 - U1
        let negU1 = u1.negated(magnitude: 1)
        var h = u2
        h.add(negU1)

        // I = (2*H)²
        var i = h
        i.mulInt(2)
        i.square()

        // J = H*I
        let j = FieldElement.mul(h, i)

        // r = 2*(S2 - S1)
        let negS1 = s1.negated(magnitude: 1)
        var r = s2
        r.add(negS1)
        r.mulInt(2)

        // V = U1*I
        let v = FieldElement.mul(u1, i)

        // X3 = r² - J - 2*V
        var x3 = r.squared()
        let negJ = j.negated(magnitude: 1)
        x3.add(negJ)
        var neg2V = v
        neg2V.mulInt(2)
        neg2V.negate(magnitude: 2)
        x3.add(neg2V)
        x3.normalise()

        // Y3 = r*(V - X3) - 2*S1*J
        let negX3 = x3.negated(magnitude: 1)
        var vMinusX3 = v
        vMinusX3.add(negX3)
        vMinusX3.normalise()
        var y3 = FieldElement.mul(r, vMinusX3)
        var s1j = FieldElement.mul(s1, j)
        s1j.mulInt(2)
        s1j.negate(magnitude: 2)
        y3.add(s1j)
        y3.normalise()

        // Z3 = ((Z1+Z2)² - Z1Z1 - Z2Z2) * H
        var z1PlusZ2 = FieldElement.add(z, other.z)
        z1PlusZ2.square()
        var negZ1Z1Z2Z2 = FieldElement.add(z1z1, z2z2)
        negZ1Z1Z2Z2.negate(magnitude: 2)
        z1PlusZ2.add(negZ1Z1Z2Z2)
        var z3 = FieldElement.mul(z1PlusZ2, h)
        z3.normalise()

        return CurvePoint(x: x3, y: y3, z: z3)
    }

    // MARK: - Scalar multiplication

    /// Multiply this point by a scalar (big-endian byte array).
    /// Uses the simple double-and-add algorithm.
    func multiplied(by scalar: Data) -> CurvePoint {
        var result = CurvePoint.infinity
        var current = self

        // Process bits from LSB to MSB.
        for byteIndex in stride(from: scalar.count - 1, through: 0, by: -1) {
            let byte = scalar[byteIndex]
            for bit in 0..<8 {
                if byte & (1 << bit) != 0 {
                    result = result.adding(current)
                }
                current = current.doubled()
            }
        }

        return result
    }

    // MARK: - Encoding/Decoding

    /// Encode the point as compressed (33 bytes: 02/03 prefix + x).
    func compressed() -> Data {
        if isInfinity { return Data([0x00]) }
        let (ax, ay) = affine()
        let prefix: UInt8 = ay.isOdd ? 0x03 : 0x02
        var result = Data([prefix])
        result.append(ax.toBytes())
        return result
    }

    /// Encode the point as uncompressed (65 bytes: 04 prefix + x + y).
    func uncompressed() -> Data {
        if isInfinity { return Data([0x00]) }
        let (ax, ay) = affine()
        var result = Data([0x04])
        result.append(ax.toBytes())
        result.append(ay.toBytes())
        return result
    }

    /// Decode a point from compressed or uncompressed encoding.
    static func fromBytes(_ data: Data) -> CurvePoint? {
        guard !data.isEmpty else { return nil }

        switch data[0] {
        case 0x04:
            // Uncompressed: 04 + x(32) + y(32)
            guard data.count == 65 else { return nil }
            let x = FieldElement(bytes: data[1..<33].asData)
            let y = FieldElement(bytes: data[33..<65].asData)
            let point = CurvePoint(x: x, y: y, z: FieldElement(1))
            guard point.isOnCurve() else { return nil }
            return point

        case 0x02, 0x03:
            // Compressed: 02/03 + x(32)
            guard data.count == 33 else { return nil }
            let x = FieldElement(bytes: data[1..<33].asData)
            // y² = x³ + 7
            var x3 = x.squared()
            x3.mul(x)
            x3.addInt(Secp256k1.b)
            x3.normalise()

            var y = x3.squareRoot()
            y.normalise()

            // Verify that the square root is valid.
            var y2check = y.squared()
            y2check.normalise()
            guard y2check == x3 else { return nil }

            // Choose the correct y parity.
            let wantOdd = data[0] == 0x03
            if y.isOdd != wantOdd {
                y.negate(magnitude: 1)
                y.normalise()
            }

            return CurvePoint(x: x, y: y, z: FieldElement(1))

        default:
            return nil
        }
    }
}

// MARK: - Data slice helper

private extension Data.SubSequence {
    var asData: Data { Data(self) }
}
