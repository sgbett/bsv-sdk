import Foundation

/// secp256k1 curve constants and parameters.
public enum Secp256k1: Sendable {

    /// Field prime: p = 2^256 - 2^32 - 977
    static let p = Data(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")!

    /// Group order.
    static let N = Data(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")!

    /// Half the group order, used for low-S normalisation.
    static let halfN = Data(hex: "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")!

    /// Generator point x-coordinate.
    static let gx = FieldElement(hex: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")!

    /// Generator point y-coordinate.
    static let gy = FieldElement(hex: "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")!

    /// The generator point G.
    static let G = CurvePoint(x: gx, y: gy, z: FieldElement(1))

    /// Curve coefficient b = 7.
    static let b: UInt32 = 7

    /// Byte size of scalar values.
    static let byteSize = 32
}

/// Compare two 32-byte big-endian scalars: returns -1, 0, or 1.
func scalarCompare(_ a: Data, _ b: Data) -> Int {
    precondition(a.count == 32 && b.count == 32)
    for i in 0..<32 {
        if a[i] < b[i] { return -1 }
        if a[i] > b[i] { return 1 }
    }
    return 0
}

/// Check if a 32-byte scalar is zero.
func scalarIsZero(_ s: Data) -> Bool {
    s.allSatisfy { $0 == 0 }
}
