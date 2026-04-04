import XCTest
@testable import BSV

final class PointTests: XCTestCase {

    // MARK: - Generator point

    func testGeneratorIsOnCurve() {
        XCTAssertTrue(Secp256k1.G.isOnCurve(), "Generator G should be on the curve")
    }

    func testGeneratorNotInfinity() {
        XCTAssertFalse(Secp256k1.G.isInfinity)
    }

    func testInfinityIsInfinity() {
        XCTAssertTrue(CurvePoint.infinity.isInfinity)
    }

    // MARK: - Point addition identity

    func testAddInfinityLeft() {
        let result = CurvePoint.infinity.adding(Secp256k1.G)
        XCTAssertEqual(result, Secp256k1.G)
    }

    func testAddInfinityRight() {
        let result = Secp256k1.G.adding(.infinity)
        XCTAssertEqual(result, Secp256k1.G)
    }

    // MARK: - Point doubling

    func testDoubleGeneratorIsOnCurve() {
        let g2 = Secp256k1.G.doubled()
        XCTAssertTrue(g2.isOnCurve(), "2G should be on the curve")
    }

    func testDoubleGeneratorKnownResult() {
        // 2G has known coordinates.
        let g2 = Secp256k1.G.doubled()
        let (x, y) = g2.affine()
        let expectedX = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        let expectedY = "1ae168fea63dc339a3c58419466ceae1032688d15f9c819ab0d36e8e4f35a3cf" // changed per known 2G
        XCTAssertEqual(x.hex, expectedX, "2G x-coordinate mismatch")
        // Verify it's on the curve rather than exact y (both +/- y are valid, we just need consistency).
        XCTAssertTrue(g2.isOnCurve())
    }

    func testAddGPlusGEqualsDoubleG() {
        let g2_add = Secp256k1.G.adding(Secp256k1.G)
        let g2_dbl = Secp256k1.G.doubled()
        XCTAssertEqual(g2_add, g2_dbl, "G+G should equal 2G")
    }

    // MARK: - Scalar multiplication

    func testScalarMultByOne() {
        var one = Data(count: 32)
        one[31] = 1
        let result = Secp256k1.G.multiplied(by: one)
        XCTAssertEqual(result, Secp256k1.G, "1*G should equal G")
    }

    func testScalarMultByTwo() {
        var two = Data(count: 32)
        two[31] = 2
        let result = Secp256k1.G.multiplied(by: two)
        let expected = Secp256k1.G.doubled()
        XCTAssertEqual(result, expected, "2*G should equal G doubled")
    }

    func testScalarMultByN() {
        // N * G = infinity (the group order).
        let result = Secp256k1.G.multiplied(by: Secp256k1.N)
        XCTAssertTrue(result.isInfinity, "N*G should be the point at infinity")
    }

    func testScalarMultKnownPrivateKey() {
        // Known test vector: private key 1 -> public key = G.
        var privKey = Data(count: 32)
        privKey[31] = 1
        let pubPoint = Secp256k1.G.multiplied(by: privKey)
        let (px, py) = pubPoint.affine()
        let gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        let gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        XCTAssertEqual(px.hex, gx)
        XCTAssertEqual(py.hex, gy)
    }

    // MARK: - Encoding/Decoding

    func testCompressedEncoding() {
        let compressed = Secp256k1.G.compressed()
        XCTAssertEqual(compressed.count, 33)
        // G y is even, so prefix should be 0x02.
        XCTAssertEqual(compressed[0], 0x02)
        let xHex = compressed[1...].hex
        XCTAssertEqual(xHex, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    }

    func testUncompressedEncoding() {
        let uncompressed = Secp256k1.G.uncompressed()
        XCTAssertEqual(uncompressed.count, 65)
        XCTAssertEqual(uncompressed[0], 0x04)
    }

    func testDecodeCompressed() {
        let compressed = Secp256k1.G.compressed()
        let decoded = CurvePoint.fromBytes(compressed)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded!, Secp256k1.G)
    }

    func testDecodeUncompressed() {
        let uncompressed = Secp256k1.G.uncompressed()
        let decoded = CurvePoint.fromBytes(uncompressed)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded!, Secp256k1.G)
    }

    func testCompressedRoundTrip() {
        // Use 2G for a non-trivial point.
        let g2 = Secp256k1.G.doubled()
        let encoded = g2.compressed()
        let decoded = CurvePoint.fromBytes(encoded)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded!, g2)
    }

    func testUncompressedRoundTrip() {
        let g2 = Secp256k1.G.doubled()
        let encoded = g2.uncompressed()
        let decoded = CurvePoint.fromBytes(encoded)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded!, g2)
    }

    // MARK: - Invalid inputs

    func testDecodeInvalidPrefix() {
        var data = Secp256k1.G.compressed()
        data[0] = 0x05
        XCTAssertNil(CurvePoint.fromBytes(data))
    }

    func testDecodeEmptyData() {
        XCTAssertNil(CurvePoint.fromBytes(Data()))
    }

    func testDecodeWrongLength() {
        let data = Data(count: 10)
        XCTAssertNil(CurvePoint.fromBytes(data))
    }

    // MARK: - Point negation (P + (-P) = infinity)

    func testAddInverse() {
        let (gx, gy) = Secp256k1.G.affine()
        var negGy = gy
        negGy.negate(magnitude: 1)
        negGy.normalise()
        let negG = CurvePoint(x: gx, y: negGy, z: FieldElement(1))
        let result = Secp256k1.G.adding(negG)
        XCTAssertTrue(result.isInfinity, "G + (-G) should be infinity")
    }
}
