import XCTest
@testable import BSV

final class FieldTests: XCTestCase {

    // MARK: - Zero and One

    func testZero() {
        let f = FieldElement()
        XCTAssertTrue(f.isZero)
        XCTAssertFalse(f.isOne)
        XCTAssertEqual(f.hex, String(repeating: "0", count: 64))
    }

    func testOne() {
        let f = FieldElement(1)
        XCTAssertFalse(f.isZero)
        XCTAssertTrue(f.isOne)
        let expected = String(repeating: "0", count: 63) + "1"
        XCTAssertEqual(f.hex, expected)
    }

    // MARK: - Byte round-trip

    func testBytesRoundTrip() {
        // Use the secp256k1 generator x-coordinate as a known value.
        let gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        guard let data = Data(hex: gx) else {
            XCTFail("Invalid hex"); return
        }
        let f = FieldElement(bytes: data).normalised()
        XCTAssertEqual(f.toBytes().hex, gx)
    }

    func testHexInit() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000005"
        let f = FieldElement(hex: hex)!.normalised()
        XCTAssertEqual(f.toBytes().hex, hex)
    }

    func testHexInitShort() {
        let f = FieldElement(hex: "5")!.normalised()
        XCTAssertEqual(f, FieldElement(5))
    }

    // MARK: - Addition

    func testAdd() {
        let a = FieldElement(3)
        let b = FieldElement(7)
        var c = FieldElement.add(a, b)
        c.normalise()
        XCTAssertEqual(c, FieldElement(10))
    }

    func testAddInt() {
        var f = FieldElement(100)
        f.addInt(50)
        f.normalise()
        XCTAssertEqual(f, FieldElement(150))
    }

    // MARK: - Negation

    func testNegate() {
        var a = FieldElement(1)
        a.normalise()
        var neg = a.negated(magnitude: 1)
        neg.normalise()
        // -1 mod p should equal p - 1
        let pMinusOne = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"
        XCTAssertEqual(neg.hex, pMinusOne)
    }

    func testAddNegateIsZero() {
        let gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        var a = FieldElement(hex: gx)!
        a.normalise()
        var negA = a.negated(magnitude: 1)
        a.add(negA)
        a.normalise()
        XCTAssertTrue(a.isZero)
    }

    // MARK: - Multiplication

    func testMulSmall() {
        var a = FieldElement(7)
        var b = FieldElement(6)
        var c = FieldElement.mul(a, b)
        c.normalise()
        XCTAssertEqual(c, FieldElement(42))
    }

    func testMulInt() {
        var f = FieldElement(11)
        f.mulInt(3)
        f.normalise()
        XCTAssertEqual(f, FieldElement(33))
    }

    func testMulByOne() {
        let gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        var a = FieldElement(hex: gx)!
        a.normalise()
        let one = FieldElement(1)
        var result = FieldElement.mul(a, one)
        result.normalise()
        XCTAssertEqual(result.hex, gx)
    }

    // MARK: - Squaring

    func testSquare() {
        var a = FieldElement(7)
        var b = a.squared()
        b.normalise()
        XCTAssertEqual(b, FieldElement(49))
    }

    func testSquareEqualsMultiply() {
        let gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        var a = FieldElement(hex: gx)!
        a.normalise()
        var sq = a.squared()
        sq.normalise()
        var mul = FieldElement.mul(a, a)
        mul.normalise()
        XCTAssertEqual(sq, mul)
    }

    // MARK: - Inverse

    func testInverse() {
        let gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        var a = FieldElement(hex: gx)!
        a.normalise()
        var inv = a.inversed()
        inv.normalise()
        // a * a^(-1) should equal 1
        var product = FieldElement.mul(a, inv)
        product.normalise()
        XCTAssertTrue(product.isOne, "Expected a * a^(-1) = 1, got \(product.hex)")
    }

    func testInverseSmall() {
        var a = FieldElement(3)
        var inv = a.inversed()
        inv.normalise()
        var product = FieldElement.mul(FieldElement(3), inv)
        product.normalise()
        XCTAssertTrue(product.isOne)
    }

    // MARK: - Square root

    func testSqrt() {
        // 4 has a well-known square root of 2
        var f = FieldElement(4)
        var root = f.squareRoot()
        root.normalise()
        var check = root.squared()
        check.normalise()
        XCTAssertEqual(check, FieldElement(4))
    }

    func testSqrtOfGeneratorX() {
        // Verify that x³ + 7 has a square root (i.e., the generator point is on the curve).
        let gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        var x = FieldElement(hex: gx)!
        x.normalise()
        // y² = x³ + 7
        var x3 = x.squared()
        x3.mul(x)
        x3.normalise()
        x3.addInt(7)
        x3.normalise()
        var y = x3.squareRoot()
        y.normalise()
        var y2 = y.squared()
        y2.normalise()
        x3 = FieldElement(hex: gx)!
        x3.normalise()
        var x3check = x3.squared()
        x3check.mul(x3)
        x3check.normalise()
        x3check.addInt(7)
        x3check.normalise()
        XCTAssertEqual(y2, x3check, "sqrt(x³+7)² should equal x³+7")
    }

    // MARK: - Odd/Even

    func testIsOdd() {
        XCTAssertTrue(FieldElement(1).isOdd)
        XCTAssertTrue(FieldElement(3).isOdd)
        XCTAssertFalse(FieldElement(0).isOdd)
        XCTAssertFalse(FieldElement(2).isOdd)
    }

    // MARK: - Edge cases

    func testPrimeIsZero() {
        // The prime itself should normalise to zero.
        let p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        var f = FieldElement(hex: p)!
        f.normalise()
        XCTAssertTrue(f.isZero, "The prime modulus should normalise to zero")
    }

    func testPrimeMinusOneIsMaxValue() {
        let pMinusOne = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"
        var f = FieldElement(hex: pMinusOne)!
        f.normalise()
        XCTAssertFalse(f.isZero)
        XCTAssertEqual(f.hex, pMinusOne)
    }
}
