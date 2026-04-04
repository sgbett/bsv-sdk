import XCTest
@testable import BSV

final class ScalarTests: XCTestCase {

    func testScalarMulSmall() {
        var a = Data(count: 32); a[31] = 7
        var b = Data(count: 32); b[31] = 6
        let result = scalarMulModN(a, b)
        var expected = Data(count: 32); expected[31] = 42
        XCTAssertEqual(result, expected, "7 * 6 mod N = 42")
    }

    func testScalarInvModN() {
        var a = Data(count: 32); a[31] = 7
        let inv = scalarInvModN(a)
        let product = scalarMulModN(inv, a)
        var one = Data(count: 32); one[31] = 1
        XCTAssertEqual(product, one, "7 * 7^(-1) mod N should be 1")
    }

    func testScalarAddModN() {
        var a = Data(count: 32); a[31] = 3
        var b = Data(count: 32); b[31] = 4
        let result = scalarAddModN(a, b)
        var expected = Data(count: 32); expected[31] = 7
        XCTAssertEqual(result, expected)
    }

    func testScalarModN() {
        // N itself should become 0
        let result = scalarModN(Secp256k1.N)
        XCTAssertTrue(scalarIsZero(result), "N mod N = 0")
    }

    func testScalarMulLarger() {
        // a * 1 = a mod N
        let a = Data(hex: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")!
        var one = Data(count: 32); one[31] = 1
        let result = scalarMulModN(a, one)
        XCTAssertEqual(result, a, "a * 1 should be a, got \(result.hex)")
    }

    func testScalarMulCommutative() {
        var a = Data(count: 32); a[31] = 100
        var b = Data(count: 32); b[31] = 200
        let ab = scalarMulModN(a, b)
        let ba = scalarMulModN(b, a)
        XCTAssertEqual(ab, ba, "Multiplication should be commutative")
        // 100 * 200 = 20000
        var expected = Data(count: 32)
        expected[30] = 0x4E  // 20000 = 0x4E20
        expected[31] = 0x20
        XCTAssertEqual(ab, expected, "100*200=20000")
    }

    func testScalarInvLarger() {
        // Use a realistic 32-byte value
        let a = Data(hex: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")!
        let inv = scalarInvModN(a)
        let product = scalarMulModN(inv, a)
        var one = Data(count: 32); one[31] = 1
        XCTAssertEqual(product, one, "a * a^(-1) mod N should be 1, got \(product.hex)")
    }
}
