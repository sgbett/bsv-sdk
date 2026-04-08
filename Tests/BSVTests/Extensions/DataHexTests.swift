import XCTest
import Foundation
@testable import BSV

final class DataHexTests: XCTestCase {

    // MARK: - Hex String → Data

    func testEmptyHexString() {
        XCTAssertEqual(Data(hex: ""), Data())
    }

    func testValidLowercaseHex() {
        XCTAssertEqual(Data(hex: "48656c6c6f"), Data([0x48, 0x65, 0x6c, 0x6c, 0x6f]))
    }

    func testValidUppercaseHex() {
        XCTAssertEqual(Data(hex: "48656C6C6F"), Data([0x48, 0x65, 0x6c, 0x6c, 0x6f]))
    }

    func testOddLengthHexPadsLeadingZero() {
        XCTAssertEqual(Data(hex: "1"), Data([0x01]))
    }

    func testInvalidCharactersReturnNil() {
        XCTAssertNil(Data(hex: "ZZZZ"))
        XCTAssertNil(Data(hex: "0xGG"))
    }

    func testHexPrefixStripped() {
        XCTAssertEqual(Data(hex: "0xff"), Data([0xff]))
    }

    func testAllZeroBytes() {
        XCTAssertEqual(Data(hex: "000000"), Data([0x00, 0x00, 0x00]))
    }

    // MARK: - Data → Hex String

    func testEmptyDataToHex() {
        XCTAssertEqual(Data().hex, "")
    }

    func testDataToHexIsLowercase() {
        XCTAssertEqual(Data([0xDE, 0xAD, 0xBE, 0xEF]).hex, "deadbeef")
    }

    func testRoundTrip() {
        let original = "0123456789abcdef"
        let data = Data(hex: original)!
        XCTAssertEqual(data.hex, original)
    }

    func testSingleByte() {
        let data = Data(hex: "0a")
        XCTAssertEqual(data, Data([0x0a]))
        XCTAssertEqual(data?.hex, "0a")
    }
}
