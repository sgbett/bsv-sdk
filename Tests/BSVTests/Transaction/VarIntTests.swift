import XCTest
import Foundation
@testable import BSV

final class VarIntTests: XCTestCase {

    // MARK: - Single byte (0x00–0xFC)

    func testEncodeZero() {
        XCTAssertEqual(VarInt.encode(0), Data([0x00]))
    }

    func testEncodeSmallValue() {
        XCTAssertEqual(VarInt.encode(100), Data([0x64]))
    }

    func testEncodeMaxSingleByte() {
        XCTAssertEqual(VarInt.encode(0xFC), Data([0xFC]))
    }

    // MARK: - Two bytes (0xFD prefix)

    func testEncodeTwoByteMinimum() {
        XCTAssertEqual(VarInt.encode(0xFD), Data([0xFD, 0xFD, 0x00]))
    }

    func testEncodeTwoByteValue() {
        XCTAssertEqual(VarInt.encode(260), Data([0xFD, 0x04, 0x01]))
    }

    func testEncodeTwoByteMax() {
        XCTAssertEqual(VarInt.encode(0xFFFF), Data([0xFD, 0xFF, 0xFF]))
    }

    // MARK: - Four bytes (0xFE prefix)

    func testEncodeFourByteMinimum() {
        XCTAssertEqual(VarInt.encode(0x10000), Data([0xFE, 0x00, 0x00, 0x01, 0x00]))
    }

    func testEncodeFourByteMax() {
        XCTAssertEqual(VarInt.encode(0xFFFF_FFFF), Data([0xFE, 0xFF, 0xFF, 0xFF, 0xFF]))
    }

    // MARK: - Eight bytes (0xFF prefix)

    func testEncodeEightByteMinimum() {
        XCTAssertEqual(VarInt.encode(0x1_0000_0000), Data([0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]))
    }

    func testEncodeEightByteMax() {
        XCTAssertEqual(VarInt.encode(UInt64.max), Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
    }

    // MARK: - Decode

    func testDecodeSingleByte() {
        let result = VarInt.decode(Data([0x64]))
        XCTAssertEqual(result?.value, 100)
        XCTAssertEqual(result?.bytesRead, 1)
    }

    func testDecodeTwoBytes() {
        let result = VarInt.decode(Data([0xFD, 0x04, 0x01]))
        XCTAssertEqual(result?.value, 260)
        XCTAssertEqual(result?.bytesRead, 3)
    }

    func testDecodeFourBytes() {
        let result = VarInt.decode(Data([0xFE, 0x00, 0x00, 0x01, 0x00]))
        XCTAssertEqual(result?.value, 0x10000)
        XCTAssertEqual(result?.bytesRead, 5)
    }

    func testDecodeEightBytes() {
        let result = VarInt.decode(Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
        XCTAssertEqual(result?.value, UInt64.max)
        XCTAssertEqual(result?.bytesRead, 9)
    }

    func testDecodeWithOffset() {
        let data = Data([0x00, 0x00, 0xFD, 0x04, 0x01])
        let result = VarInt.decode(data, offset: 2)
        XCTAssertEqual(result?.value, 260)
        XCTAssertEqual(result?.bytesRead, 3)
    }

    func testDecodeInsufficientData() {
        XCTAssertNil(VarInt.decode(Data([0xFD, 0x04])))
        XCTAssertNil(VarInt.decode(Data([0xFE, 0x00, 0x00])))
        XCTAssertNil(VarInt.decode(Data([0xFF, 0x00])))
        XCTAssertNil(VarInt.decode(Data()))
    }

    // MARK: - Round trip

    func testRoundTrip() {
        let values: [UInt64] = [0, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFF_FFFF, 0x1_0000_0000, UInt64.max]
        for value in values {
            let encoded = VarInt.encode(value)
            let decoded = VarInt.decode(encoded)
            XCTAssertEqual(decoded?.value, value, "Round-trip failed for \(value)")
        }
    }
}
