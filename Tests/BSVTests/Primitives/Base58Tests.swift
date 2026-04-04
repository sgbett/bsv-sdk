import XCTest
import Foundation
@testable import BSV

final class Base58Tests: XCTestCase {

    // MARK: - Encode

    func testEncodeEmptyData() {
        XCTAssertEqual(Base58.encode(Data()), "")
    }

    func testEncodeHelloWorld() {
        let data = Data("Hello World!".utf8)
        XCTAssertEqual(Base58.encode(data), "2NEpo7TZRRrLZSi2U")
    }

    func testEncodeLeadingZeros() {
        let data = Data([0x00, 0x00, 0x01])
        let encoded = Base58.encode(data)
        XCTAssertTrue(encoded.hasPrefix("11"))
        XCTAssertEqual(encoded, "112")
    }

    func testEncodeSingleZeroByte() {
        XCTAssertEqual(Base58.encode(Data([0x00])), "1")
    }

    // MARK: - Decode

    func testDecodeEmptyString() {
        XCTAssertEqual(Base58.decode(""), Data())
    }

    func testDecodeHelloWorld() {
        XCTAssertEqual(Base58.decode("2NEpo7TZRRrLZSi2U"), Data("Hello World!".utf8))
    }

    func testDecodeLeadingOnes() {
        XCTAssertEqual(Base58.decode("112"), Data([0x00, 0x00, 0x01]))
    }

    func testDecodeInvalidCharacters() {
        XCTAssertNil(Base58.decode("0"))
        XCTAssertNil(Base58.decode("O"))
        XCTAssertNil(Base58.decode("I"))
        XCTAssertNil(Base58.decode("l"))
    }

    func testRoundTrip() {
        let data = Data(hex: "00010966776006953d5567439e5e39f86a0d273bee")!
        let encoded = Base58.encode(data)
        let decoded = Base58.decode(encoded)
        XCTAssertEqual(decoded, data)
    }

    // MARK: - Base58Check

    func testCheckEncodeAndDecode() {
        let data = Data([0x00, 0x01, 0x09, 0x66, 0x77])
        let encoded = Base58.checkEncode(data)
        let decoded = Base58.checkDecode(encoded)
        XCTAssertEqual(decoded, data)
    }

    func testCheckDecodeInvalidChecksum() {
        let data = Data([0x01, 0x02, 0x03])
        var encoded = Base58.checkEncode(data)
        let lastChar = encoded.removeLast()
        let replacement: Character = lastChar == "a" ? "b" : "a"
        encoded.append(replacement)
        XCTAssertNil(Base58.checkDecode(encoded))
    }

    func testCheckDecodeTooShort() {
        XCTAssertNil(Base58.checkDecode("1"))
    }

    // MARK: - Known Bitcoin vectors

    func testBitcoinAddressVector() {
        let versionAndHash = Data(hex: "00010966776006953d5567439e5e39f86a0d273bee")!
        let address = Base58.checkEncode(versionAndHash)
        XCTAssertEqual(address, "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")
    }
}
