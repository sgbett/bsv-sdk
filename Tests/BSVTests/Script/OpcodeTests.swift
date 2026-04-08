import XCTest
@testable import BSV

final class OpcodeTests: XCTestCase {

    func testKnownOpcodeValues() {
        XCTAssertEqual(OpCodes.OP_0, 0x00)
        XCTAssertEqual(OpCodes.OP_FALSE, 0x00)
        XCTAssertEqual(OpCodes.OP_PUSHDATA1, 0x4c)
        XCTAssertEqual(OpCodes.OP_PUSHDATA2, 0x4d)
        XCTAssertEqual(OpCodes.OP_PUSHDATA4, 0x4e)
        XCTAssertEqual(OpCodes.OP_1NEGATE, 0x4f)
        XCTAssertEqual(OpCodes.OP_1, 0x51)
        XCTAssertEqual(OpCodes.OP_TRUE, 0x51)
        XCTAssertEqual(OpCodes.OP_16, 0x60)
        XCTAssertEqual(OpCodes.OP_DUP, 0x76)
        XCTAssertEqual(OpCodes.OP_HASH160, 0xa9)
        XCTAssertEqual(OpCodes.OP_EQUALVERIFY, 0x88)
        XCTAssertEqual(OpCodes.OP_CHECKSIG, 0xac)
        XCTAssertEqual(OpCodes.OP_RETURN, 0x6a)
        XCTAssertEqual(OpCodes.OP_CHECKMULTISIG, 0xae)
        XCTAssertEqual(OpCodes.OP_INVALIDOPCODE, 0xff)
    }

    func testNameLookup() {
        XCTAssertEqual(OpCodes.name(for: 0x76), "OP_DUP")
        XCTAssertEqual(OpCodes.name(for: 0xa9), "OP_HASH160")
        XCTAssertEqual(OpCodes.name(for: 0x00), "OP_0")
        XCTAssertEqual(OpCodes.name(for: 0x14), "OP_DATA_20")
    }

    func testCodeLookup() {
        XCTAssertEqual(OpCodes.code(for: "OP_DUP"), 0x76)
        XCTAssertEqual(OpCodes.code(for: "OP_CHECKSIG"), 0xac)
        XCTAssertEqual(OpCodes.code(for: "OP_FALSE"), 0x00)
        XCTAssertEqual(OpCodes.code(for: "OP_TRUE"), 0x51)
        XCTAssertNil(OpCodes.code(for: "OP_NONEXISTENT"))
    }

    func testIsDataPush() {
        XCTAssertFalse(OpCodes.isDataPush(0x00))
        XCTAssertTrue(OpCodes.isDataPush(0x01))
        XCTAssertTrue(OpCodes.isDataPush(0x4b))
        XCTAssertFalse(OpCodes.isDataPush(0x4c))
    }

    func testSmallIntValue() {
        XCTAssertEqual(OpCodes.smallIntValue(OpCodes.OP_0), 0)
        XCTAssertEqual(OpCodes.smallIntValue(OpCodes.OP_1), 1)
        XCTAssertEqual(OpCodes.smallIntValue(OpCodes.OP_16), 16)
        XCTAssertNil(OpCodes.smallIntValue(OpCodes.OP_DUP))
    }
}
