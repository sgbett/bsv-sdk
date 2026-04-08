// SPDX-License-Identifier: Open BSV License Version 5
// Tests for Bitcoin script number encoding.

import XCTest
@testable import BSV

final class ScriptNumberTests: XCTestCase {

    func testZeroIsEmpty() {
        XCTAssertEqual(ScriptNumber.encode(0), Data())
        XCTAssertEqual(try ScriptNumber.decode(Data()), 0)
    }

    func testSmallPositives() throws {
        XCTAssertEqual(ScriptNumber.encode(1), Data([0x01]))
        XCTAssertEqual(ScriptNumber.encode(16), Data([0x10]))
        XCTAssertEqual(ScriptNumber.encode(127), Data([0x7f]))
        // 128 needs an extra byte because its high bit would be taken as sign.
        XCTAssertEqual(ScriptNumber.encode(128), Data([0x80, 0x00]))
        XCTAssertEqual(try ScriptNumber.decode(Data([0x80, 0x00])), 128)
    }

    func testSmallNegatives() throws {
        XCTAssertEqual(ScriptNumber.encode(-1), Data([0x81]))
        XCTAssertEqual(ScriptNumber.encode(-127), Data([0xff]))
        XCTAssertEqual(ScriptNumber.encode(-128), Data([0x80, 0x80]))
        XCTAssertEqual(try ScriptNumber.decode(Data([0x81])), -1)
        XCTAssertEqual(try ScriptNumber.decode(Data([0x80, 0x80])), -128)
    }

    func testRoundTrip() throws {
        let values: [Int64] = [0, 1, -1, 255, -255, 256, -256, 65535, -65535, 123456, -123456, 2147483647, -2147483647]
        for v in values {
            let data = ScriptNumber.encode(v)
            let back = try ScriptNumber.decode(data, maxNumSize: 8)
            XCTAssertEqual(back, v, "round trip failed for \(v)")
        }
    }

    func testMaxSizeExceeded() {
        let bytes = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        XCTAssertThrowsError(try ScriptNumber.decode(bytes, maxNumSize: 4))
    }

    func testNonMinimalRejected() {
        // 0x00 0x00: redundant trailing zero
        XCTAssertThrowsError(try ScriptNumber.decode(Data([0x00, 0x00])))
        // 0x01 0x00: redundant trailing zero, top not sign-bit
        XCTAssertThrowsError(try ScriptNumber.decode(Data([0x01, 0x00])))
        // 0x80 0x80 is minimal (-128).
        XCTAssertNoThrow(try ScriptNumber.decode(Data([0x80, 0x80])))
    }

    func testCastToBool() {
        XCTAssertFalse(ScriptNumber.castToBool(Data()))
        XCTAssertFalse(ScriptNumber.castToBool(Data([0x00])))
        XCTAssertFalse(ScriptNumber.castToBool(Data([0x00, 0x00, 0x80]))) // negative zero
        XCTAssertTrue(ScriptNumber.castToBool(Data([0x01])))
        XCTAssertTrue(ScriptNumber.castToBool(Data([0x80, 0x00]))) // 128
    }
}

final class ScriptStackTests: XCTestCase {

    func testPushPopPeek() throws {
        var s = ScriptStack()
        try s.push(Data([0x01]))
        try s.push(Data([0x02]))
        XCTAssertEqual(s.size, 2)
        XCTAssertEqual(try s.peek(), Data([0x02]))
        XCTAssertEqual(try s.peek(1), Data([0x01]))
        XCTAssertEqual(try s.pop(), Data([0x02]))
        XCTAssertEqual(s.size, 1)
    }

    func testUnderflow() {
        var s = ScriptStack()
        XCTAssertThrowsError(try s.pop())
        XCTAssertThrowsError(try s.peek())
    }

    func testMaxSize() throws {
        var s = ScriptStack()
        for _ in 0..<ScriptStack.maxStackSize {
            try s.push(Data())
        }
        XCTAssertThrowsError(try s.push(Data()))
    }

    func testAltStack() throws {
        var s = ScriptStack()
        try s.pushAlt(Data([0xAA]))
        XCTAssertEqual(try s.popAlt(), Data([0xAA]))
        XCTAssertThrowsError(try s.popAlt())
    }
}
