import XCTest
@testable import BSV

final class ScriptBuilderTests: XCTestCase {

    func testBuildP2PKH() {
        let hash160 = Data(repeating: 0xAA, count: 20)
        let script = ScriptBuilder()
            .addOpcode(OpCodes.OP_DUP)
            .addOpcode(OpCodes.OP_HASH160)
            .addData(hash160)
            .addOpcode(OpCodes.OP_EQUALVERIFY)
            .addOpcode(OpCodes.OP_CHECKSIG)
            .build()

        XCTAssertTrue(script.isP2PKH)
        XCTAssertEqual(script.publicKeyHash(), hash160)
    }

    func testBuildOpReturn() {
        let data = Data("hello".utf8)
        let script = ScriptBuilder()
            .addOpcode(OpCodes.OP_FALSE)
            .addOpcode(OpCodes.OP_RETURN)
            .addData(data)
            .build()

        XCTAssertTrue(script.isOpReturn)
    }

    func testEmptyBuilder() {
        let script = ScriptBuilder().build()
        XCTAssertEqual(script.data.count, 0)
    }
}
