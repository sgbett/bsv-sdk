import XCTest
@testable import BSV

final class ScriptChunkTests: XCTestCase {

    func testBareOpcodeRoundtrip() {
        let chunk = ScriptChunk(opcode: OpCodes.OP_DUP)
        let binary = chunk.toBinary()
        XCTAssertEqual(binary, Data([0x76]))

        var offset = 0
        let parsed = try! ScriptChunk.fromBinary(binary, offset: &offset)
        XCTAssertEqual(parsed.opcode, OpCodes.OP_DUP)
        XCTAssertNil(parsed.data)
        XCTAssertEqual(offset, 1)
    }

    func testDirectPushRoundtrip() {
        // 3 bytes of data → opcode 0x03
        let data = Data([0xaa, 0xbb, 0xcc])
        let chunk = ScriptChunk(opcode: 0x03, data: data)
        let binary = chunk.toBinary()
        XCTAssertEqual(binary, Data([0x03, 0xaa, 0xbb, 0xcc]))

        var offset = 0
        let parsed = try! ScriptChunk.fromBinary(binary, offset: &offset)
        XCTAssertEqual(parsed.opcode, 0x03)
        XCTAssertEqual(parsed.data, data)
        XCTAssertEqual(offset, 4)
    }

    func testPushData1Roundtrip() {
        // 100 bytes → needs OP_PUSHDATA1
        let data = Data(repeating: 0x42, count: 100)
        let chunk = ScriptChunk(opcode: OpCodes.OP_PUSHDATA1, data: data)
        let binary = chunk.toBinary()

        XCTAssertEqual(binary[0], OpCodes.OP_PUSHDATA1)
        XCTAssertEqual(binary[1], 100) // length byte
        XCTAssertEqual(binary.count, 102) // 1 opcode + 1 length + 100 data

        var offset = 0
        let parsed = try! ScriptChunk.fromBinary(binary, offset: &offset)
        XCTAssertEqual(parsed.opcode, OpCodes.OP_PUSHDATA1)
        XCTAssertEqual(parsed.data, data)
    }

    func testPushData2Roundtrip() {
        let data = Data(repeating: 0xAB, count: 300)
        let chunk = ScriptChunk(opcode: OpCodes.OP_PUSHDATA2, data: data)
        let binary = chunk.toBinary()

        XCTAssertEqual(binary[0], OpCodes.OP_PUSHDATA2)
        // Length is 300 = 0x012C in LE → [0x2C, 0x01]
        XCTAssertEqual(binary[1], 0x2C)
        XCTAssertEqual(binary[2], 0x01)
        XCTAssertEqual(binary.count, 303) // 1 + 2 + 300

        var offset = 0
        let parsed = try! ScriptChunk.fromBinary(binary, offset: &offset)
        XCTAssertEqual(parsed.opcode, OpCodes.OP_PUSHDATA2)
        XCTAssertEqual(parsed.data, data)
    }

    func testEncodePushDataMinimal() {
        // 20 bytes → direct push (opcode = 0x14)
        let data20 = Data(repeating: 0x00, count: 20)
        let chunk20 = ScriptChunk.encodePushData(data20)
        XCTAssertEqual(chunk20.opcode, 0x14)

        // 76 bytes → OP_PUSHDATA1
        let data76 = Data(repeating: 0x00, count: 76)
        let chunk76 = ScriptChunk.encodePushData(data76)
        XCTAssertEqual(chunk76.opcode, OpCodes.OP_PUSHDATA1)

        // 256 bytes → OP_PUSHDATA2
        let data256 = Data(repeating: 0x00, count: 256)
        let chunk256 = ScriptChunk.encodePushData(data256)
        XCTAssertEqual(chunk256.opcode, OpCodes.OP_PUSHDATA2)
    }

    func testParseAllMultipleChunks() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        var script = Data()
        script.append(OpCodes.OP_DUP)
        script.append(OpCodes.OP_HASH160)
        script.append(0x14) // push 20 bytes
        script.append(Data(repeating: 0xAA, count: 20))
        script.append(OpCodes.OP_EQUALVERIFY)
        script.append(OpCodes.OP_CHECKSIG)

        let chunks = try! ScriptChunk.parseAll(from: script)
        XCTAssertEqual(chunks.count, 5)
        XCTAssertEqual(chunks[0].opcode, OpCodes.OP_DUP)
        XCTAssertEqual(chunks[1].opcode, OpCodes.OP_HASH160)
        XCTAssertEqual(chunks[2].opcode, 0x14)
        XCTAssertEqual(chunks[2].data?.count, 20)
        XCTAssertEqual(chunks[3].opcode, OpCodes.OP_EQUALVERIFY)
        XCTAssertEqual(chunks[4].opcode, OpCodes.OP_CHECKSIG)
    }

    func testParseErrorOnTruncatedData() {
        // Opcode says push 5 bytes but only 2 available
        let data = Data([0x05, 0xAA, 0xBB])
        XCTAssertThrowsError(try ScriptChunk.parseAll(from: data))
    }

    func testASMRepresentation() {
        let opChunk = ScriptChunk(opcode: OpCodes.OP_DUP)
        XCTAssertEqual(opChunk.toASM(), "OP_DUP")

        let dataChunk = ScriptChunk(opcode: 0x03, data: Data([0xaa, 0xbb, 0xcc]))
        XCTAssertEqual(dataChunk.toASM(), "aabbcc")
    }
}
