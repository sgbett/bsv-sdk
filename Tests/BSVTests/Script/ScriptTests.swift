import XCTest
@testable import BSV

final class ScriptTests: XCTestCase {

    // MARK: - P2PKH Detection

    func testIsP2PKH() {
        // Standard P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let hex = "76a914" + String(repeating: "aa", count: 20) + "88ac"
        let script = Script(hex: hex)!
        XCTAssertTrue(script.isP2PKH)
        XCTAssertFalse(script.isP2PK)
        XCTAssertFalse(script.isP2SH)
        XCTAssertFalse(script.isOpReturn)
    }

    func testP2PKHLockTemplate() {
        let hash160 = Data(repeating: 0xBB, count: 20)
        let script = Script.p2pkhLock(hash160: hash160)
        XCTAssertTrue(script.isP2PKH)
        XCTAssertEqual(script.publicKeyHash(), hash160)
        XCTAssertEqual(script.data.count, 25)
    }

    // MARK: - P2PK Detection

    func testIsP2PKCompressed() {
        // <33-byte compressed pubkey> OP_CHECKSIG
        var data = Data()
        data.append(0x21) // push 33 bytes
        data.append(0x02) // compressed prefix
        data.append(Data(repeating: 0xAA, count: 32))
        data.append(OpCodes.OP_CHECKSIG)
        let script = Script(data: data)
        XCTAssertTrue(script.isP2PK)
    }

    func testIsP2PKUncompressed() {
        // <65-byte uncompressed pubkey> OP_CHECKSIG
        var data = Data()
        data.append(0x41) // push 65 bytes
        data.append(0x04) // uncompressed prefix
        data.append(Data(repeating: 0xBB, count: 64))
        data.append(OpCodes.OP_CHECKSIG)
        let script = Script(data: data)
        XCTAssertTrue(script.isP2PK)
    }

    // MARK: - P2SH Detection (read-only)

    func testIsP2SH() {
        // OP_HASH160 <20 bytes> OP_EQUAL
        let hex = "a914" + String(repeating: "cc", count: 20) + "87"
        let script = Script(hex: hex)!
        XCTAssertTrue(script.isP2SH)
        XCTAssertEqual(script.scriptHash(), Data(repeating: 0xCC, count: 20))
    }

    // MARK: - OP_RETURN Detection

    func testIsOpReturn() {
        // OP_FALSE OP_RETURN <data>
        let script = Script.opReturn(data: Data([0x01, 0x02, 0x03]))
        XCTAssertTrue(script.isOpReturn)
    }

    func testIsOpReturnBare() {
        // OP_RETURN directly
        let script = Script(data: Data([OpCodes.OP_RETURN]))
        XCTAssertTrue(script.isOpReturn)
    }

    // MARK: - Multisig Detection

    func testIsMultisig() {
        // OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
        var data = Data()
        data.append(OpCodes.OP_1)
        // pubkey1: 33 bytes
        data.append(0x21)
        data.append(0x02)
        data.append(Data(repeating: 0xAA, count: 32))
        // pubkey2: 33 bytes
        data.append(0x21)
        data.append(0x03)
        data.append(Data(repeating: 0xBB, count: 32))
        data.append(OpCodes.OP_2)
        data.append(OpCodes.OP_CHECKMULTISIG)
        let script = Script(data: data)
        XCTAssertTrue(script.isMultisig)
    }

    // MARK: - ASM Round-trip

    func testASMRoundtrip() {
        let asm = "OP_DUP OP_HASH160 aabbccddee00112233445566778899aabbccddee OP_EQUALVERIFY OP_CHECKSIG"
        let script = Script.fromASM(asm)!
        XCTAssertTrue(script.isP2PKH)
        let output = script.toASM()
        XCTAssertEqual(output, asm)
    }

    func testFromASMEmpty() {
        let script = Script.fromASM("")!
        XCTAssertEqual(script.data.count, 0)
        XCTAssertEqual(script.toASM(), "")
    }

    // MARK: - Hex Round-trip

    func testHexRoundtrip() {
        let hex = "76a914aabbccddee00112233445566778899aabbccddee88ac"
        let script = Script(hex: hex)!
        XCTAssertEqual(script.toHex(), hex)
    }

    // MARK: - P2PKH Unlock Template

    func testP2PKHUnlock() {
        let sig = Data(repeating: 0x30, count: 72)
        let pubkey = Data(repeating: 0x02, count: 33)
        let script = Script.p2pkhUnlock(signature: sig, publicKey: pubkey)

        let chunks = script.chunks
        XCTAssertEqual(chunks.count, 2)
        XCTAssertEqual(chunks[0].data?.count, 72)
        XCTAssertEqual(chunks[1].data?.count, 33)
    }

    // MARK: - fromChunks

    func testFromChunks() {
        let chunks = [
            ScriptChunk(opcode: OpCodes.OP_DUP),
            ScriptChunk(opcode: OpCodes.OP_HASH160),
            ScriptChunk.encodePushData(Data(repeating: 0xFF, count: 20)),
            ScriptChunk(opcode: OpCodes.OP_EQUALVERIFY),
            ScriptChunk(opcode: OpCodes.OP_CHECKSIG),
        ]
        let script = Script.fromChunks(chunks)
        XCTAssertTrue(script.isP2PKH)
    }

    // MARK: - Equality

    func testEquality() {
        let a = Script(hex: "76a91400000000000000000000000000000000000000008ac")
        let b = Script(hex: "76a91400000000000000000000000000000000000000008ac")
        XCTAssertEqual(a, b)
    }
}
