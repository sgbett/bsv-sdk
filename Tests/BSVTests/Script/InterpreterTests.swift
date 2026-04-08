// SPDX-License-Identifier: Open BSV License Version 5
// Tests for the Bitcoin script interpreter.

import XCTest
@testable import BSV

final class InterpreterTests: XCTestCase {

    /// Helper: evaluate unlock + lock pair as ASM and return true on success.
    private func eval(_ unlock: String, _ lock: String) -> Bool {
        guard let u = Script.fromASM(unlock), let l = Script.fromASM(lock) else {
            return false
        }
        do {
            return try Interpreter.evaluate(unlockingScript: u, lockingScript: l)
        } catch {
            return false
        }
    }

    // MARK: - Basic push + equality

    func testTrivialTruthyPush() throws {
        let unlock = Script(data: Data([OpCodes.OP_1]))
        let lock = Script(data: Data())
        XCTAssertTrue(try Interpreter.evaluate(unlockingScript: unlock, lockingScript: lock))
    }

    func testFalseStackFails() {
        let unlock = Script(data: Data([OpCodes.OP_0]))
        let lock = Script(data: Data())
        XCTAssertThrowsError(try Interpreter.evaluate(unlockingScript: unlock, lockingScript: lock))
    }

    func testSimpleTrue() { XCTAssertTrue(eval("OP_1", "OP_1 OP_EQUAL")) }
    func testAdd() { XCTAssertTrue(eval("OP_2 OP_3", "OP_ADD OP_5 OP_EQUAL")) }
    func testSub() { XCTAssertTrue(eval("OP_5 OP_3", "OP_SUB OP_2 OP_EQUAL")) }
    func testNegativeResult() {
        // 3 - 5 = -2 ; encoded as 0x82.
        XCTAssertTrue(eval("OP_3 OP_5", "OP_SUB 82 OP_EQUAL"))
    }
    func testFalseResult() { XCTAssertFalse(eval("OP_1 OP_2", "OP_ADD OP_1 OP_EQUAL")) }

    // MARK: - Stack manipulation

    func testDupEqualverify() { XCTAssertTrue(eval("OP_5", "OP_DUP OP_EQUALVERIFY OP_1")) }
    func testSwap() { XCTAssertTrue(eval("OP_1 OP_2", "OP_SWAP OP_1 OP_EQUALVERIFY OP_2 OP_EQUAL")) }
    func testRotAndDrop() {
        // 1 2 3 -> ROT -> 2 3 1 -> DROP -> 2 3 -> DROP -> 2 (truthy).
        XCTAssertTrue(eval("OP_1 OP_2 OP_3", "OP_ROT OP_DROP OP_DROP"))
    }
    func testDepth() { XCTAssertTrue(eval("OP_1 OP_1", "OP_DEPTH OP_2 OP_EQUALVERIFY OP_DROP")) }

    // MARK: - Flow control

    func testIfTrue() { XCTAssertTrue(eval("OP_1", "OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF")) }
    func testIfFalse() { XCTAssertFalse(eval("OP_0", "OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF")) }
    func testVerify() {
        XCTAssertFalse(eval("OP_0", "OP_VERIFY OP_1"))
        XCTAssertTrue(eval("OP_1", "OP_VERIFY OP_1"))
    }

    func testUnbalancedIfFails() {
        let unlock = Script(data: Data([OpCodes.OP_1]))
        let lock = Script(data: Data([OpCodes.OP_IF, OpCodes.OP_1]))
        XCTAssertThrowsError(try Interpreter.evaluate(unlockingScript: unlock, lockingScript: lock))
    }

    // MARK: - Crypto

    func testHash160() {
        // HASH160("") = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
        XCTAssertTrue(eval("OP_0", "OP_HASH160 b472a266d0bd89c13706a4132ccfb16f7c3b9fcb OP_EQUAL"))
    }

    func testSha256() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        XCTAssertTrue(eval("OP_0", "OP_SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 OP_EQUAL"))
    }

    // MARK: - Splice

    func testCatAndSplit() {
        XCTAssertTrue(eval("aa bb", "OP_CAT OP_DUP OP_1 OP_SPLIT OP_CAT OP_EQUAL"))
    }

    func testSize() {
        XCTAssertTrue(eval("aabbccdd", "OP_SIZE OP_4 OP_EQUALVERIFY OP_DROP OP_1"))
    }

    // MARK: - Bitwise

    func testAndOrXor() {
        XCTAssertTrue(eval("0f 05", "OP_AND 05 OP_EQUAL"))
        XCTAssertTrue(eval("0f 05", "OP_OR 0f OP_EQUAL"))
        XCTAssertTrue(eval("0f 05", "OP_XOR 0a OP_EQUAL"))
    }

    // MARK: - Push-only unlocking enforcement

    func testUnlockingMustBePushOnly() {
        let unlock = Script(data: Data([OpCodes.OP_1, OpCodes.OP_DUP]))
        let lock = Script(data: Data([OpCodes.OP_DROP, OpCodes.OP_1]))
        XCTAssertThrowsError(try Interpreter.evaluate(unlockingScript: unlock, lockingScript: lock))
    }

    // MARK: - End-to-end P2PKH signing and evaluation

    func testP2PKHEvaluatesWithSignedTransaction() throws {
        let priv = PrivateKey(hex: String(repeating: "01", count: 32))!
        let pub = PublicKey.fromPrivateKey(priv)
        let lockScript = Script.p2pkhLock(hash160: pub.hash160())

        let sourceTx = Transaction(version: 1, inputs: [], outputs: [], lockTime: 0)
        sourceTx.addOutput(satoshis: 10_000, lockingScript: lockScript)

        let spendTx = Transaction(version: 1, inputs: [], outputs: [], lockTime: 0)
        spendTx.addInput(
            sourceTXID: sourceTx.txidData(),
            sourceOutputIndex: 0,
            sourceSatoshis: 10_000,
            sourceLockingScript: lockScript,
            unlockingScriptTemplate: P2PKH.unlock(privateKey: priv)
        )
        spendTx.addOutput(satoshis: 9_000, lockingScript: Script.p2pkhLock(hash160: pub.hash160()))

        try spendTx.sign()

        XCTAssertTrue(try Interpreter.verify(transaction: spendTx, inputIndex: 0))
    }

    func testP2PKHFailsWithTamperedOutput() throws {
        let priv = PrivateKey(hex: String(repeating: "02", count: 32))!
        let pub = PublicKey.fromPrivateKey(priv)
        let lockScript = Script.p2pkhLock(hash160: pub.hash160())

        let sourceTx = Transaction(version: 1, inputs: [], outputs: [], lockTime: 0)
        sourceTx.addOutput(satoshis: 5_000, lockingScript: lockScript)

        let spendTx = Transaction(version: 1, inputs: [], outputs: [], lockTime: 0)
        spendTx.addInput(
            sourceTXID: sourceTx.txidData(),
            sourceOutputIndex: 0,
            sourceSatoshis: 5_000,
            sourceLockingScript: lockScript,
            unlockingScriptTemplate: P2PKH.unlock(privateKey: priv)
        )
        spendTx.addOutput(satoshis: 4_000, lockingScript: Script.p2pkhLock(hash160: pub.hash160()))

        try spendTx.sign()

        // Tamper with the output amount after signing.
        spendTx.outputs[0] = TransactionOutput(
            satoshis: 1_000,
            lockingScript: spendTx.outputs[0].lockingScript
        )

        XCTAssertThrowsError(try Interpreter.verify(transaction: spendTx, inputIndex: 0))
    }
}
