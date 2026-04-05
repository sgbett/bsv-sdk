import XCTest
@testable import BSV

final class Phase4ConformanceTests: XCTestCase {

    // MARK: - Transaction Serialisation

    func testTransactionRoundtrip() throws {
        // A simple 1-input, 2-output transaction
        let hex = "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"

        let tx = try Transaction.fromHex(hex)
        XCTAssertEqual(tx.version, 1)
        XCTAssertEqual(tx.inputs.count, 1)
        XCTAssertEqual(tx.outputs.count, 2)
        XCTAssertEqual(tx.lockTime, 0)
        XCTAssertEqual(tx.toHex(), hex)
    }

    func testTransactionTwoInputs() throws {
        let hex = "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000"

        let tx = try Transaction.fromHex(hex)
        XCTAssertEqual(tx.inputs.count, 2)
        XCTAssertEqual(tx.outputs.count, 3)
        XCTAssertEqual(tx.toHex(), hex)
    }

    func testTransactionId() throws {
        let hex = "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"
        let tx = try Transaction.fromHex(hex)
        let txid = tx.txid()
        // txid should be 64 hex chars
        XCTAssertEqual(txid.count, 64)
        // Round-trip: re-serialise and check txid is stable
        let tx2 = try Transaction.fromHex(tx.toHex())
        XCTAssertEqual(tx2.txid(), txid)
    }

    // MARK: - Sighash Preimage (BIP-143 with FORKID)

    func testSighashPreimage1In2Out() throws {
        let txHex = "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"
        let tx = try Transaction.fromHex(txHex)

        tx.inputs[0].sourceSatoshis = 100000000
        tx.inputs[0].sourceLockingScript = Script(hex: "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")

        let pre = try Sighash.preimage(tx: tx, inputIndex: 0, sighashType: .allForkID)
        XCTAssertEqual(pre.hex, "010000007ced5b2e5cf3ea407b005d8b18c393b6256ea2429b6ff409983e10adc61d0ae83bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504493a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac00e1f50500000000ffffffff87841ab2b7a4133af2c58256edb7c3c9edca765a852ebe2d0dc962604a30f1030000000041000000")
    }

    func testSighashPreimage2In3OutIndex0() throws {
        let txHex = "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000"
        let tx = try Transaction.fromHex(txHex)

        tx.inputs[0].sourceSatoshis = 2000000000
        tx.inputs[0].sourceLockingScript = Script(hex: "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac")

        let pre = try Sighash.preimage(tx: tx, inputIndex: 0, sighashType: .allForkID)
        XCTAssertEqual(pre.hex, "01000000eaef7a1b82f72f4097e63b0173906d690cc137221d221fc4150bae88570fa356752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0094357700000000ffffffff0cf3246582f4b1b5fd150b942916c7d5c78e80259cbab1a761a9e4ac3a66e0a70000000041000000")
    }

    func testSighashPreimage2In3OutIndex1() throws {
        let txHex = "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000"
        let tx = try Transaction.fromHex(txHex)

        tx.inputs[1].sourceSatoshis = 2000000000
        tx.inputs[1].sourceLockingScript = Script(hex: "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac")

        let pre = try Sighash.preimage(tx: tx, inputIndex: 1, sighashType: .allForkID)
        XCTAssertEqual(pre.hex, "01000000eaef7a1b82f72f4097e63b0173906d690cc137221d221fc4150bae88570fa356752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632addebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0094357700000000ffffffff0cf3246582f4b1b5fd150b942916c7d5c78e80259cbab1a761a9e4ac3a66e0a70000000041000000")
    }

    // MARK: - Sighash Digest

    func testSighashDigest1In2Out() throws {
        let txHex = "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"
        let tx = try Transaction.fromHex(txHex)

        tx.inputs[0].sourceSatoshis = 100000000
        tx.inputs[0].sourceLockingScript = Script(hex: "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")

        let hash = try Sighash.signatureHash(tx: tx, inputIndex: 0, sighashType: .allForkID)
        XCTAssertEqual(hash.hex, "be9a42ef2e2dd7ef02cd631290667292cbbc5018f4e3f6843a8f4c302a2111b1")
    }

    func testSighashDigest2In3OutIndex0() throws {
        let txHex = "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000"
        let tx = try Transaction.fromHex(txHex)

        tx.inputs[0].sourceSatoshis = 2000000000
        tx.inputs[0].sourceLockingScript = Script(hex: "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac")

        let hash = try Sighash.signatureHash(tx: tx, inputIndex: 0, sighashType: .allForkID)
        XCTAssertEqual(hash.hex, "8b15eecfb6d5e727485e19797b5d1829e0630e8b43c806707685238e28a3194c")
    }

    func testSighashDigest2In3OutIndex1() throws {
        let txHex = "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000"
        let tx = try Transaction.fromHex(txHex)

        tx.inputs[1].sourceSatoshis = 2000000000
        tx.inputs[1].sourceLockingScript = Script(hex: "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac")

        let hash = try Sighash.signatureHash(tx: tx, inputIndex: 1, sighashType: .allForkID)
        XCTAssertEqual(hash.hex, "7b72c355a2714a5039d97fbd5eee792099b0eab4bf07d2e5bfcfc3309f81badb")
    }

    // MARK: - P2PKH End-to-End

    func testP2PKHSignAndVerifyStructure() throws {
        // Use a known private key
        let privKeyData = Data(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let privKey = PrivateKey(data: privKeyData)!
        let pubKey = PublicKey.fromPrivateKey(privKey)
        let pubKeyHash = Digest.hash160(pubKey.toCompressed())

        // Create a locking script
        let lockingScript = P2PKH.lock(hash160: pubKeyHash)
        XCTAssertTrue(lockingScript.isP2PKH)

        // Build a transaction spending a fake UTXO
        let tx = Transaction()
        let fakeTxid = Digest.sha256d(Data("fake utxo".utf8))
        tx.addInput(
            sourceTXID: fakeTxid,
            sourceOutputIndex: 0,
            sourceSatoshis: 100000,
            sourceLockingScript: lockingScript,
            unlockingScriptTemplate: P2PKH.unlock(privateKey: privKey)
        )
        tx.addOutput(
            satoshis: 90000,
            lockingScript: P2PKH.lock(hash160: pubKeyHash)
        )

        // Sign
        try tx.sign()

        // Verify the unlocking script has 2 pushes (sig + pubkey)
        let chunks = tx.inputs[0].unlockingScript.chunks
        XCTAssertEqual(chunks.count, 2)

        // First chunk: DER signature + sighash byte
        let sigData = chunks[0].data!
        XCTAssertEqual(sigData[0], 0x30) // DER sequence tag
        XCTAssertEqual(sigData.last, 0x41) // SIGHASH_ALL | FORKID

        // Second chunk: compressed public key (33 bytes)
        let pubKeyFromScript = chunks[1].data!
        XCTAssertEqual(pubKeyFromScript.count, 33)
        XCTAssertEqual(pubKeyFromScript, pubKey.toCompressed())

        // Serialisation round-trip
        let hex = tx.toHex()
        let tx2 = try Transaction.fromHex(hex)
        XCTAssertEqual(tx2.toHex(), hex)
        XCTAssertEqual(tx2.txid(), tx.txid())
    }

    // MARK: - Fee Model

    func testSatoshisPerKilobyteFee() {
        let model = SatoshisPerKilobyte(satoshis: 50)

        // Build a simple transaction to estimate
        let tx = Transaction()
        let fakeTxid = Data(count: 32)
        tx.addInput(
            sourceTXID: fakeTxid,
            sourceOutputIndex: 0,
            sourceSatoshis: 100000,
            sourceLockingScript: Script(data: Data()),
            unlockingScriptTemplate: P2PKHUnlock(
                privateKey: PrivateKey(data: Data(hex: "0000000000000000000000000000000000000000000000000000000000000001")!)!
            )
        )
        tx.addOutput(satoshis: 90000, lockingScript: Script.p2pkhLock(hash160: Data(count: 20)))

        let fee = model.computeFee(tx: tx)
        // Estimated size ~148 bytes for 1-in 1-out P2PKH, fee = ceil(148/1000 * 50) = 8
        XCTAssertTrue(fee > 0)
        XCTAssertTrue(fee < 100) // sanity check
    }

    // MARK: - TransactionInput/Output Serialisation

    func testOutputBinarySerialization() {
        let output = TransactionOutput(
            satoshis: 5000000,
            lockingScript: Script(hex: "76a91404ff367be719efa79d76e4416ffb072cd53b208888ac")!
        )
        let binary = output.toBinary()

        // Parse it back
        var offset = 0
        let parsed = try! TransactionOutput.fromBinary(binary, offset: &offset)
        XCTAssertEqual(parsed.satoshis, 5000000)
        XCTAssertEqual(parsed.lockingScript.toHex(), "76a91404ff367be719efa79d76e4416ffb072cd53b208888ac")
    }

    func testInputBinarySerialization() {
        let txid = Data(hex: "93a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651")!
        let input = TransactionInput(
            sourceTXID: txid,
            sourceOutputIndex: 0,
            unlockingScript: Script(data: Data()),
            sequenceNumber: 0xFFFFFFFF
        )
        let binary = input.toBinary()

        var offset = 0
        let parsed = try! TransactionInput.fromBinary(binary, offset: &offset)
        XCTAssertEqual(parsed.sourceTXID, txid)
        XCTAssertEqual(parsed.sourceOutputIndex, 0)
        XCTAssertEqual(parsed.sequenceNumber, 0xFFFFFFFF)
    }
}
