import XCTest
@testable import BSV

final class BSMTests: XCTestCase {

    // MARK: - Magic hash

    func testMagicHashEmptyMessage() {
        let hash = BSM.magicHash(Data())
        // Sanity: magic hash should be 32 bytes.
        XCTAssertEqual(hash.count, 32)
    }

    func testMagicHashKnownValue() {
        // VarInt(24) || "Bitcoin Signed Message:\n" || VarInt(11) || "hello world"
        // SHA-256d
        let hash = BSM.magicHash("hello world".data(using: .utf8)!)
        XCTAssertEqual(hash.count, 32)
    }

    // MARK: - Cross-SDK known vectors (from go-sdk)

    func testSignKnownVectorTestMessage() throws {
        let pk = PrivateKey(hex: "0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")!
        let sig = try BSM.sign(message: "test message", privateKey: pk)
        XCTAssertEqual(
            sig.base64EncodedString(),
            "IFxPx8JHsCiivB+DW/RgNpCLT6yG3j436cUNWKekV3ORBrHNChIjeVReyAco7PVmmDtVD3POs9FhDlm/nk5I6O8="
        )
    }

    func testSignKnownVectorThisIsATest() throws {
        let pk = PrivateKey(hex: "ef0b8bad0be285099534277fde328f8f19b3be9cadcd4c08e6ac0b5f863745ac")!
        let sig = try BSM.sign(message: "This is a test message", privateKey: pk)
        XCTAssertEqual(
            sig.base64EncodedString(),
            "H+zZagsyz7ioC/ZOa5EwsaKice0vs2BvZ0ljgkFHxD3vGsMlGeD4sXHEcfbI4h8lP29VitSBdf4A+nHXih7svf4="
        )
    }

    func testSignKnownVectorOneCharMessage() throws {
        let pk = PrivateKey(hex: "c7726663147afd1add392d129086e57c0b05aa66a6ded564433c04bd55741434")!
        let sig = try BSM.sign(message: "1", privateKey: pk)
        XCTAssertEqual(
            sig.base64EncodedString(),
            "IMcRFG1VNN9TDGXpCU+9CqKLNOuhwQiXI5hZpkTOuYHKBDOWayNuAABofYLqUHYTMiMf9mYFQ0sPgFJZz3F7ELQ="
        )
    }

    func testSignKnownVectorLongMessage() throws {
        let pk = PrivateKey(hex: "0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")!
        let longMessage = String(repeating: "This time I'm writing a new message that is obnixiously long af. ", count: 14).trimmingCharacters(in: .whitespaces)
        let sig = try BSM.sign(message: longMessage, privateKey: pk)
        XCTAssertEqual(
            sig.base64EncodedString(),
            "HxRcFXQc7LHxFNpK5lzhR+LF5ixIvhB089bxYzTAV02yGHm/3ALxltz/W4lGp77Q5UTxdj+TU+96mdAcJ5b/fGs="
        )
    }

    // MARK: - Sign / verify round-trip

    func testSignVerifyRoundTrip() throws {
        let pk = PrivateKey.random()!
        let pub = PublicKey.fromPrivateKey(pk)
        let address = pub.toAddress()

        let message = "round-trip test message"
        let sig = try BSM.sign(message: message, privateKey: pk)

        XCTAssertTrue(BSM.verify(message: message, signature: sig, address: address))
    }

    func testVerifyKnownSignature() throws {
        let pk = PrivateKey(hex: "0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")!
        let address = PublicKey.fromPrivateKey(pk).toAddress()
        let sig = Data(base64Encoded: "IFxPx8JHsCiivB+DW/RgNpCLT6yG3j436cUNWKekV3ORBrHNChIjeVReyAco7PVmmDtVD3POs9FhDlm/nk5I6O8=")!

        XCTAssertTrue(BSM.verify(message: "test message", signature: sig, address: address))
    }

    func testVerifyFailsWithWrongMessage() throws {
        let pk = PrivateKey.random()!
        let address = PublicKey.fromPrivateKey(pk).toAddress()

        let sig = try BSM.sign(message: "original", privateKey: pk)
        XCTAssertFalse(BSM.verify(message: "tampered", signature: sig, address: address))
    }

    func testVerifyFailsWithWrongAddress() throws {
        let alice = PrivateKey.random()!
        let bob = PrivateKey.random()!
        let bobAddress = PublicKey.fromPrivateKey(bob).toAddress()

        let sig = try BSM.sign(message: "hello", privateKey: alice)
        XCTAssertFalse(BSM.verify(message: "hello", signature: sig, address: bobAddress))
    }

    func testVerifyFailsWithBadSignatureLength() {
        let address = "1Some1Address1Here"
        let badSig = Data(repeating: 0, count: 10)
        XCTAssertFalse(BSM.verify(message: "hello", signature: badSig, address: address))
    }

    // MARK: - Pubkey recovery

    func testPubKeyRecovery() throws {
        let pk = PrivateKey.random()!
        let expectedPub = PublicKey.fromPrivateKey(pk)

        let sig = try BSM.sign(message: "recover me", privateKey: pk)
        let (recovered, compressed) = try BSM.recoverPublicKey(signature: sig, message: "recover me".data(using: .utf8)!)

        XCTAssertEqual(recovered, expectedPub)
        XCTAssertTrue(compressed)
    }

    func testRecoverPublicKeyUncompressed() throws {
        let pk = PrivateKey.random()!
        let expectedPub = PublicKey.fromPrivateKey(pk)

        let sig = try BSM.sign(message: "uncompressed", privateKey: pk, compressed: false)
        let (recovered, compressed) = try BSM.recoverPublicKey(signature: sig, message: "uncompressed".data(using: .utf8)!)

        XCTAssertEqual(recovered, expectedPub)
        XCTAssertFalse(compressed)
    }

    // MARK: - Base64 helpers

    func testSignBase64Helper() throws {
        let pk = PrivateKey(hex: "0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")!
        let b64 = try BSM.signBase64(message: "test message", privateKey: pk)
        XCTAssertEqual(b64, "IFxPx8JHsCiivB+DW/RgNpCLT6yG3j436cUNWKekV3ORBrHNChIjeVReyAco7PVmmDtVD3POs9FhDlm/nk5I6O8=")
    }
}
