import XCTest
@testable import BSV

final class AuthNonceTests: XCTestCase {

    func testCreateVerifyRoundTrip() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let nonce = try await AuthNonce.create(wallet: wallet)
        XCTAssertFalse(nonce.isEmpty)

        let valid = try await AuthNonce.verify(nonce, wallet: wallet)
        XCTAssertTrue(valid)
    }

    func testVerifyRejectsNonceFromAnotherWallet() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let attacker = ProtoWallet(rootKey: PrivateKey.random()!)

        let nonce = try await AuthNonce.create(wallet: wallet)
        let valid = try await AuthNonce.verify(nonce, wallet: attacker)
        XCTAssertFalse(valid)
    }

    func testVerifyRejectsMalformedInput() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let invalid = try await AuthNonce.verify("not-base64!!", wallet: wallet)
        XCTAssertFalse(invalid)
    }

    func testVerifyRejectsTamperedNonce() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let nonce = try await AuthNonce.create(wallet: wallet)

        // Flip a byte in the decoded nonce and re-encode.
        var raw = Data(base64Encoded: nonce)!
        raw[0] ^= 0xFF
        let tampered = raw.base64EncodedString()

        let valid = try await AuthNonce.verify(tampered, wallet: wallet)
        XCTAssertFalse(valid)
    }
}
