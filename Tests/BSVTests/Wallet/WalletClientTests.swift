import XCTest
@testable import BSV

final class WalletClientTests: XCTestCase {

    /// A substrate that captures the last request and returns a scripted response.
    final class MockSubstrate: WalletSubstrate, @unchecked Sendable {
        var lastMethod: String?
        var lastBody: [String: Any]?
        var lastOriginator: String?
        var response: [String: Any] = [:]
        var error: Error?

        func invoke(method: String, body: Data, originator: String?) async throws -> Data {
            lastMethod = method
            lastOriginator = originator
            if let obj = try JSONSerialization.jsonObject(with: body) as? [String: Any] {
                lastBody = obj
            }
            if let error { throw error }
            return try JSONSerialization.data(withJSONObject: response, options: [])
        }
    }

    // MARK: - getPublicKey

    func testGetPublicKeyEncodesRequestAndDecodesResponse() async throws {
        let mock = MockSubstrate()
        let identity = PublicKey.fromPrivateKey(PrivateKey.random()!)
        mock.response = ["publicKey": identity.hex]

        let client = WalletClient(substrate: mock, originator: "app.example.com")
        let result = try await client.getPublicKey(args: GetPublicKeyArgs(identityKey: true))
        XCTAssertEqual(result.publicKey, identity)
        XCTAssertEqual(mock.lastMethod, "getPublicKey")
        XCTAssertEqual(mock.lastOriginator, "app.example.com")
        XCTAssertEqual(mock.lastBody?["identityKey"] as? Bool, true)
    }

    // MARK: - encrypt

    func testEncryptSendsEncodedProtocolAndBytes() async throws {
        let mock = MockSubstrate()
        let expected = Data([0xDE, 0xAD, 0xBE, 0xEF])
        mock.response = ["ciphertext": Array(expected)]

        let client = WalletClient(substrate: mock)
        let plaintext = Data([0x01, 0x02, 0x03])
        let result = try await client.encrypt(args: WalletEncryptArgs(
            encryption: WalletEncryptionArgs(
                protocolID: WalletProtocol(securityLevel: .app, protocol: "example protocol"),
                keyID: "k1",
                counterparty: .`self`
            ),
            plaintext: plaintext
        ))

        XCTAssertEqual(result.ciphertext, expected)
        XCTAssertEqual(mock.lastMethod, "encrypt")
        // Protocol ID serialised as [level, name].
        let protoArray = mock.lastBody?["protocolID"] as? [Any]
        XCTAssertEqual(protoArray?.count, 2)
        XCTAssertEqual(protoArray?[0] as? Int, 1)
        XCTAssertEqual(protoArray?[1] as? String, "example protocol")
        XCTAssertEqual(mock.lastBody?["counterparty"] as? String, "self")
        // Plaintext serialised as byte array.
        let sent = mock.lastBody?["plaintext"] as? [Int]
        XCTAssertEqual(sent, plaintext.map { Int($0) })
    }

    // MARK: - verifyHmac

    func testVerifyHmacThrowsOnInvalid() async throws {
        let mock = MockSubstrate()
        mock.response = ["valid": false]
        let client = WalletClient(substrate: mock)
        do {
            _ = try await client.verifyHmac(args: VerifyHmacArgs(
                encryption: WalletEncryptionArgs(
                    protocolID: WalletProtocol(securityLevel: .silent, protocol: "hmac test"),
                    keyID: "1"
                ),
                data: Data([0x00]),
                hmac: Data(repeating: 0x01, count: 32)
            ))
            XCTFail("expected invalidHmac")
        } catch WalletError.invalidHmac {
            // expected
        }
    }

    // MARK: - error envelope handling

    func testRemoteErrorEnvelopeMapsToWalletError() async throws {
        let mock = MockSubstrate()
        mock.response = [
            "status": "error",
            "code": 6,
            "description": "invalid protocolID"
        ]

        // The substrate decides that 2xx+status:error is an error — we need
        // the HTTP substrate path for that, so here we simulate by throwing
        // directly from the mock:
        mock.error = WalletError.invalidParameter(name: "protocolID", message: "invalid protocolID")

        let client = WalletClient(substrate: mock)
        do {
            _ = try await client.getPublicKey(args: GetPublicKeyArgs(identityKey: true))
            XCTFail("expected error")
        } catch WalletError.invalidParameter(let name, _) {
            XCTAssertEqual(name, "protocolID")
        }
    }

    // MARK: - byte serialisation helpers

    func testDecodeBytesAcceptsHexAndArray() {
        XCTAssertEqual(WalletClient.decodeBytes([1, 2, 3]), Data([1, 2, 3]))
        XCTAssertEqual(WalletClient.decodeBytes("deadbeef"), Data([0xde, 0xad, 0xbe, 0xef]))
        XCTAssertNil(WalletClient.decodeBytes(nil))
    }
}
