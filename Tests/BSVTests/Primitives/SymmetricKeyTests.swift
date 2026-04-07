import XCTest
@testable import BSV

final class SymmetricKeyTests: XCTestCase {

    // MARK: - Round trip

    func testRoundTripUTF8() throws {
        let key = SymmetricKey.random()
        let plaintext = "hello, world".data(using: .utf8)!
        let ciphertext = try key.encrypt(plaintext)
        let decrypted = try key.decrypt(ciphertext)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testRoundTripEmpty() throws {
        let key = SymmetricKey.random()
        let ciphertext = try key.encrypt(Data())
        let decrypted = try key.decrypt(ciphertext)
        XCTAssertEqual(decrypted, Data())
    }

    func testRoundTripLargePayload() throws {
        let key = SymmetricKey.random()
        var plaintext = Data(count: 4096)
        for i in 0..<plaintext.count { plaintext[i] = UInt8(i % 256) }
        let ciphertext = try key.encrypt(plaintext)
        let decrypted = try key.decrypt(ciphertext)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Format

    func testCiphertextLength() throws {
        let key = SymmetricKey.random()
        let plaintext = "12345".data(using: .utf8)!
        let ciphertext = try key.encrypt(plaintext)
        // 32 (iv) + 5 (ciphertext same length as plaintext for GCM) + 16 (tag)
        XCTAssertEqual(ciphertext.count, 32 + plaintext.count + 16)
    }

    // MARK: - Tampering

    func testDecryptTamperedCiphertextFails() throws {
        let key = SymmetricKey.random()
        var ct = try key.encrypt("hello".data(using: .utf8)!)
        // Flip a byte in the middle (in the actual ciphertext, not iv).
        ct[35] ^= 0xFF
        XCTAssertThrowsError(try key.decrypt(ct))
    }

    func testDecryptTamperedTagFails() throws {
        let key = SymmetricKey.random()
        var ct = try key.encrypt("hello".data(using: .utf8)!)
        // Flip the last byte (auth tag).
        ct[ct.count - 1] ^= 0xFF
        XCTAssertThrowsError(try key.decrypt(ct))
    }

    func testDecryptShortFails() {
        let key = SymmetricKey.random()
        let ct = Data(repeating: 0, count: 10)
        XCTAssertThrowsError(try key.decrypt(ct)) { error in
            XCTAssertEqual(error as? SymmetricKey.Error, .ciphertextTooShort)
        }
    }

    func testDecryptWithWrongKeyFails() throws {
        let alice = SymmetricKey.random()
        let bob = SymmetricKey.random()
        let ct = try alice.encrypt("secret".data(using: .utf8)!)
        XCTAssertThrowsError(try bob.decrypt(ct))
    }

    // MARK: - Key validation

    func testInitRejectsBadLength() {
        XCTAssertNil(SymmetricKey(key: Data(count: 16)))
        XCTAssertNil(SymmetricKey(key: Data(count: 64)))
    }

    func testInitAccepts32Bytes() {
        XCTAssertNotNil(SymmetricKey(key: Data(count: 32)))
    }

    // MARK: - Cross-SDK vectors (from go-sdk SymmetricKey.vectors.json)

    /// Decrypt a ciphertext produced by another SDK (TS/Go) and verify the
    /// plaintext matches. The vector format is:
    ///   key:        base64-encoded 32-byte symmetric key
    ///   ciphertext: base64-encoded encrypted blob (iv || ct || tag)
    ///   plaintext:  base64-encoded UTF-8 string OR raw UTF-8 string
    func testCrossSDKVector1() throws {
        let key = SymmetricKey(key: Data(base64Encoded: "LIe9CoVXxDDDKt9F4j2lE+GP4oPcMElwyX+LVsuRLqw=")!)!
        let ct = Data(base64Encoded: "1cf74FpvW0koFZk5e1VQcCtF7UdLj9mtN/L9loFlXwhf6w/06THwVirsvDShuT/KlOjO/HFALj8AcGLU1KRs4zNJDaX2wNebuPkH+qp5N/0cp3fZxgFzHJB3jBPDcdFi8O9WXIBLx9jUQ5KFQk0mZCB2k90VniInWuzqqOQAQQlBy2rgBWp4xg==")!
        // The go-sdk vector treats the plaintext field as a literal UTF-8 string
        // (not base64), so the plaintext here is the base64-looking string itself.
        let expectedPlain = "5+w9tts+i14GDfPSEJwcaAfce7zVLC7wsRAMnCBqIczkqL08I05FZTl7n14H9hnPkS7HBm3EGWNDKCZ64ckCGg==".data(using: .utf8)!

        let decrypted = try key.decrypt(ct)
        XCTAssertEqual(decrypted, expectedPlain)
    }

    func testCrossSDKVector2_PlainText() throws {
        let key = SymmetricKey(key: Data(base64Encoded: "qIgnjD0FfGVMiWo107bP0oHsLA402lhC7AYUFIKY1KQ=")!)!
        let ct = Data(base64Encoded: "ktpzKolKsvtWrvLl0yMdGvh5ngd1hiaNcC1b5yuzo2DEKO/4S7gePO/CWOmW/dloHhzfbBQH9rKDFKK7xHHgqYRc")!
        let expectedPlain = "A cat and a mouse.".data(using: .utf8)!

        let decrypted = try key.decrypt(ct)
        XCTAssertEqual(decrypted, expectedPlain)
    }

    func testCrossSDKVector3_Unicode() throws {
        let key = SymmetricKey(key: Data(base64Encoded: "K7E/bf3wp6hrVeW0V1KvFJS5JZMhyxwPHCIW6wKBTb0=")!)!
        let ct = Data(base64Encoded: "vremTalPp+NxN/loEtLMB94tEymdFk2TfBoTWNYcf4sQqYSNkx2WPdJ4LxrIsGuIg9KMOt7FOcIpDb6rRVpP")!
        let expectedPlain = "üñîçø∂é".data(using: .utf8)!

        let decrypted = try key.decrypt(ct)
        XCTAssertEqual(decrypted, expectedPlain)
    }
}
