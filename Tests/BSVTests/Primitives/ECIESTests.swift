import XCTest
@testable import BSV

final class ECIESTests: XCTestCase {

    // Shared test vector from go-sdk.
    static let wif = "L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu"
    static let message = "hello world"

    // MARK: - Known vector (encrypt with self as sender)

    func testElectrumEncryptKnownVector() throws {
        let pk = PrivateKey(wif: ECIESTests.wif)!
        let pub = PublicKey.fromPrivateKey(pk)

        let encrypted = try ECIES.encrypt(
            message: ECIESTests.message.data(using: .utf8)!,
            toPublicKey: pub,
            fromPrivateKey: pk
        )

        // Go-sdk test vector (same WIF + "hello world" + self as sender).
        let expected = Data(
            base64Encoded: "QklFMQO7zpX/GS4XpthCy6/hT38ZKsBGbn8JKMGHOY5ifmaoT890Krt9cIRk/ULXaB5uC08owRICzenFbm31pZGu0gCM2uOxpofwHacKidwZ0Q7aEw=="
        )!

        XCTAssertEqual(encrypted, expected)
    }

    // MARK: - Round-trip

    func testRoundTripWithEphemeralKey() throws {
        let pk = PrivateKey(wif: ECIESTests.wif)!
        let pub = PublicKey.fromPrivateKey(pk)

        let plaintext = "the quick brown fox jumps over the lazy dog".data(using: .utf8)!
        let encrypted = try ECIES.encrypt(message: plaintext, toPublicKey: pub)
        let decrypted = try ECIES.decrypt(encryptedData: encrypted, toPrivateKey: pk)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testRoundTripWithCounterparty() throws {
        let alice = PrivateKey.random()!
        let bob = PrivateKey.random()!
        let bobPub = PublicKey.fromPrivateKey(bob)
        let alicePub = PublicKey.fromPrivateKey(alice)

        let plaintext = "secret message".data(using: .utf8)!

        // Alice encrypts for Bob using her private key.
        let encrypted = try ECIES.encrypt(
            message: plaintext,
            toPublicKey: bobPub,
            fromPrivateKey: alice
        )

        // Bob decrypts without knowing Alice's pubkey (derived from payload).
        let decryptedNoPeer = try ECIES.decrypt(encryptedData: encrypted, toPrivateKey: bob)
        XCTAssertEqual(decryptedNoPeer, plaintext)

        // Bob decrypts with explicit peer pubkey.
        let decryptedWithPeer = try ECIES.decrypt(
            encryptedData: encrypted,
            toPrivateKey: bob,
            fromPublicKey: alicePub
        )
        XCTAssertEqual(decryptedWithPeer, plaintext)
    }

    func testRoundTripEmptyMessage() throws {
        let pk = PrivateKey.random()!
        let pub = PublicKey.fromPrivateKey(pk)

        let encrypted = try ECIES.encrypt(message: Data(), toPublicKey: pub)
        let decrypted = try ECIES.decrypt(encryptedData: encrypted, toPrivateKey: pk)

        XCTAssertEqual(decrypted, Data())
    }

    func testRoundTripBinaryMessage() throws {
        let pk = PrivateKey.random()!
        let pub = PublicKey.fromPrivateKey(pk)

        var binary = Data(count: 1024)
        for i in 0..<binary.count { binary[i] = UInt8(i % 256) }

        let encrypted = try ECIES.encrypt(message: binary, toPublicKey: pub)
        let decrypted = try ECIES.decrypt(encryptedData: encrypted, toPrivateKey: pk)

        XCTAssertEqual(decrypted, binary)
    }

    // MARK: - Error cases

    func testDecryptRejectsInvalidMagic() {
        let pk = PrivateKey.random()!
        // 85 bytes of zeros — too small to match, but also wrong magic.
        var bad = Data(count: 85)
        bad.withUnsafeMutableBytes { _ in }

        XCTAssertThrowsError(try ECIES.decrypt(encryptedData: bad, toPrivateKey: pk))
    }

    func testDecryptRejectsTooShort() {
        let pk = PrivateKey.random()!
        let bad = Data([0x42, 0x49, 0x45, 0x31]) // "BIE1" only
        XCTAssertThrowsError(try ECIES.decrypt(encryptedData: bad, toPrivateKey: pk)) { error in
            XCTAssertEqual(error as? ECIES.Error, .invalidCiphertext)
        }
    }

    func testDecryptRejectsTamperedMac() throws {
        let pk = PrivateKey.random()!
        let pub = PublicKey.fromPrivateKey(pk)

        var encrypted = try ECIES.encrypt(
            message: "tamper".data(using: .utf8)!,
            toPublicKey: pub
        )

        // Flip the last byte (in the MAC).
        encrypted[encrypted.count - 1] ^= 0xFF

        XCTAssertThrowsError(try ECIES.decrypt(encryptedData: encrypted, toPrivateKey: pk)) { error in
            XCTAssertEqual(error as? ECIES.Error, .hmacMismatch)
        }
    }

    func testDecryptWithWrongKeyFails() throws {
        let alice = PrivateKey.random()!
        let bob = PrivateKey.random()!
        let alicePub = PublicKey.fromPrivateKey(alice)

        let encrypted = try ECIES.encrypt(
            message: "for alice".data(using: .utf8)!,
            toPublicKey: alicePub
        )

        // Bob tries to decrypt a message meant for Alice.
        XCTAssertThrowsError(try ECIES.decrypt(encryptedData: encrypted, toPrivateKey: bob))
    }
}
