import XCTest
@testable import BSV

final class PrivateKeyTests: XCTestCase {

    // MARK: - Basic creation

    func testFromBytes() {
        var bytes = Data(count: 32)
        bytes[31] = 1
        let key = PrivateKey(data: bytes)
        XCTAssertNotNil(key)
        XCTAssertEqual(key!.toBytes(), bytes)
    }

    func testFromHex() {
        let key = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")
        XCTAssertNotNil(key)
    }

    func testRejectsZero() {
        XCTAssertNil(PrivateKey(data: Data(count: 32)))
    }

    func testRejectsN() {
        XCTAssertNil(PrivateKey(data: Secp256k1.N))
    }

    func testRejectsWrongLength() {
        XCTAssertNil(PrivateKey(data: Data(count: 31)))
        XCTAssertNil(PrivateKey(data: Data(count: 33)))
    }

    // MARK: - WIF round-trip

    func testWIFRoundTrip() {
        let key = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let wif = key.toWIF()
        let restored = PrivateKey(wif: wif)
        XCTAssertNotNil(restored)
        XCTAssertEqual(restored!.data, key.data)
    }

    func testKnownWIF() {
        // Private key = 1, compressed WIF (well-known).
        let expectedWIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        let key = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        XCTAssertEqual(key.toWIF(), expectedWIF)
    }

    func testDecodeKnownWIF() {
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        let key = PrivateKey(wif: wif)
        XCTAssertNotNil(key)
        XCTAssertEqual(key!.hex, "0000000000000000000000000000000000000000000000000000000000000001")
    }

    func testKnownWIF2() {
        // Another known test vector.
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        let key = PrivateKey(wif: wif)
        XCTAssertNotNil(key)
        // This is an uncompressed WIF (33 bytes: version + key, no compression flag).
        XCTAssertEqual(key!.hex, "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
    }

    // MARK: - Public key derivation

    func testPublicKeyFromPrivKey1() {
        let key = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = key.publicKey()
        // privKey = 1 => pubKey = G
        XCTAssertEqual(pub, Secp256k1.G)
    }

    func testPublicKeyFromPrivKey2() {
        let key = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000002")!
        let pub = key.publicKey()
        let expected = Secp256k1.G.doubled()
        XCTAssertEqual(pub, expected)
    }

    // MARK: - Signing

    func testSign() {
        let key = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let hash = Digest.sha256("test".data(using: .utf8)!)
        let sig = key.sign(hash: hash)
        XCTAssertNotNil(sig)
        XCTAssertTrue(sig!.isLowS)
    }

    // MARK: - Random generation

    func testRandomGeneration() {
        let key = PrivateKey.random()
        XCTAssertNotNil(key)
        XCTAssertEqual(key!.data.count, 32)
        XCTAssertFalse(scalarIsZero(key!.data))
    }

    // MARK: - Hex

    func testHexRoundTrip() {
        let hexStr = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        let key = PrivateKey(hex: hexStr)!
        XCTAssertEqual(key.hex, hexStr)
    }

    // MARK: - Invalid WIF

    func testRejectsInvalidWIF() {
        XCTAssertNil(PrivateKey(wif: "notavalidwif"))
        XCTAssertNil(PrivateKey(wif: ""))
    }
}
