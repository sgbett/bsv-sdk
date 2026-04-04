import XCTest
@testable import BSV

final class PublicKeyTests: XCTestCase {

    // MARK: - From private key

    func testFromPrivateKey() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        // privKey = 1 => pubKey = G
        XCTAssertEqual(pub.point, Secp256k1.G)
    }

    func testFromPrivateKey2() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000002")!
        let pub = PublicKey.fromPrivateKey(priv)
        let expected = Secp256k1.G.doubled()
        XCTAssertEqual(pub.point, expected)
    }

    // MARK: - Compressed encoding

    func testCompressedEncoding() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        let compressed = pub.toCompressed()
        XCTAssertEqual(compressed.count, 33)
        // G has even y, so prefix is 0x02.
        XCTAssertEqual(compressed[0], 0x02)
    }

    func testKnownCompressedHex() {
        // Private key = 1 => public key = G (well-known compressed hex).
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        let expected = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        XCTAssertEqual(pub.hex, expected)
    }

    // MARK: - Uncompressed encoding

    func testUncompressedEncoding() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        let uncompressed = pub.toUncompressed()
        XCTAssertEqual(uncompressed.count, 65)
        XCTAssertEqual(uncompressed[0], 0x04)
    }

    func testKnownUncompressedHex() {
        // G point uncompressed.
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        let uncompressed = pub.toUncompressed()
        // x coordinate of G.
        let xHex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        // y coordinate of G.
        let yHex = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        let expectedHex = "04" + xHex + yHex
        XCTAssertEqual(uncompressed.hex, expectedHex)
    }

    // MARK: - From bytes round-trip

    func testCompressedRoundTrip() {
        let priv = PrivateKey(hex: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")!
        let pub = PublicKey.fromPrivateKey(priv)
        let compressed = pub.toCompressed()
        let restored = PublicKey(data: compressed)
        XCTAssertNotNil(restored)
        XCTAssertEqual(restored!, pub)
    }

    func testUncompressedRoundTrip() {
        let priv = PrivateKey(hex: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")!
        let pub = PublicKey.fromPrivateKey(priv)
        let uncompressed = pub.toUncompressed()
        let restored = PublicKey(data: uncompressed)
        XCTAssertNotNil(restored)
        XCTAssertEqual(restored!, pub)
    }

    // MARK: - From hex

    func testFromHexCompressed() {
        let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        let pub = PublicKey(hex: hex)
        XCTAssertNotNil(pub)
        XCTAssertEqual(pub!.hex, hex)
    }

    func testFromHexUncompressed() {
        let hex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        let pub = PublicKey(hex: hex)
        XCTAssertNotNil(pub)
        // Should equal G.
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        XCTAssertEqual(pub!, PublicKey.fromPrivateKey(priv))
    }

    // MARK: - Invalid inputs

    func testRejectsInvalidHex() {
        XCTAssertNil(PublicKey(hex: "notahexstring"))
        XCTAssertNil(PublicKey(hex: ""))
    }

    func testRejectsWrongLength() {
        XCTAssertNil(PublicKey(data: Data(count: 32)))
        XCTAssertNil(PublicKey(data: Data(count: 34)))
    }

    func testRejectsInvalidPoint() {
        // Valid prefix but all zeros for x — not a valid point.
        var data = Data([0x02])
        data.append(Data(count: 32))
        XCTAssertNil(PublicKey(data: data))
    }

    // MARK: - Hash160

    func testHash160() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        let h = pub.hash160()
        XCTAssertEqual(h.count, 20)
        // Known hash160 of compressed G point.
        let expected = "751e76e8199196d454941c45d1b3a323f1433bd6"
        XCTAssertEqual(h.hex, expected)
    }

    // MARK: - Address

    func testToAddress() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        // Known mainnet P2PKH address for compressed pubkey of private key 1.
        let expected = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        XCTAssertEqual(pub.toAddress(), expected)
    }

    func testToAddress2() {
        // Another known vector: private key from WIF.
        let priv = PrivateKey(wif: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")!
        let pub = PublicKey.fromPrivateKey(priv)
        XCTAssertEqual(pub.toAddress(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    }

    // MARK: - Verify

    func testVerifyValidSignature() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        let hash = Digest.sha256("test".data(using: .utf8)!)
        let sig = priv.sign(hash: hash)!
        XCTAssertTrue(pub.verify(hash: hash, signature: sig))
    }

    func testVerifyRejectsWrongKey() {
        let priv1 = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let priv2 = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000002")!
        let pub2 = PublicKey.fromPrivateKey(priv2)
        let hash = Digest.sha256("test".data(using: .utf8)!)
        let sig = priv1.sign(hash: hash)!
        XCTAssertFalse(pub2.verify(hash: hash, signature: sig))
    }

    func testVerifyRejectsWrongHash() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        let hash1 = Digest.sha256("test".data(using: .utf8)!)
        let hash2 = Digest.sha256("other".data(using: .utf8)!)
        let sig = priv.sign(hash: hash1)!
        XCTAssertFalse(pub.verify(hash: hash2, signature: sig))
    }

    // MARK: - DER encoding

    func testDERMatchesCompressed() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        XCTAssertEqual(pub.toDER(), pub.toCompressed())
        XCTAssertEqual(pub.derHex, pub.hex)
    }

    // MARK: - Equality

    func testEqualityFromDifferentPrivateKeys() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub1 = PublicKey.fromPrivateKey(priv)
        let pub2 = PublicKey(hex: pub1.hex)!
        XCTAssertEqual(pub1, pub2)
    }

    func testInequalityDifferentKeys() {
        let priv1 = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let priv2 = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000002")!
        let pub1 = PublicKey.fromPrivateKey(priv1)
        let pub2 = PublicKey.fromPrivateKey(priv2)
        XCTAssertNotEqual(pub1, pub2)
    }
}
