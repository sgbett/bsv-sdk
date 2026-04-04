import XCTest
import Foundation
@testable import BSV

final class DigestTests: XCTestCase {

    // MARK: - SHA-256

    func testSha256EmptyInput() {
        let hash = Digest.sha256(Data())
        XCTAssertEqual(hash.hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testSha256Hello() {
        let hash = Digest.sha256(Data("hello".utf8))
        XCTAssertEqual(hash.hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }

    // MARK: - SHA-256d

    func testSha256dEmpty() {
        let hash = Digest.sha256d(Data())
        XCTAssertEqual(hash.hex, "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
    }

    func testSha256dHello() {
        let hash = Digest.sha256d(Data("hello".utf8))
        let first = Digest.sha256(Data("hello".utf8))
        let expected = Digest.sha256(first)
        XCTAssertEqual(hash, expected)
    }

    // MARK: - SHA-512

    func testSha512EmptyInput() {
        let hash = Digest.sha512(Data())
        XCTAssertEqual(hash.hex, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    }

    // MARK: - SHA-1

    func testSha1EmptyInput() {
        let hash = Digest.sha1(Data())
        XCTAssertEqual(hash.hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    }

    func testSha1Hello() {
        let hash = Digest.sha1(Data("hello".utf8))
        XCTAssertEqual(hash.hex, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    }

    // MARK: - RIPEMD-160

    func testRipemd160EmptyInput() {
        let hash = Digest.ripemd160(Data())
        XCTAssertEqual(hash.hex, "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    }

    func testRipemd160Hello() {
        let hash = Digest.ripemd160(Data("hello".utf8))
        XCTAssertEqual(hash.hex, "108f07b8382412612c048d07d13f814118445acd")
    }

    func testRipemd160ABC() {
        let hash = Digest.ripemd160(Data("abc".utf8))
        XCTAssertEqual(hash.hex, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    }

    // MARK: - Hash160

    func testHash160() {
        let data = Data("hello".utf8)
        let expected = Digest.ripemd160(Digest.sha256(data))
        XCTAssertEqual(Digest.hash160(data), expected)
    }

    func testHash160KnownPublicKey() {
        // Satoshi's public key (compressed) from the genesis coinbase
        let pubKeyHex = "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
        let pubKey = Data(hex: pubKeyHex)!
        let hash = Digest.hash160(pubKey)
        XCTAssertEqual(hash.hex, "010966776006953d5567439e5e39f86a0d273bee")
    }

    // MARK: - HMAC-SHA256

    func testHmacSha256() {
        let key = Data("key".utf8)
        let data = Data("The quick brown fox jumps over the lazy dog".utf8)
        let mac = Digest.hmacSha256(data: data, key: key)
        XCTAssertEqual(mac.hex, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
    }

    // MARK: - HMAC-SHA512

    func testHmacSha512() {
        let key = Data("key".utf8)
        let data = Data("The quick brown fox jumps over the lazy dog".utf8)
        let mac = Digest.hmacSha512(data: data, key: key)
        XCTAssertEqual(mac.hex, "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a")
    }

    // MARK: - PBKDF2

    func testPbkdf2HmacSha512() {
        let password = Data("password".utf8)
        let salt = Data("salt".utf8)
        let derived = Digest.pbkdf2HmacSha512(
            password: password, salt: salt, iterations: 1, keyLength: 64
        )
        XCTAssertNotNil(derived)
        XCTAssertEqual(derived?.count, 64)
        XCTAssertEqual(derived?.hex, "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce")
    }
}
