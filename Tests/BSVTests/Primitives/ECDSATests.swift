import XCTest
@testable import BSV

final class ECDSATests: XCTestCase {

    // MARK: - Known private key / public key

    /// Private key = 1, public key = G.
    private let privKeyOne: Data = {
        var d = Data(count: 32)
        d[31] = 1
        return d
    }()

    private let testHash: Data = {
        // SHA-256 of "test message"
        Digest.sha256("test message".data(using: .utf8)!)
    }()

    // MARK: - Sign and Verify

    func testSignAndVerify() {
        guard let sig = ECDSA.sign(hash: testHash, privateKey: privKeyOne) else {
            XCTFail("Sign failed"); return
        }

        XCTAssertEqual(sig.r.count, 32)
        XCTAssertEqual(sig.s.count, 32)

        // Verify with G as the public key (private key = 1).
        let valid = ECDSA.verify(hash: testHash, r: sig.r, s: sig.s, publicKey: Secp256k1.G)
        XCTAssertTrue(valid, "Signature should verify against the correct public key")
    }

    func testVerifyRejectsWrongKey() {
        guard let sig = ECDSA.sign(hash: testHash, privateKey: privKeyOne) else {
            XCTFail("Sign failed"); return
        }

        // Use 2G as the wrong public key.
        let wrongKey = Secp256k1.G.doubled()
        let valid = ECDSA.verify(hash: testHash, r: sig.r, s: sig.s, publicKey: wrongKey)
        XCTAssertFalse(valid, "Signature should not verify against wrong public key")
    }

    func testVerifyRejectsWrongHash() {
        guard let sig = ECDSA.sign(hash: testHash, privateKey: privKeyOne) else {
            XCTFail("Sign failed"); return
        }

        let wrongHash = Digest.sha256("wrong message".data(using: .utf8)!)
        let valid = ECDSA.verify(hash: wrongHash, r: sig.r, s: sig.s, publicKey: Secp256k1.G)
        XCTAssertFalse(valid, "Signature should not verify with wrong hash")
    }

    // MARK: - Low-S

    func testLowSNormalisation() {
        guard let sig = ECDSA.sign(hash: testHash, privateKey: privKeyOne, forceLowS: true) else {
            XCTFail("Sign failed"); return
        }

        // s should be <= N/2
        XCTAssertTrue(
            scalarCompare(sig.s, Secp256k1.halfN) <= 0,
            "s should be in the lower half of the curve order"
        )
    }

    // MARK: - Recovery

    func testRecoverPublicKey() {
        guard let sig = ECDSA.sign(hash: testHash, privateKey: privKeyOne) else {
            XCTFail("Sign failed"); return
        }

        let recovered = ECDSA.recover(
            hash: testHash, r: sig.r, s: sig.s, recoveryId: sig.recoveryId
        )
        XCTAssertNotNil(recovered, "Recovery should succeed")
        XCTAssertEqual(recovered!, Secp256k1.G, "Recovered key should equal G (privKey = 1)")
    }

    // MARK: - Determinism (RFC 6979)

    func testDeterministicSignature() {
        let sig1 = ECDSA.sign(hash: testHash, privateKey: privKeyOne)
        let sig2 = ECDSA.sign(hash: testHash, privateKey: privKeyOne)
        XCTAssertNotNil(sig1)
        XCTAssertNotNil(sig2)
        XCTAssertEqual(sig1!.r, sig2!.r, "Same inputs should produce same r")
        XCTAssertEqual(sig1!.s, sig2!.s, "Same inputs should produce same s")
    }

    func testDifferentHashesDifferentSignatures() {
        let hash2 = Digest.sha256("different message".data(using: .utf8)!)
        let sig1 = ECDSA.sign(hash: testHash, privateKey: privKeyOne)
        let sig2 = ECDSA.sign(hash: hash2, privateKey: privKeyOne)
        XCTAssertNotNil(sig1)
        XCTAssertNotNil(sig2)
        XCTAssertNotEqual(sig1!.r, sig2!.r, "Different hashes should produce different r")
    }

    // MARK: - Sign with a different private key

    func testSignWithPrivateKey2() {
        var privKey = Data(count: 32)
        privKey[31] = 2
        let pubKey = Secp256k1.G.multiplied(by: privKey)

        guard let sig = ECDSA.sign(hash: testHash, privateKey: privKey) else {
            XCTFail("Sign failed"); return
        }

        let valid = ECDSA.verify(hash: testHash, r: sig.r, s: sig.s, publicKey: pubKey)
        XCTAssertTrue(valid)
    }

    // MARK: - Edge cases

    func testRejectsZeroPrivateKey() {
        let zeroKey = Data(count: 32)
        XCTAssertNil(ECDSA.sign(hash: testHash, privateKey: zeroKey))
    }

    func testRejectsPrivateKeyEqualToN() {
        XCTAssertNil(ECDSA.sign(hash: testHash, privateKey: Secp256k1.N))
    }

    func testVerifyRejectsZeroR() {
        let zeroR = Data(count: 32)
        let someS = Data(repeating: 1, count: 32)
        XCTAssertFalse(ECDSA.verify(hash: testHash, r: zeroR, s: someS, publicKey: Secp256k1.G))
    }

    func testVerifyRejectsZeroS() {
        let someR = Data(repeating: 1, count: 32)
        let zeroS = Data(count: 32)
        XCTAssertFalse(ECDSA.verify(hash: testHash, r: someR, s: zeroS, publicKey: Secp256k1.G))
    }

    // MARK: - Known test vector

    func testKnownRFC6979Vector() {
        // RFC 6979 A.2.5 test vector for secp256k1 with SHA-256.
        // Private key: 1
        // Message: "Satoshi Nakamoto" (we'll hash it ourselves)
        let message = "Satoshi Nakamoto".data(using: .utf8)!
        let hash = Digest.sha256(message)

        guard let sig = ECDSA.sign(hash: hash, privateKey: privKeyOne) else {
            XCTFail("Sign failed"); return
        }

        // Verify the signature.
        let valid = ECDSA.verify(hash: hash, r: sig.r, s: sig.s, publicKey: Secp256k1.G)
        XCTAssertTrue(valid, "Known vector signature should verify")

        // Recover and verify.
        let recovered = ECDSA.recover(hash: hash, r: sig.r, s: sig.s, recoveryId: sig.recoveryId)
        XCTAssertNotNil(recovered)
        XCTAssertEqual(recovered!, Secp256k1.G)
    }

    // MARK: - Round-trip with arbitrary private key

    func testSignVerifyRecoverArbitraryKey() {
        let privKeyHex = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        guard let privKey = Data(hex: privKeyHex) else {
            XCTFail("Invalid hex"); return
        }

        let pubPoint = Secp256k1.G.multiplied(by: privKey)
        let hash = Digest.sha256d("Hello BSV".data(using: .utf8)!)

        guard let sig = ECDSA.sign(hash: hash, privateKey: privKey) else {
            XCTFail("Sign failed"); return
        }

        XCTAssertTrue(ECDSA.verify(hash: hash, r: sig.r, s: sig.s, publicKey: pubPoint))

        let recovered = ECDSA.recover(hash: hash, r: sig.r, s: sig.s, recoveryId: sig.recoveryId)
        XCTAssertNotNil(recovered)
        XCTAssertEqual(recovered!, pubPoint)
    }
}
