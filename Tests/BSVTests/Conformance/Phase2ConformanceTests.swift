import XCTest
@testable import BSV

/// End-to-end conformance tests for Phase 2 (Keys & Signatures).
///
/// These verify that the full pipeline — private key creation, public key
/// derivation, address generation, signing, verification, and serialisation
/// — produces results matching known Bitcoin test vectors.
final class Phase2ConformanceTests: XCTestCase {

    // MARK: - Private Key -> WIF -> Address pipeline

    /// Test vector: private key 1 (the simplest non-trivial key).
    func testPipelinePrivKey1() {
        let privHex = "0000000000000000000000000000000000000000000000000000000000000001"
        let expectedWIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        let expectedPubHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        let expectedAddress = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

        let priv = PrivateKey(hex: privHex)!
        XCTAssertEqual(priv.toWIF(), expectedWIF)

        let pub = PublicKey.fromPrivateKey(priv)
        XCTAssertEqual(pub.hex, expectedPubHex)
        XCTAssertEqual(pub.toAddress(), expectedAddress)

        // Round-trip: WIF -> PrivateKey -> same public key
        let restored = PrivateKey(wif: expectedWIF)!
        let restoredPub = PublicKey.fromPrivateKey(restored)
        XCTAssertEqual(restoredPub, pub)
    }

    /// Go-sdk WIF test vector.
    func testPipelineGoSDKVector() {
        let privHex = "2b2afb5ea8d8c623acd6744547628988d86787003bb970afe15d471b727db79c"
        let expectedWIF = "Kxfd8ABTYZHBH3y1jToJ2AUJTMVbsNaqQsrkpo9gnnc1JXfBH8mn"

        let priv = PrivateKey(hex: privHex)!
        XCTAssertEqual(priv.toWIF(), expectedWIF)

        // Round-trip
        let restored = PrivateKey(wif: expectedWIF)!
        XCTAssertEqual(restored.hex, privHex)
    }

    /// Uncompressed WIF test vector (5H prefix).
    func testUncompressedWIFVector() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        let expectedHex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
        let priv = PrivateKey(wif: wif)!
        XCTAssertEqual(priv.hex, expectedHex)
    }

    // MARK: - ECDSA sign then verify round-trip

    func testSignVerifyRoundTrip() {
        // Use several different private keys and messages.
        let keys = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            "2b2afb5ea8d8c623acd6744547628988d86787003bb970afe15d471b727db79c",
        ]
        let messages = ["hello", "world", "BSV", "test message 12345"]

        for keyHex in keys {
            let priv = PrivateKey(hex: keyHex)!
            let pub = PublicKey.fromPrivateKey(priv)

            for msg in messages {
                let hash = Digest.sha256(msg.data(using: .utf8)!)
                let sig = priv.sign(hash: hash)
                XCTAssertNotNil(sig, "Failed to sign with key \(keyHex) message \(msg)")
                XCTAssertTrue(sig!.isLowS, "Signature should have low-S for key \(keyHex)")
                XCTAssertTrue(pub.verify(hash: hash, signature: sig!),
                              "Verification failed for key \(keyHex) message \(msg)")
            }
        }
    }

    /// Verify that different private keys produce signatures that don't cross-verify.
    func testSignVerifyCrossKeyRejection() {
        let priv1 = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let priv2 = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000002")!
        let pub1 = PublicKey.fromPrivateKey(priv1)
        let pub2 = PublicKey.fromPrivateKey(priv2)

        let hash = Digest.sha256("cross-key test".data(using: .utf8)!)
        let sig1 = priv1.sign(hash: hash)!
        let sig2 = priv2.sign(hash: hash)!

        // Each signature verifies with its own key.
        XCTAssertTrue(pub1.verify(hash: hash, signature: sig1))
        XCTAssertTrue(pub2.verify(hash: hash, signature: sig2))

        // But not with the other key.
        XCTAssertFalse(pub1.verify(hash: hash, signature: sig2))
        XCTAssertFalse(pub2.verify(hash: hash, signature: sig1))
    }

    /// RFC 6979 determinism: signing the same hash with the same key always
    /// produces the same signature.
    func testSigningDeterminism() {
        let priv = PrivateKey(hex: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")!
        let hash = Digest.sha256("determinism test".data(using: .utf8)!)

        let sig1 = priv.sign(hash: hash)!
        let sig2 = priv.sign(hash: hash)!

        XCTAssertEqual(sig1.r, sig2.r)
        XCTAssertEqual(sig1.s, sig2.s)
    }

    // MARK: - Signature DER round-trip

    func testDERRoundTripMultipleKeys() {
        let keys = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        ]

        for keyHex in keys {
            let priv = PrivateKey(hex: keyHex)!
            let hash = Digest.sha256("DER round-trip".data(using: .utf8)!)
            let sig = priv.sign(hash: hash)!

            let der = sig.toDER()
            let parsed = Signature.fromDER(der)
            XCTAssertNotNil(parsed, "Failed to parse DER for key \(keyHex)")
            XCTAssertEqual(parsed!.r, sig.r, "R mismatch for key \(keyHex)")
            XCTAssertEqual(parsed!.s, sig.s, "S mismatch for key \(keyHex)")
        }
    }

    func testCompactRoundTripMultipleKeys() {
        let keys = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        ]

        for keyHex in keys {
            let priv = PrivateKey(hex: keyHex)!
            let hash = Digest.sha256("compact round-trip".data(using: .utf8)!)
            let sig = priv.sign(hash: hash)!

            let compact = sig.toCompact()
            XCTAssertEqual(compact.count, 64)
            let parsed = Signature.fromCompact(compact)
            XCTAssertNotNil(parsed, "Failed to parse compact for key \(keyHex)")
            XCTAssertEqual(parsed!.r, sig.r)
            XCTAssertEqual(parsed!.s, sig.s)
        }
    }

    // MARK: - Known DER vectors from go-sdk (Bitcoin blockchain signatures)

    func testKnownDERFromBlockchain() {
        // Valid signature from Bitcoin tx 0437cd7f8525ceed2324359c2d0ba26006d92d85.
        let validDER = Data([
            0x30, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
            0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
            0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
            0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
            0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
            0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
            0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
            0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09,
        ])

        let sig = Signature.fromDER(validDER)
        XCTAssertNotNil(sig, "Should parse valid blockchain DER signature")

        // Round-trip: re-encode to DER and compare.
        let reencoded = sig!.toDER()
        XCTAssertEqual(reencoded, validDER, "DER re-encoding should match original")
    }

    func testRejectBadMagicDER() {
        // Same as above but with 0x31 instead of 0x30.
        let badMagic = Data([
            0x31, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
            0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
            0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
            0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
            0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
            0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
            0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
            0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09,
        ])
        XCTAssertNil(Signature.fromDER(badMagic))
    }

    func testRejectBadIntMarkerDER() {
        // First integer marker changed from 0x02 to 0x03.
        let badMarker = Data([
            0x30, 0x44, 0x03, 0x20, 0x4e, 0x45, 0xe1, 0x69,
            0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
            0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
            0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
            0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
            0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
            0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
            0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09,
        ])
        XCTAssertNil(Signature.fromDER(badMarker))
    }

    // MARK: - ECDSA recovery

    func testSignAndRecover() {
        let priv = PrivateKey(hex: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")!
        let pub = PublicKey.fromPrivateKey(priv)
        let hash = Digest.sha256("recovery test".data(using: .utf8)!)

        let result = ECDSA.sign(hash: hash, privateKey: priv.data)
        XCTAssertNotNil(result)

        let recovered = ECDSA.recover(hash: hash, r: result!.r, s: result!.s, recoveryId: result!.recoveryId)
        XCTAssertNotNil(recovered)
        XCTAssertEqual(recovered!, pub.point)
    }

    // MARK: - Public key encoding conformance

    func testPublicKeyCompressedUncompressedRoundTrip() {
        let keys = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        ]

        for keyHex in keys {
            let priv = PrivateKey(hex: keyHex)!
            let pub = PublicKey.fromPrivateKey(priv)

            // Compressed round-trip.
            let compressed = pub.toCompressed()
            XCTAssertEqual(compressed.count, 33)
            let fromCompressed = PublicKey(data: compressed)
            XCTAssertNotNil(fromCompressed)
            XCTAssertEqual(fromCompressed!, pub)

            // Uncompressed round-trip.
            let uncompressed = pub.toUncompressed()
            XCTAssertEqual(uncompressed.count, 65)
            let fromUncompressed = PublicKey(data: uncompressed)
            XCTAssertNotNil(fromUncompressed)
            XCTAssertEqual(fromUncompressed!, pub)
        }
    }

    // MARK: - Low-S normalisation conformance

    func testLowSEnforcement() {
        // Sign several messages and verify all signatures have low-S.
        let priv = PrivateKey(hex: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")!
        let pub = PublicKey.fromPrivateKey(priv)

        for i in 0..<10 {
            let msg = "low-s test \(i)"
            let hash = Digest.sha256(msg.data(using: .utf8)!)
            let sig = priv.sign(hash: hash)!
            XCTAssertTrue(sig.isLowS, "Signature for message '\(msg)' should have low-S")
            XCTAssertTrue(pub.verify(hash: hash, signature: sig))
        }
    }

    /// Artificially high-S signature should normalise correctly and still verify.
    func testHighSNormalisationStillVerifies() {
        let priv = PrivateKey(hex: "0000000000000000000000000000000000000000000000000000000000000001")!
        let pub = PublicKey.fromPrivateKey(priv)
        let hash = Digest.sha256("high-s test".data(using: .utf8)!)

        let sig = priv.sign(hash: hash)!
        XCTAssertTrue(sig.isLowS)

        // Create a high-S version.
        let highS = scalarSubN(Secp256k1.N, sig.s)
        let highSig = Signature(r: sig.r, s: highS)
        XCTAssertFalse(highSig.isLowS)

        // Normalise back to low-S.
        let normalised = highSig.lowSNormalised()
        XCTAssertTrue(normalised.isLowS)
        XCTAssertEqual(normalised.s, sig.s)

        // Both the original and normalised should verify (ECDSA.verify doesn't enforce low-S).
        XCTAssertTrue(pub.verify(hash: hash, signature: sig))
        XCTAssertTrue(pub.verify(hash: hash, signature: normalised))
    }

    // MARK: - Known address vectors

    func testKnownAddressVectors() {
        // Well-known Bitcoin address test vectors.
        struct AddressVector {
            let privKeyHex: String
            let expectedAddress: String
        }

        let vectors = [
            AddressVector(
                privKeyHex: "0000000000000000000000000000000000000000000000000000000000000001",
                expectedAddress: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
            ),
            AddressVector(
                privKeyHex: "0000000000000000000000000000000000000000000000000000000000000002",
                expectedAddress: "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"
            ),
            AddressVector(
                privKeyHex: "0000000000000000000000000000000000000000000000000000000000000003",
                expectedAddress: "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb"
            ),
        ]

        for vector in vectors {
            let priv = PrivateKey(hex: vector.privKeyHex)!
            let pub = PublicKey.fromPrivateKey(priv)
            XCTAssertEqual(pub.toAddress(), vector.expectedAddress,
                           "Address mismatch for privkey \(vector.privKeyHex)")
        }
    }
}
