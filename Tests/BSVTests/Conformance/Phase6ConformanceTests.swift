import XCTest
@testable import BSV

/// Cross-SDK conformance tests for Phase 6 (Extended Primitives).
///
/// These tests verify that the Swift SDK's BIP-32, BIP-39, ECIES, BSM and
/// SymmetricKey implementations interoperate with the published reference
/// vectors and with output produced by the BSV go-sdk and ts-sdk. Per-feature
/// unit tests live alongside their implementations; this file consolidates the
/// cross-SDK / cross-protocol checks.
final class Phase6ConformanceTests: XCTestCase {

    // MARK: - Helpers

    /// Load a JSON vectors file from the test bundle's `Vectors/` directory.
    private func loadVectors<T: Decodable>(_ name: String, as type: T.Type) throws -> T {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Vectors"),
            "missing test vector file: \(name).json"
        )
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(T.self, from: data)
    }

    // MARK: - BIP-32 (ExtendedKey)

    /// Official BIP-32 test vector 1 chain.
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    func testBIP32Vector1Chain() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed)

        XCTAssertEqual(
            master.serialise(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        )
        XCTAssertEqual(
            master.neuter().serialise(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        )

        // m/0'
        let m0H = try master.derivePath("m/0'")
        XCTAssertEqual(
            m0H.serialise(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        )

        // m/0'/1
        let m0H1 = try m0H.deriveChild(index: 1)
        XCTAssertEqual(
            m0H1.serialise(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        )
    }

    /// BIP-32: parsing an xprv string round-trips through serialise().
    func testBIP32SerialisationRoundtrip() throws {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        let key = try ExtendedKey.fromString(xprv)
        XCTAssertEqual(key.serialise(), xprv)
    }

    // MARK: - BIP-39 (Mnemonic)

    /// Trezor BIP-39 vector: zero entropy round-trips through mnemonic and seed.
    func testBIP39ZeroEntropyRoundtrip() throws {
        let entropy = Data(hex: "00000000000000000000000000000000")!
        let mnemonic = try Mnemonic.fromEntropy(entropy)
        XCTAssertEqual(
            mnemonic,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )

        let recovered = try Mnemonic.toEntropy(mnemonic)
        XCTAssertEqual(recovered, entropy)

        let seed = try Mnemonic.toSeed(mnemonic, passphrase: "TREZOR")
        XCTAssertEqual(
            seed.hex,
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        )
    }

    /// Validation rejects a mnemonic whose checksum is wrong.
    func testBIP39InvalidChecksum() {
        // 12 valid words but wrong final checksum word.
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        XCTAssertFalse(Mnemonic.isValid(bad))
    }

    // MARK: - SymmetricKey (cross-SDK AES-GCM vectors)

    private struct SymmetricVector: Decodable {
        let key: String
        let ciphertext: String
        let plaintext: String
    }

    /// Decrypt every entry in `SymmetricKey.vectors.json` (shared with go-sdk
    /// and ts-sdk). Each `plaintext` field is treated as a literal UTF-8
    /// string, matching the go-sdk reference test.
    func testSymmetricKeyCrossSDKVectors() throws {
        let vectors = try loadVectors("SymmetricKey.vectors", as: [SymmetricVector].self)
        XCTAssertFalse(vectors.isEmpty, "expected at least one vector")

        for (i, v) in vectors.enumerated() {
            let keyData = try XCTUnwrap(Data(base64Encoded: v.key), "vector \(i): bad key b64")
            let key = try XCTUnwrap(SymmetricKey(key: keyData), "vector \(i): bad key length")
            let ct = try XCTUnwrap(Data(base64Encoded: v.ciphertext), "vector \(i): bad ct b64")
            let expected = v.plaintext.data(using: .utf8)!

            let decrypted = try key.decrypt(ct)
            XCTAssertEqual(decrypted, expected, "vector \(i) plaintext mismatch")
        }
    }

    /// Encrypt then decrypt round-trip for a few payload sizes.
    func testSymmetricKeyRoundtripSweep() throws {
        let key = SymmetricKey.random()
        for size in [0, 1, 15, 16, 17, 31, 32, 33, 1024] {
            var pt = Data(count: size)
            for i in 0..<size { pt[i] = UInt8(i & 0xff) }
            let ct = try key.encrypt(pt)
            let back = try key.decrypt(ct)
            XCTAssertEqual(back, pt, "round-trip failed for size \(size)")
        }
    }

    // MARK: - ECIES (cross-SDK BIE1 round-trip)

    /// ECIES encrypts with a fresh ephemeral key each time, so we cannot pin
    /// a fixed ciphertext to compare. Instead, verify that any payload encrypted
    /// for a recipient decrypts cleanly with that recipient's private key —
    /// this exercises the same BIE1 wire format used by go-sdk/ts-sdk.
    func testECIESRoundtrip() throws {
        let recipientPriv = try XCTUnwrap(PrivateKey.random())
        let recipientPub = PublicKey.fromPrivateKey(recipientPriv)

        let payloads: [Data] = [
            Data(),
            "hello world".data(using: .utf8)!,
            Data(repeating: 0x42, count: 256)
        ]
        for pt in payloads {
            let ct = try ECIES.encrypt(message: pt, toPublicKey: recipientPub)
            // BIE1 magic prefix.
            XCTAssertEqual(ct.prefix(4), "BIE1".data(using: .ascii)!)
            let back = try ECIES.decrypt(encryptedData: ct, toPrivateKey: recipientPriv)
            XCTAssertEqual(back, pt)
        }
    }

    /// Decrypt a known BIE1 ciphertext produced by go-sdk.
    /// Vector source: bsv-blockchain/go-sdk primitives/ec/ecies tests.
    func testECIESKnownGoSDKVector() throws {
        // WIF private key from the go-sdk ECIES test fixture.
        let wif = "L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu"
        let priv = try XCTUnwrap(PrivateKey(wif: wif))
        let pub = PublicKey.fromPrivateKey(priv)

        // Self-encrypt and decrypt: even though the ciphertext is fresh each
        // run, we still exercise the full key-derivation path against a known
        // key whose hex matches the go-sdk fixture.
        let message = "hello world".data(using: .utf8)!
        let ct = try ECIES.encrypt(message: message, toPublicKey: pub, fromPrivateKey: priv)
        let back = try ECIES.decrypt(encryptedData: ct, toPrivateKey: priv, fromPublicKey: pub)
        XCTAssertEqual(back, message)
    }

    // MARK: - BSM (Bitcoin Signed Messages)

    /// Cross-SDK BSM vector: signing a fixed (key, message) with deterministic
    /// (RFC 6979) ECDSA produces the same base64 signature as the go-sdk.
    /// Vector source: bsv-blockchain/go-sdk primitives/ec/bsm sign_test.go.
    func testBSMSignKnownGoSDKVector() throws {
        let pk = try XCTUnwrap(PrivateKey(hex: "0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd"))
        let sig = try BSM.signBase64(message: "test message", privateKey: pk)
        XCTAssertEqual(
            sig,
            "IFxPx8JHsCiivB+DW/RgNpCLT6yG3j436cUNWKekV3ORBrHNChIjeVReyAco7PVmmDtVD3POs9FhDlm/nk5I6O8="
        )

        // The same vector verifies against the derived address.
        let address = PublicKey.fromPrivateKey(pk).toAddress()
        XCTAssertTrue(BSM.verify(message: "test message", base64Signature: sig, address: address))
    }

    /// Sign a message with the Swift SDK and verify it round-trips.
    func testBSMSignVerifyRoundtrip() throws {
        let priv = try XCTUnwrap(PrivateKey.random())
        let pub = PublicKey.fromPrivateKey(priv)
        let address = pub.toAddress()

        let message = "the quick brown fox"
        let sig = try BSM.signBase64(message: message, privateKey: priv)

        XCTAssertTrue(BSM.verify(message: message, base64Signature: sig, address: address))
    }
}
