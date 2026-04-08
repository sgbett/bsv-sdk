import XCTest
@testable import BSV

/// Tests for BRC-42 key derivation, including the shared vectors from the
/// other BSV SDKs (`Tests/BSVTests/Conformance/Vectors/BRC42.{private,public}.vectors.json`).
final class KeyDeriverTests: XCTestCase {

    // MARK: - Shared vectors

    private struct PrivateVector: Decodable {
        let senderPublicKey: String
        let recipientPrivateKey: String
        let invoiceNumber: String
        let privateKey: String
    }

    private struct PublicVector: Decodable {
        let senderPrivateKey: String
        let recipientPublicKey: String
        let invoiceNumber: String
        let publicKey: String
    }

    private func loadVectors<T: Decodable>(_ name: String, as type: T.Type) throws -> T {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Vectors"),
            "missing test vector file: \(name).json"
        )
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(T.self, from: data)
    }

    func testBRC42PrivateKeyVectors() throws {
        let vectors = try loadVectors("BRC42.private.vectors", as: [PrivateVector].self)
        XCTAssertFalse(vectors.isEmpty)

        for vector in vectors {
            let recipient = PrivateKey(hex: vector.recipientPrivateKey)!
            let sender = PublicKey(hex: vector.senderPublicKey)!

            let derivedPrivate = KeyDeriver(rootKey: recipient).deriveChildPrivate(
                priv: recipient,
                counterpartyPub: sender,
                invoiceNumber: vector.invoiceNumber
            )
            XCTAssertEqual(
                derivedPrivate.hex,
                vector.privateKey,
                "BRC-42 private derivation mismatch for invoice \(vector.invoiceNumber)"
            )
        }
    }

    func testBRC42PublicKeyVectors() throws {
        let vectors = try loadVectors("BRC42.public.vectors", as: [PublicVector].self)
        XCTAssertFalse(vectors.isEmpty)

        for vector in vectors {
            let sender = PrivateKey(hex: vector.senderPrivateKey)!
            let recipient = PublicKey(hex: vector.recipientPublicKey)!

            let derivedPublic = KeyDeriver(rootKey: sender).deriveChildPublic(
                pub: recipient,
                counterpartyPriv: sender,
                invoiceNumber: vector.invoiceNumber
            )
            XCTAssertEqual(
                derivedPublic.hex,
                vector.publicKey,
                "BRC-42 public derivation mismatch for invoice \(vector.invoiceNumber)"
            )
        }
    }

    // MARK: - High-level derive API

    func testDerivePublicKeyMatchesDerivePrivateKey() throws {
        let root = PrivateKey.random()!
        let counterparty = PrivateKey.random()!
        let deriver = KeyDeriver(rootKey: root)

        let proto = WalletProtocol(securityLevel: .app, protocol: "test protocolname")
        let counterpartyCp = WalletCounterparty.publicKey(PublicKey.fromPrivateKey(counterparty))

        // Deriving for self: the derived public key must equal priv * G.
        let selfPriv = try deriver.derivePrivateKey(
            protocolID: proto,
            keyID: "1",
            counterparty: counterpartyCp
        )
        let selfPub = try deriver.derivePublicKey(
            protocolID: proto,
            keyID: "1",
            counterparty: counterpartyCp,
            forSelf: true
        )
        XCTAssertEqual(PublicKey.fromPrivateKey(selfPriv), selfPub)
    }

    func testDeriveSymmetricKeyIsSymmetric() throws {
        // Two parties derive the same symmetric key from opposite viewpoints.
        let alice = PrivateKey.random()!
        let bob = PrivateKey.random()!
        let aliceDeriver = KeyDeriver(rootKey: alice)
        let bobDeriver = KeyDeriver(rootKey: bob)

        let proto = WalletProtocol(securityLevel: .counterparty, protocol: "shared symmetric")

        let aliceKey = try aliceDeriver.deriveSymmetricKey(
            protocolID: proto,
            keyID: "message-1",
            counterparty: .publicKey(PublicKey.fromPrivateKey(bob))
        )
        let bobKey = try bobDeriver.deriveSymmetricKey(
            protocolID: proto,
            keyID: "message-1",
            counterparty: .publicKey(PublicKey.fromPrivateKey(alice))
        )
        XCTAssertEqual(aliceKey.key, bobKey.key)
    }

    // MARK: - Invoice number validation

    func testRejectsEmptyKeyID() {
        let deriver = KeyDeriver(rootKey: PrivateKey.random()!)
        let proto = WalletProtocol(securityLevel: .silent, protocol: "valid name")
        XCTAssertThrowsError(
            try deriver.computeInvoiceNumber(protocolID: proto, keyID: "")
        )
    }

    func testRejectsShortProtocolName() {
        let deriver = KeyDeriver(rootKey: PrivateKey.random()!)
        let proto = WalletProtocol(securityLevel: .silent, protocol: "abc")
        XCTAssertThrowsError(
            try deriver.computeInvoiceNumber(protocolID: proto, keyID: "1")
        )
    }

    func testRejectsProtocolNameEndingInProtocol() {
        let deriver = KeyDeriver(rootKey: PrivateKey.random()!)
        let proto = WalletProtocol(securityLevel: .silent, protocol: "something protocol")
        XCTAssertThrowsError(
            try deriver.computeInvoiceNumber(protocolID: proto, keyID: "1")
        )
    }

    func testRejectsDoubleSpacesInProtocolName() {
        let deriver = KeyDeriver(rootKey: PrivateKey.random()!)
        let proto = WalletProtocol(securityLevel: .silent, protocol: "two  spaces")
        XCTAssertThrowsError(
            try deriver.computeInvoiceNumber(protocolID: proto, keyID: "1")
        )
    }

    func testAcceptsValidBRC43InvoiceNumber() throws {
        let deriver = KeyDeriver(rootKey: PrivateKey.random()!)
        let proto = WalletProtocol(securityLevel: .app, protocol: "test protocol name")
        let invoice = try deriver.computeInvoiceNumber(protocolID: proto, keyID: "42")
        XCTAssertEqual(invoice, "1-test protocol name-42")
    }

    // MARK: - Counterparty secrets

    func testRevealCounterpartySecretRejectsSelf() {
        let deriver = KeyDeriver(rootKey: PrivateKey.random()!)
        XCTAssertThrowsError(try deriver.revealCounterpartySecret(counterparty: .`self`))
    }
}
