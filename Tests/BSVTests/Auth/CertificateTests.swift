import XCTest
@testable import BSV

final class CertificateTests: XCTestCase {

    private func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        _ = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        return data
    }

    private func sampleCertificate(subject: PublicKey, certifier: PublicKey) -> Certificate {
        Certificate(
            type: randomBytes(32),
            serialNumber: randomBytes(32),
            subject: subject,
            certifier: certifier,
            revocationOutpoint: String(repeating: "a", count: 64) + ".0",
            fields: ["name": "Alice", "email": "alice@example.com"],
            signature: nil
        )
    }

    // MARK: - Binary round-trip

    func testBinaryRoundTrip() throws {
        let subjectKey = PrivateKey.random()!
        let certifierKey = PrivateKey.random()!
        let cert = sampleCertificate(
            subject: PublicKey.fromPrivateKey(subjectKey),
            certifier: PublicKey.fromPrivateKey(certifierKey)
        )

        let bytes = cert.toBinary(includeSignature: false)
        let parsed = try XCTUnwrap(Certificate.fromBinary(bytes))
        XCTAssertEqual(parsed.type, cert.type)
        XCTAssertEqual(parsed.serialNumber, cert.serialNumber)
        XCTAssertEqual(parsed.subject, cert.subject)
        XCTAssertEqual(parsed.certifier, cert.certifier)
        XCTAssertEqual(parsed.revocationOutpoint, cert.revocationOutpoint)
        XCTAssertEqual(parsed.fields, cert.fields)
        XCTAssertNil(parsed.signature)
    }

    // MARK: - Sign / verify round-trip

    func testSignVerifyRoundTrip() async throws {
        let certifierWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let certifierIdentity = try await certifierWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey

        var cert = sampleCertificate(
            subject: PublicKey.fromPrivateKey(PrivateKey.random()!),
            certifier: certifierIdentity
        )
        try await cert.sign(certifierWallet: certifierWallet)
        XCTAssertNotNil(cert.signature)
        XCTAssertFalse(cert.signature!.isEmpty)

        let ok = try await cert.verify()
        XCTAssertTrue(ok)
    }

    func testTamperedFieldsFailVerification() async throws {
        let certifierWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        var cert = sampleCertificate(
            subject: PublicKey.fromPrivateKey(PrivateKey.random()!),
            certifier: PublicKey.fromPrivateKey(PrivateKey.random()!)
        )
        try await cert.sign(certifierWallet: certifierWallet)

        // Mutate a field after signing.
        cert.fields["name"] = "Mallory"
        let ok = try await cert.verify()
        XCTAssertFalse(ok)
    }

    func testDoubleSignIsRejected() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        var cert = sampleCertificate(
            subject: PublicKey.fromPrivateKey(PrivateKey.random()!),
            certifier: PublicKey.fromPrivateKey(PrivateKey.random()!)
        )
        try await cert.sign(certifierWallet: wallet)

        do {
            try await cert.sign(certifierWallet: wallet)
            XCTFail("expected certificateInvalid error")
        } catch AuthError.certificateInvalid {
            // expected
        }
    }

    // MARK: - Master / verifiable certificates

    func testMasterCertificateIssueAndVerifierKeyring() async throws {
        let certifierWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let subjectWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let verifierWallet = ProtoWallet(rootKey: PrivateKey.random()!)

        let subjectIdentity = try await subjectWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey
        let verifierIdentity = try await verifierWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey
        let certifierIdentity = try await certifierWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey

        let master = try await MasterCertificate.issueCertificateForSubject(
            certifierWallet: certifierWallet,
            subject: subjectIdentity,
            fields: ["name": "Bob", "dob": "2000-01-01"],
            certificateType: randomBytes(32)
        )

        // Subject re-encrypts the keyring for the verifier.
        let verifierKeyring = try await MasterCertificate.createKeyringForVerifier(
            subjectWallet: subjectWallet,
            certifier: .publicKey(certifierIdentity),
            verifier: .publicKey(verifierIdentity),
            fields: master.certificate.fields,
            fieldsToReveal: ["name"],
            masterKeyring: master.masterKeyring,
            serialNumber: master.certificate.serialNumber
        )

        var verifiable = VerifiableCertificate(
            certificate: master.certificate,
            keyring: verifierKeyring
        )
        let decrypted = try await verifiable.decryptFields(verifierWallet: verifierWallet)
        XCTAssertEqual(decrypted["name"], "Bob")
        XCTAssertNil(decrypted["dob"]) // not revealed
    }
}
