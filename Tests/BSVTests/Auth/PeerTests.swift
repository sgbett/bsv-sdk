import XCTest
@testable import BSV

/// A pair of in-memory transports connected back-to-back.
///
/// Each side can `send` a message; the other side's `onData` callback is
/// invoked asynchronously. The pair is thread-safe by virtue of each side
/// being its own actor.
actor InMemoryTransport: Transport {
    private var partner: InMemoryTransport?
    private var onDataCallback: (@Sendable (AuthMessage) async throws -> Void)?

    func connect(to partner: InMemoryTransport) {
        self.partner = partner
    }

    func send(_ message: AuthMessage) async throws {
        guard let partner else {
            throw AuthError.transportFailure("in-memory transport is not connected")
        }
        await partner.deliver(message)
    }

    func onData(_ callback: @escaping @Sendable (AuthMessage) async throws -> Void) async throws {
        self.onDataCallback = callback
    }

    fileprivate func deliver(_ message: AuthMessage) async {
        guard let cb = onDataCallback else { return }
        do {
            try await cb(message)
        } catch {
            // Tests make errors observable via XCTFail in their own handlers.
        }
    }
}

/// Create a pair of connected transports.
func makeConnectedTransports() async -> (InMemoryTransport, InMemoryTransport) {
    let a = InMemoryTransport()
    let b = InMemoryTransport()
    await a.connect(to: b)
    await b.connect(to: a)
    return (a, b)
}

final class PeerTests: XCTestCase {

    func testHandshakeEstablishesAuthenticatedSession() async throws {
        let (transportA, transportB) = await makeConnectedTransports()

        let aliceWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let bobWallet = ProtoWallet(rootKey: PrivateKey.random()!)

        let alice = try await Peer(wallet: aliceWallet, transport: transportA)
        let bob = try await Peer(wallet: bobWallet, transport: transportB)
        _ = bob // Keep Bob alive — the onData callback captures self weakly.

        let bobIdentity = try await bobWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey

        let session = try await alice.getAuthenticatedSession(identityKey: bobIdentity)
        XCTAssertTrue(session.isAuthenticated)
        XCTAssertEqual(session.peerIdentityKey, bobIdentity)
        withExtendedLifetime(bob) {}
    }

    func testGeneralMessageRoundTrip() async throws {
        let (transportA, transportB) = await makeConnectedTransports()

        let aliceWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let bobWallet = ProtoWallet(rootKey: PrivateKey.random()!)

        let alice = try await Peer(wallet: aliceWallet, transport: transportA)
        let bob = try await Peer(wallet: bobWallet, transport: transportB)

        // Collect messages Bob receives.
        let received = MessageCollector()
        await bob.listenForGeneralMessages { identity, payload in
            Task { await received.append(identity: identity, payload: payload) }
        }

        let bobIdentity = try await bobWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey
        let payload = Data("hello peer".utf8)
        try await alice.toPeer(payload, identityKey: bobIdentity)

        // Give Bob's handler a moment to run.
        try await Task.sleep(nanoseconds: 100_000_000)

        let received0 = await received.all()
        XCTAssertEqual(received0.count, 1)
        XCTAssertEqual(received0.first?.payload, payload)
        withExtendedLifetime(bob) {}
    }

    // MARK: - Vuln 1: Certificate verification bypass

    /// A legitimate certificate — properly signed by a certifier that Alice
    /// trusts, with the correct subject and type — is accepted, and the
    /// session flag flips to `certificatesValidated = true`.
    func testCertificateResponseAcceptsValidCertificate() async throws {
        let fixture = try await CertResponseFixture.make(requireCerts: true)
        let cert = try await fixture.buildCertificate(
            subject: fixture.bobIdentity,
            certifierWallet: fixture.certifierWallet,
            type: fixture.requestedType
        )
        // Sanity check: the cert we built must pass cert.verify() on its own.
        let directVerify = try await cert.verify()
        XCTAssertTrue(directVerify, "fixture produced an unverifiable cert")

        try await fixture.sendCertificateResponse([cert])
        let validated = await fixture.waitForCertificatesValidated()
        XCTAssertTrue(validated, "valid certificate should flip certificatesValidated")
        withExtendedLifetime(fixture.bob) {}
    }

    /// A certificate with no signature must be rejected.
    func testCertificateResponseRejectsUnsignedCertificate() async throws {
        let fixture = try await CertResponseFixture.make(requireCerts: true)
        var cert = try await fixture.buildCertificate(
            subject: fixture.bobIdentity,
            certifierWallet: fixture.certifierWallet,
            type: fixture.requestedType
        )
        cert.signature = nil

        try await fixture.sendCertificateResponse([cert])

        let sessionLookup = await fixture.alice.sessionManager.getSession(fixture.bobIdentity.hex)
        let session = try XCTUnwrap(sessionLookup)
        XCTAssertFalse(session.certificatesValidated)
        withExtendedLifetime(fixture.bob) {}
    }

    /// A certificate signed by a certifier NOT in `certificatesToRequest.certifiers`
    /// must be rejected.
    func testCertificateResponseRejectsWrongCertifier() async throws {
        let fixture = try await CertResponseFixture.make(requireCerts: true)
        let otherCertifier = ProtoWallet(rootKey: PrivateKey.random()!)
        let cert = try await fixture.buildCertificate(
            subject: fixture.bobIdentity,
            certifierWallet: otherCertifier,
            type: fixture.requestedType
        )

        try await fixture.sendCertificateResponse([cert])

        let sessionLookup = await fixture.alice.sessionManager.getSession(fixture.bobIdentity.hex)
        let session = try XCTUnwrap(sessionLookup)
        XCTAssertFalse(session.certificatesValidated)
        withExtendedLifetime(fixture.bob) {}
    }

    /// A certificate with a type NOT in `certificatesToRequest.types` must
    /// be rejected.
    func testCertificateResponseRejectsWrongType() async throws {
        let fixture = try await CertResponseFixture.make(requireCerts: true)
        var other = Data(count: 32)
        _ = other.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        let cert = try await fixture.buildCertificate(
            subject: fixture.bobIdentity,
            certifierWallet: fixture.certifierWallet,
            type: other
        )

        try await fixture.sendCertificateResponse([cert])

        let sessionLookup = await fixture.alice.sessionManager.getSession(fixture.bobIdentity.hex)
        let session = try XCTUnwrap(sessionLookup)
        XCTAssertFalse(session.certificatesValidated)
        withExtendedLifetime(fixture.bob) {}
    }

    /// A certificate whose subject does not match the claimed message identity
    /// must be rejected.
    func testCertificateResponseRejectsWrongSubject() async throws {
        let fixture = try await CertResponseFixture.make(requireCerts: true)
        let strangerSubject = PublicKey.fromPrivateKey(PrivateKey.random()!)
        let cert = try await fixture.buildCertificate(
            subject: strangerSubject,
            certifierWallet: fixture.certifierWallet,
            type: fixture.requestedType
        )

        try await fixture.sendCertificateResponse([cert])

        let sessionLookup = await fixture.alice.sessionManager.getSession(fixture.bobIdentity.hex)
        let session = try XCTUnwrap(sessionLookup)
        XCTAssertFalse(session.certificatesValidated)
        withExtendedLifetime(fixture.bob) {}
    }

    /// A certificate whose signature is complete garbage must be rejected.
    func testCertificateResponseRejectsForgedSignature() async throws {
        let fixture = try await CertResponseFixture.make(requireCerts: true)
        var cert = try await fixture.buildCertificate(
            subject: fixture.bobIdentity,
            certifierWallet: fixture.certifierWallet,
            type: fixture.requestedType
        )
        // Replace the signature with random bytes of a plausible DER length.
        cert.signature = Data(repeating: 0x30, count: 70)

        try await fixture.sendCertificateResponse([cert])

        let sessionLookup = await fixture.alice.sessionManager.getSession(fixture.bobIdentity.hex)
        let session = try XCTUnwrap(sessionLookup)
        XCTAssertFalse(session.certificatesValidated)
        withExtendedLifetime(fixture.bob) {}
    }

    // MARK: - Vuln 3: General message identity spoofing

    /// A general message whose `identityKey` does not match the session's
    /// stored `peerIdentityKey` must be rejected, even if the inner
    /// signature is cryptographically valid against the claimed key.
    /// BRC-43 verification is ECDH-symmetric, so without this check any
    /// third party could forge messages into an existing session by
    /// signing with their own root key.
    func testGeneralMessageRejectsMismatchedIdentity() async throws {
        let (aliceTransport, bobTransport) = await makeConnectedTransports()

        let aliceWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let bobWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let charlieWallet = ProtoWallet(rootKey: PrivateKey.random()!)

        let alice = try await Peer(wallet: aliceWallet, transport: aliceTransport)
        let bob = try await Peer(wallet: bobWallet, transport: bobTransport)

        let bobIdentity = try await bobWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey
        let aliceIdentity = try await aliceWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey
        let charlieIdentity = try await charlieWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey

        // Establish a legitimate Alice-Bob session via the standard
        // handshake. Alice's session now has peerIdentityKey = Bob.
        _ = try await alice.getAuthenticatedSession(identityKey: bobIdentity)

        // Collect whatever Alice's general-message listener delivers so we
        // can assert the forged message never makes it through.
        let received = MessageCollector()
        await alice.listenForGeneralMessages { identity, payload in
            Task { await received.append(identity: identity, payload: payload) }
        }

        // Charlie crafts a general message claiming identityKey = Charlie,
        // targeted at Alice's session nonce. He signs with his own root
        // key under counterparty = Alice — a signature that would pass
        // verification if Alice naively verified with
        // counterparty = message.identityKey.
        let aliceSessionLookup = await alice.sessionManager.getSession(bobIdentity.hex)
        let aliceSession = try XCTUnwrap(aliceSessionLookup)
        let charlieNonce = try await AuthNonce.create(wallet: charlieWallet)
        let payload = Data("spoofed".utf8)
        let charlieSig = try await charlieWallet.createSignature(args: CreateSignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: Peer.signatureProtocol,
                keyID: "\(charlieNonce) \(aliceSession.sessionNonce)",
                counterparty: .publicKey(aliceIdentity)
            ),
            data: payload
        )).signature

        let spoofed = AuthMessage(
            messageType: .general,
            identityKey: charlieIdentity,
            nonce: charlieNonce,
            yourNonce: aliceSession.sessionNonce,
            payload: payload,
            signature: charlieSig
        )

        // Deliver via Bob's transport so Alice's onData processes it.
        try await bobTransport.send(spoofed)
        try await Task.sleep(nanoseconds: 100_000_000)

        let delivered = await received.all()
        XCTAssertEqual(
            delivered.count, 0,
            "spoofed general message with mismatched identity must not be delivered"
        )
        withExtendedLifetime(bob) {}
    }

    // MARK: - H1: Handshake continuation leak on malformed initialResponse

    /// A malformed `initialResponse` (e.g. invalid signature) must cause
    /// `initiateHandshake` to throw rather than hang forever. The waiter
    /// continuation must be resumed on any failure path inside
    /// `processInitialResponse`, not only on success.
    func testMalformedInitialResponseThrowsRatherThanHangs() async throws {
        let (aliceTransport, peerTransport) = await makeConnectedTransports()

        let aliceWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let attackerWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let alice = try await Peer(wallet: aliceWallet, transport: aliceTransport)

        let attackerIdentity = try await attackerWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey

        // Hook the peer transport so any incoming initialRequest is
        // answered with a malformed initialResponse: echo Alice's nonce
        // but sign with a garbage payload so signature verification
        // fails. processInitialResponse must fail and wake the waiter.
        try await peerTransport.onData { [peerTransport, attackerWallet, attackerIdentity] message in
            guard message.messageType == .initialRequest,
                  let aliceNonce = message.initialNonce else { return }

            let attackerNonce = try await AuthNonce.create(wallet: attackerWallet)
            // Deliberately sign unrelated data — verification will fail
            // inside processInitialResponse, which must surface as an
            // error from getAuthenticatedSession rather than a deadlock.
            let badSig = try await attackerWallet.createSignature(args: CreateSignatureArgs(
                encryption: WalletEncryptionArgs(
                    protocolID: Peer.signatureProtocol,
                    keyID: "\(aliceNonce) \(attackerNonce)",
                    counterparty: .publicKey(message.identityKey)
                ),
                data: Data("garbage".utf8)
            )).signature

            let response = AuthMessage(
                messageType: .initialResponse,
                identityKey: attackerIdentity,
                initialNonce: attackerNonce,
                yourNonce: aliceNonce,
                signature: badSig
            )
            try await peerTransport.send(response)
        }

        // Race the handshake against a watchdog. If the fix is missing,
        // getAuthenticatedSession hangs forever and the watchdog wins,
        // causing the test to fail rather than hanging the suite.
        enum Outcome: Sendable { case threw, succeeded, timedOut }
        let outcome: Outcome = await withTaskGroup(of: Outcome.self) { group in
            group.addTask {
                do {
                    _ = try await alice.getAuthenticatedSession(identityKey: attackerIdentity)
                    return .succeeded
                } catch {
                    return .threw
                }
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                return .timedOut
            }
            let first = await group.next() ?? .timedOut
            group.cancelAll()
            return first
        }
        XCTAssertEqual(
            outcome, .threw,
            "malformed initialResponse must cause initiateHandshake to throw, not hang or succeed"
        )
    }

    // MARK: - Vuln 2: Unsigned initialRequest session injection

    /// An attacker-controlled peer sends Alice an unsigned BRC-66
    /// `initialRequest` claiming identity `victim`. Alice's responder
    /// path creates a session whose `peerIdentityKey` is the claimed key
    /// — but that claim is UNVERIFIED. A subsequent
    /// `getAuthenticatedSession(identityKey: victim)` call must NOT
    /// return the attacker-seeded session.
    func testInitialRequestDoesNotEnableIdentityLookup() async throws {
        let (aliceTransport, attackerTransport) = await makeConnectedTransports()

        let aliceWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let alice = try await Peer(wallet: aliceWallet, transport: aliceTransport)

        // Pick a victim identity entirely unrelated to either party.
        let victimKey = PrivateKey.random()!
        let victimIdentity = PublicKey.fromPrivateKey(victimKey)

        // Attacker has their own wallet but crafts a raw initialRequest
        // AuthMessage whose identityKey is the victim's public key.
        let attackerWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let attackerInitialNonce = try await AuthNonce.create(wallet: attackerWallet)

        let spoofed = AuthMessage(
            messageType: .initialRequest,
            identityKey: victimIdentity,
            initialNonce: attackerInitialNonce
        )
        try await attackerTransport.send(spoofed)

        // Drain in-flight actor work so Alice's processInitialRequest has
        // completed.
        try await Task.sleep(nanoseconds: 100_000_000)

        // Identity lookup must not return the attacker-seeded session.
        let byIdentity = await alice.sessionManager.getSession(victimIdentity.hex)
        XCTAssertNil(
            byIdentity,
            "attacker-seeded session must not be reachable via identity-key lookup"
        )
    }

}

// MARK: - Certificate-response test fixture

/// Scaffolding for tests that exercise `processCertificateResponse` without
/// running a full BRC-66 certificate-response flow. Stands up two real peers
/// (Alice + Bob) with Alice configured to require certificates from a known
/// certifier, then exposes a helper to send a hand-signed `certificateResponse`
/// message from Bob to Alice using the wire protocol.
private struct CertResponseFixture {
    let alice: Peer
    let bob: Peer
    let aliceWallet: ProtoWallet
    let bobWallet: ProtoWallet
    let certifierWallet: ProtoWallet
    let bobIdentity: PublicKey
    let certifierIdentity: PublicKey
    let requestedType: Data
    let transportB: InMemoryTransport

    /// Build a fixture with an in-memory transport pair, run the BRC-66
    /// handshake so Alice has an authenticated session with Bob, and return
    /// the ready-to-use handles.
    static func make(requireCerts: Bool) async throws -> CertResponseFixture {
        let (transportA, transportB) = await makeConnectedTransports()

        let aliceWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let bobWallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let certifierWallet = ProtoWallet(rootKey: PrivateKey.random()!)

        let certifierIdentity = try await certifierWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey

        // Pin the certificate type so the test can build a matching cert.
        var typeBytes = Data(count: 32)
        _ = typeBytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }

        let requested: RequestedCertificateSet
        if requireCerts {
            requested = RequestedCertificateSet(
                certifiers: [certifierIdentity.hex],
                types: [typeBytes.base64EncodedString(): ["name"]]
            )
        } else {
            requested = RequestedCertificateSet()
        }

        let alice = try await Peer(
            wallet: aliceWallet,
            transport: transportA,
            certificatesToRequest: requested
        )
        let bob = try await Peer(wallet: bobWallet, transport: transportB)

        let bobIdentity = try await bobWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey

        // Run the BRC-66 handshake to completion. Alice's
        // `getAuthenticatedSession` does not block on certificate
        // validation (only `toPeer` does), so it returns once the
        // handshake itself is authenticated. At that point Alice's session
        // has `certificatesValidated = false` which is exactly the
        // pre-condition the tests want before exercising
        // processCertificateResponse.
        _ = try await alice.getAuthenticatedSession(identityKey: bobIdentity)

        return CertResponseFixture(
            alice: alice,
            bob: bob,
            aliceWallet: aliceWallet,
            bobWallet: bobWallet,
            certifierWallet: certifierWallet,
            bobIdentity: bobIdentity,
            certifierIdentity: certifierIdentity,
            requestedType: typeBytes,
            transportB: transportB
        )
    }

    /// Build a signed BRC-103 certificate with a pinned type.
    func buildCertificate(
        subject: PublicKey,
        certifierWallet: WalletInterface,
        type: Data
    ) async throws -> Certificate {
        var serial = Data(count: 32)
        _ = serial.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        let certifierID = try await certifierWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey
        var cert = Certificate(
            type: type,
            serialNumber: serial,
            subject: subject,
            certifier: certifierID,
            revocationOutpoint: String(repeating: "0", count: 64) + ".0",
            fields: ["name": "Bob"],
            signature: nil
        )
        try await cert.sign(certifierWallet: certifierWallet)
        return cert
    }

    /// Construct a properly-signed outer `certificateResponse` envelope and
    /// deliver it to Alice via Bob's transport. The outer signature is
    /// correct — what the tests exercise is the inner certificate
    /// verification.
    func sendCertificateResponse(_ certs: [Certificate]) async throws {
        // Fetch Alice's view of the session so we can address the response
        // with the nonce Alice minted.
        guard let session = await alice.sessionManager.getSession(bobIdentity.hex) else {
            throw AuthError.sessionNotFound("alice has no session for bob")
        }
        let aliceSessionNonce = session.sessionNonce

        // Mint a nonce for Bob-side and sign the JSON payload the way
        // processCertificateResponse expects.
        let bobNonce = try await AuthNonce.create(wallet: bobWallet)
        let jsonData = CanonicalJSON.encodeCertificates(certs)

        let aliceIdentity = try await aliceWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey

        let signature = try await bobWallet.createSignature(args: CreateSignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: Peer.signatureProtocol,
                keyID: "\(bobNonce) \(aliceSessionNonce)",
                counterparty: .publicKey(aliceIdentity)
            ),
            data: jsonData
        )).signature

        let response = AuthMessage(
            messageType: .certificateResponse,
            identityKey: bobIdentity,
            nonce: bobNonce,
            yourNonce: aliceSessionNonce,
            certificates: certs,
            signature: signature
        )

        try await transportB.send(response)
    }

    /// Spin-wait on Alice's session until `certificatesValidated` flips
    /// to true, or a bounded timeout elapses. Returns the final value.
    func waitForCertificatesValidated() async -> Bool {
        for _ in 0..<50 {
            let s = await alice.sessionManager.getSession(bobIdentity.hex)
            if s?.certificatesValidated == true { return true }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        let final = await alice.sessionManager.getSession(bobIdentity.hex)
        return final?.certificatesValidated ?? false
    }
}

// MARK: - Helpers

private actor MessageCollector {
    struct Entry: Sendable {
        let identity: PublicKey
        let payload: Data
    }
    private var entries: [Entry] = []

    func append(identity: PublicKey, payload: Data) {
        entries.append(Entry(identity: identity, payload: payload))
    }

    func all() -> [Entry] { entries }
}
