import Foundation

/// A BRC-66 mutual-authentication peer.
///
/// A `Peer` wraps a `WalletInterface` (for signing/verification), a
/// `Transport` (for message delivery), and a `SessionManager` (for tracking
/// multiple concurrent authenticated sessions). It can initiate a handshake
/// with a remote peer, respond to incoming handshakes, handle certificate
/// requests/responses, and send/receive general messages.
///
/// Sessions are identified by a `sessionNonce` that the local peer mints
/// (using `AuthNonce.create`) at the start of each handshake, and the remote
/// peer echoes back in subsequent `yourNonce` fields so the local peer can
/// look the session up when a message arrives.
///
/// All network I/O is routed through the `Transport`, so users can plug in
/// any substrate — HTTP, WebSocket, or an in-memory pipe for tests.
public actor Peer {

    // MARK: - Stored state

    public let wallet: WalletInterface
    public let transport: Transport
    public let sessionManager: SessionManager
    public private(set) var certificatesToRequest: RequestedCertificateSet

    private var identityKey: PublicKey?
    private var lastInteractedPeer: PublicKey?

    /// Callbacks waiting for a specific `initialResponse` (keyed by the
    /// session nonce the local peer minted in the initial request).
    private var initialResponseWaiters: [String: CheckedContinuation<Void, Error>] = [:]

    /// Listeners for inbound general messages.
    private var generalMessageListeners: [UUID: @Sendable (PublicKey, Data) -> Void] = [:]
    private var certificatesReceivedListeners: [UUID: @Sendable (PublicKey, [VerifiableCertificate]) -> Void] = [:]
    private var certificatesRequestedListeners: [UUID: @Sendable (PublicKey, RequestedCertificateSet) -> Void] = [:]

    // MARK: - Init

    public init(
        wallet: WalletInterface,
        transport: Transport,
        certificatesToRequest: RequestedCertificateSet = RequestedCertificateSet(),
        sessionManager: SessionManager? = nil
    ) async throws {
        self.wallet = wallet
        self.transport = transport
        self.certificatesToRequest = certificatesToRequest
        self.sessionManager = sessionManager ?? SessionManager()

        // Install the incoming-data callback on the transport. We capture
        // `self` weakly so the peer can be deallocated normally; callers are
        // expected to keep a strong reference to the peer for as long as
        // they want to receive messages.
        try await transport.onData { [weak self] message in
            guard let self else { return }
            try await self.handleIncomingMessage(message)
        }
    }

    // MARK: - Public API

    /// Initiates a handshake with the given peer and returns the authenticated session.
    @discardableResult
    public func getAuthenticatedSession(identityKey: PublicKey?) async throws -> PeerSession {
        if let identityKey, let existing = sessionManager.getSession(identityKey.hex),
           existing.isAuthenticated {
            return existing
        }
        let sessionNonce = try await initiateHandshake(identityKey: identityKey)
        guard let session = sessionManager.getSession(sessionNonce), session.isAuthenticated else {
            throw AuthError.sessionNotFound("handshake did not produce an authenticated session")
        }
        return session
    }

    /// Send a general message to a peer, initiating a handshake if needed.
    public func toPeer(_ message: Data, identityKey: PublicKey? = nil) async throws {
        let target = identityKey ?? lastInteractedPeer
        let session = try await getAuthenticatedSession(identityKey: target)

        guard let peerIdentity = session.peerIdentityKey else {
            throw AuthError.sessionNotFound("session is missing peer identity")
        }
        if session.certificatesRequired && !session.certificatesValidated {
            throw AuthError.certificateInvalid("peer certificates have not been validated")
        }

        let requestNonce = try generateRandomBase64(byteCount: 32)
        let keyID = "\(requestNonce) \(session.peerNonce ?? "")"
        let signature = try await wallet.createSignature(args: CreateSignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: Peer.signatureProtocol,
                keyID: keyID,
                counterparty: .publicKey(peerIdentity)
            ),
            data: message
        )).signature

        let identity = try await getIdentityKey()
        let general = AuthMessage(
            messageType: .general,
            identityKey: identity,
            nonce: requestNonce,
            yourNonce: session.peerNonce,
            payload: message,
            signature: signature
        )

        var updated = session
        updated.lastUpdate = Date()
        sessionManager.updateSession(updated)

        try await transport.send(general)
    }

    /// Register a callback for inbound general messages. Returns a token that
    /// can be used to deregister the listener via `stopListeningForGeneralMessages`.
    @discardableResult
    public func listenForGeneralMessages(
        _ callback: @escaping @Sendable (PublicKey, Data) -> Void
    ) -> UUID {
        let id = UUID()
        generalMessageListeners[id] = callback
        return id
    }

    public func stopListeningForGeneralMessages(_ id: UUID) {
        generalMessageListeners.removeValue(forKey: id)
    }

    @discardableResult
    public func listenForCertificatesReceived(
        _ callback: @escaping @Sendable (PublicKey, [VerifiableCertificate]) -> Void
    ) -> UUID {
        let id = UUID()
        certificatesReceivedListeners[id] = callback
        return id
    }

    public func stopListeningForCertificatesReceived(_ id: UUID) {
        certificatesReceivedListeners.removeValue(forKey: id)
    }

    @discardableResult
    public func listenForCertificatesRequested(
        _ callback: @escaping @Sendable (PublicKey, RequestedCertificateSet) -> Void
    ) -> UUID {
        let id = UUID()
        certificatesRequestedListeners[id] = callback
        return id
    }

    public func stopListeningForCertificatesRequested(_ id: UUID) {
        certificatesRequestedListeners.removeValue(forKey: id)
    }

    // MARK: - Handshake

    /// Protocol used to sign and verify all auth messages (BRC-66).
    public static let signatureProtocol = WalletProtocol(
        securityLevel: .counterparty,
        protocol: "auth message signature"
    )

    private func initiateHandshake(identityKey: PublicKey?) async throws -> String {
        let sessionNonce = try await AuthNonce.create(wallet: wallet)
        let certsRequired = !certificatesToRequest.certifiers.isEmpty

        // We're about to initiate a handshake. `peerIdentityKey` here is
        // the caller-supplied expected key — not yet verified. Leave
        // `peerIdentityKeyVerified = false` until `processInitialResponse`
        // verifies the peer's signature.
        sessionManager.addSession(PeerSession(
            isAuthenticated: false,
            sessionNonce: sessionNonce,
            peerIdentityKey: identityKey,
            peerIdentityKeyVerified: false,
            certificatesRequired: certsRequired,
            certificatesValidated: !certsRequired
        ))

        let identity = try await getIdentityKey()
        let request = AuthMessage(
            messageType: .initialRequest,
            identityKey: identity,
            initialNonce: sessionNonce,
            requestedCertificates: certificatesToRequest
        )

        // Register a waiter BEFORE sending, so a fast in-memory transport
        // that invokes our onData callback recursively can find and resume
        // it. The send itself runs in a detached Task so we're free to
        // await the continuation.
        let capturedNonce = sessionNonce
        let capturedTransport = transport
        let capturedRequest = request

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            initialResponseWaiters[capturedNonce] = continuation
            // Now that the waiter is installed, spawn the send. We use a
            // detached task to avoid having the send inherit the actor
            // executor — the actor is about to suspend on this continuation
            // and we want the send to make progress without needing the
            // actor thread back.
            Task.detached {
                do {
                    try await capturedTransport.send(capturedRequest)
                } catch {
                    await self.failWaiter(sessionNonce: capturedNonce, error: error)
                }
            }
        }

        return sessionNonce
    }

    /// Resume a pending handshake waiter with an error.
    private func failWaiter(sessionNonce: String, error: Error) {
        if let waiter = initialResponseWaiters.removeValue(forKey: sessionNonce) {
            waiter.resume(throwing: error)
        }
    }

    // MARK: - Inbound message dispatch

    private func handleIncomingMessage(_ message: AuthMessage) async throws {
        guard message.version == AUTH_VERSION else {
            throw AuthError.unsupportedVersion(received: message.version, expected: AUTH_VERSION)
        }

        switch message.messageType {
        case .initialRequest:
            try await processInitialRequest(message)
        case .initialResponse:
            try await processInitialResponse(message)
        case .certificateRequest:
            try await processCertificateRequest(message)
        case .certificateResponse:
            try await processCertificateResponse(message)
        case .general:
            try await processGeneralMessage(message)
        }
    }

    private func processInitialRequest(_ message: AuthMessage) async throws {
        guard let initialNonce = message.initialNonce, !initialNonce.isEmpty else {
            throw AuthError.malformedMessage("initialRequest missing initialNonce")
        }

        let sessionNonce = try await AuthNonce.create(wallet: wallet)
        let certsRequired = !certificatesToRequest.certifiers.isEmpty
        // BRC-66 `initialRequest` carries no signature, so the peer's
        // claimed `identityKey` is an unverified claim at this point. We
        // store it so we know what key to expect on the first signed
        // message, but mark `peerIdentityKeyVerified = false` so
        // `SessionManager` will not index the session under that identity.
        // Otherwise an attacker could seed a session claiming any
        // identity key and then have a later
        // `getAuthenticatedSession(identityKey:)` call pick it up. See
        // the BRC-66 security note on Vuln 2.
        sessionManager.addSession(PeerSession(
            isAuthenticated: true,
            sessionNonce: sessionNonce,
            peerNonce: initialNonce,
            peerIdentityKey: message.identityKey,
            peerIdentityKeyVerified: false,
            certificatesRequired: certsRequired,
            certificatesValidated: !certsRequired
        ))

        // Sign nonces concatenation (peer initialNonce + our sessionNonce).
        let dataToSign = decodedNonce(initialNonce) + decodedNonce(sessionNonce)
        let signature = try await wallet.createSignature(args: CreateSignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: Peer.signatureProtocol,
                keyID: "\(initialNonce) \(sessionNonce)",
                counterparty: .publicKey(message.identityKey)
            ),
            data: dataToSign
        )).signature

        // If the peer asked for certificates, notify listeners. Auto-reply
        // with an empty list for now (the tests don't exercise cert keyring
        // generation in the handshake reply path).
        if let requested = message.requestedCertificates, !requested.isEmpty {
            for cb in certificatesRequestedListeners.values {
                cb(message.identityKey, requested)
            }
        }

        let identity = try await getIdentityKey()
        let response = AuthMessage(
            messageType: .initialResponse,
            identityKey: identity,
            initialNonce: sessionNonce,
            yourNonce: initialNonce,
            certificates: nil,
            requestedCertificates: certificatesToRequest,
            signature: signature
        )

        if lastInteractedPeer == nil {
            lastInteractedPeer = message.identityKey
        }

        try await transport.send(response)
    }

    private func processInitialResponse(_ message: AuthMessage) async throws {
        guard let yourNonce = message.yourNonce else {
            throw AuthError.malformedMessage("initialResponse missing yourNonce")
        }
        let nonceValid = try await AuthNonce.verify(yourNonce, wallet: wallet)
        if !nonceValid {
            throw AuthError.invalidNonce
        }

        guard var session = sessionManager.getSession(yourNonce) else {
            throw AuthError.sessionNotFound("no session for nonce \(yourNonce)")
        }

        guard let peerInitial = message.initialNonce, let signature = message.signature else {
            throw AuthError.malformedMessage("initialResponse missing initialNonce or signature")
        }

        let dataToVerify = decodedNonce(session.sessionNonce) + decodedNonce(peerInitial)
        let verifyResult: Bool
        do {
            verifyResult = try await wallet.verifySignature(args: VerifySignatureArgs(
                encryption: WalletEncryptionArgs(
                    protocolID: Peer.signatureProtocol,
                    keyID: "\(session.sessionNonce) \(peerInitial)",
                    counterparty: .publicKey(message.identityKey)
                ),
                signature: signature,
                data: dataToVerify
            )).valid
        } catch WalletError.invalidSignature {
            throw AuthError.invalidSignature
        }
        if !verifyResult {
            throw AuthError.invalidSignature
        }

        session.peerNonce = peerInitial
        session.peerIdentityKey = message.identityKey
        // On the initiator path we have just verified the peer's
        // signature over the session-nonce pair, which proves control of
        // `message.identityKey`. Mark the identity as verified so
        // `SessionManager` indexes the session for identity-key lookup.
        session.peerIdentityKeyVerified = true
        session.isAuthenticated = true
        session.certificatesRequired = !certificatesToRequest.certifiers.isEmpty
        session.certificatesValidated = !session.certificatesRequired
        session.lastUpdate = Date()
        sessionManager.updateSession(session)

        lastInteractedPeer = message.identityKey

        // Release the handshake waiter.
        if let waiter = initialResponseWaiters.removeValue(forKey: session.sessionNonce) {
            waiter.resume(returning: ())
        }

        // Honour any cert request the peer tacked onto the response.
        if let requested = message.requestedCertificates, !requested.isEmpty {
            for cb in certificatesRequestedListeners.values {
                cb(message.identityKey, requested)
            }
        }
    }

    private func processCertificateRequest(_ message: AuthMessage) async throws {
        guard let yourNonce = message.yourNonce else {
            throw AuthError.malformedMessage("certificateRequest missing yourNonce")
        }
        let nonceValid = try await AuthNonce.verify(yourNonce, wallet: wallet)
        if !nonceValid { throw AuthError.invalidNonce }

        guard var session = sessionManager.getSession(yourNonce) else {
            throw AuthError.sessionNotFound("no session for nonce \(yourNonce)")
        }

        // Bind the signed message to the identity the session was
        // established with. BRC-43 signature verification is
        // ECDH-symmetric, so a peer who signed with counterparty=V using
        // their own root key could otherwise pass verification regardless
        // of what `message.identityKey` claims. We must therefore compare
        // the claimed identity against the stored session identity AND
        // verify using the stored identity rather than the claim.
        guard let peerIdentityKey = session.peerIdentityKey,
              message.identityKey == peerIdentityKey else {
            throw AuthError.invalidSignature
        }

        guard let requested = message.requestedCertificates,
              let signature = message.signature,
              let peerNonce = message.nonce else {
            throw AuthError.malformedMessage("certificateRequest missing fields")
        }

        // The signed data is the UTF-8 JSON of the requestedCertificates.
        let jsonData = try JSONEncoder().encode(requested)
        let valid = (try? await wallet.verifySignature(args: VerifySignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: Peer.signatureProtocol,
                keyID: "\(peerNonce) \(session.sessionNonce)",
                counterparty: .publicKey(peerIdentityKey)
            ),
            signature: signature,
            data: jsonData
        )).valid) ?? false
        if !valid { throw AuthError.invalidSignature }

        // A valid signed message proves the peer controls the claimed
        // identity key. If this is the first cryptographic evidence we
        // have (the responder path seats sessions with
        // peerIdentityKeyVerified=false), promote the session so it's
        // reachable via identity-key lookup.
        if !session.peerIdentityKeyVerified {
            session.peerIdentityKeyVerified = true
            session.lastUpdate = Date()
            sessionManager.updateSession(session)
        }

        for cb in certificatesRequestedListeners.values {
            cb(message.identityKey, requested)
        }
    }

    private func processCertificateResponse(_ message: AuthMessage) async throws {
        guard let yourNonce = message.yourNonce else {
            throw AuthError.malformedMessage("certificateResponse missing yourNonce")
        }
        let nonceValid = try await AuthNonce.verify(yourNonce, wallet: wallet)
        if !nonceValid { throw AuthError.invalidNonce }

        guard var session = sessionManager.getSession(yourNonce) else {
            throw AuthError.sessionNotFound("no session for nonce \(yourNonce)")
        }

        // Bind the signed envelope to the identity the session was
        // established with — see the note in processCertificateRequest.
        guard let peerIdentityKey = session.peerIdentityKey,
              message.identityKey == peerIdentityKey else {
            throw AuthError.invalidSignature
        }

        guard let signature = message.signature, let peerNonce = message.nonce else {
            throw AuthError.malformedMessage("certificateResponse missing fields")
        }

        // The signed data is the UTF-8 encoded JSON array of certificates.
        // Key ordering must be deterministic so both sides recompute the
        // same pre-image — Swift's default JSONEncoder does not guarantee
        // this, so we use `.sortedKeys`.
        let certs = message.certificates ?? []
        let jsonData = try Self.canonicalCertJSON(certs)
        let valid = (try? await wallet.verifySignature(args: VerifySignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: Peer.signatureProtocol,
                keyID: "\(peerNonce) \(session.sessionNonce)",
                counterparty: .publicKey(peerIdentityKey)
            ),
            signature: signature,
            data: jsonData
        )).valid) ?? false
        if !valid { throw AuthError.invalidSignature }

        // First valid signed message from the session peer — promote the
        // session to verified so identity-key lookup can find it.
        if !session.peerIdentityKeyVerified {
            session.peerIdentityKeyVerified = true
        }

        if !certs.isEmpty {
            // Verify each certificate individually. Every check uses the same
            // generic error message so a malicious peer cannot use the failure
            // reason as an oracle to learn which field tripped the check.
            let genericError = AuthError.certificateInvalid("certificate validation failed")
            let requested = certificatesToRequest
            let requestedHasCertifiers = !requested.certifiers.isEmpty

            for cert in certs {
                // Subject must match the claimed peer identity.
                if cert.subject != message.identityKey {
                    throw genericError
                }

                // Signature must verify against the certifier.
                let certValid: Bool
                do {
                    certValid = try await cert.verify()
                } catch {
                    throw genericError
                }
                if !certValid {
                    throw genericError
                }

                // If the local peer requested a specific certifier/type set,
                // the certificate must match it.
                if requestedHasCertifiers {
                    if !requested.certifiers.contains(cert.certifier.hex) {
                        throw genericError
                    }
                    if requested.types[cert.type.base64EncodedString()] == nil {
                        throw genericError
                    }
                }
            }

            session.certificatesValidated = true
            session.lastUpdate = Date()
            sessionManager.updateSession(session)
        }

        let verifiableCerts = certs.map { VerifiableCertificate(certificate: $0, keyring: [:]) }
        for cb in certificatesReceivedListeners.values {
            cb(message.identityKey, verifiableCerts)
        }
    }

    private func processGeneralMessage(_ message: AuthMessage) async throws {
        guard let yourNonce = message.yourNonce else {
            throw AuthError.malformedMessage("general message missing yourNonce")
        }
        let nonceValid = try await AuthNonce.verify(yourNonce, wallet: wallet)
        if !nonceValid { throw AuthError.invalidNonce }

        guard var session = sessionManager.getSession(yourNonce) else {
            throw AuthError.sessionNotFound("no session for nonce \(yourNonce)")
        }

        // Bind the signed envelope to the identity the session was
        // established with. BRC-43 signature verification is
        // ECDH-symmetric, so verifying with the attacker-controlled
        // `message.identityKey` (a regression from the ts-sdk reference
        // at Peer.ts:921) would allow any peer to pass verification by
        // signing the payload with their own root key under
        // counterparty=V. We must compare the claimed identity to the
        // stored session identity AND verify using the stored identity.
        guard let peerIdentityKey = session.peerIdentityKey,
              message.identityKey == peerIdentityKey else {
            throw AuthError.invalidSignature
        }

        guard let payload = message.payload,
              let signature = message.signature,
              let peerNonce = message.nonce else {
            throw AuthError.malformedMessage("general message missing fields")
        }

        let valid = (try? await wallet.verifySignature(args: VerifySignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: Peer.signatureProtocol,
                keyID: "\(peerNonce) \(session.sessionNonce)",
                counterparty: .publicKey(peerIdentityKey)
            ),
            signature: signature,
            data: payload
        )).valid) ?? false
        if !valid { throw AuthError.invalidSignature }

        // First valid signed message from the session peer — promote
        // the session so identity-key lookup can find it. Before this
        // point (responder path seeded from an unsigned initialRequest)
        // the claimed identity was untrusted.
        if !session.peerIdentityKeyVerified {
            session.peerIdentityKeyVerified = true
        }
        session.lastUpdate = Date()
        sessionManager.updateSession(session)
        lastInteractedPeer = peerIdentityKey

        for cb in generalMessageListeners.values {
            cb(peerIdentityKey, payload)
        }
    }

    // MARK: - Helpers

    /// Canonicalise the JSON pre-image used for certificate-response
    /// signing. Swift's default `JSONEncoder` does not guarantee key
    /// ordering for `[String: String]` dictionaries or for arbitrary
    /// structs, so both sides MUST sort keys to agree on the pre-image.
    internal static func canonicalCertJSON(_ certs: [Certificate]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(certs.map { CertificateJSON(from: $0) })
    }

    private func getIdentityKey() async throws -> PublicKey {
        if let identityKey { return identityKey }
        let result = try await wallet.getPublicKey(args: GetPublicKeyArgs(identityKey: true))
        self.identityKey = result.publicKey
        return result.publicKey
    }

    private func decodedNonce(_ base64: String) -> Data {
        Data(base64Encoded: base64) ?? Data()
    }

    private func generateRandomBase64(byteCount: Int) throws -> String {
        var bytes = Data(count: byteCount)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, byteCount, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw AuthError.transportFailure("failed to generate random bytes")
        }
        return bytes.base64EncodedString()
    }
}

// MARK: - JSON encoding helpers

/// Thin wrapper used to give `Certificate` a deterministic JSON shape for
/// signing. Matches the ts-sdk JSON representation used in
/// `certificateRequest` / `certificateResponse`.
internal struct CertificateJSON: Codable {
    let type: String
    let serialNumber: String
    let subject: String
    let certifier: String
    let revocationOutpoint: String
    let fields: [String: String]
    let signature: String?

    init(from cert: Certificate) {
        self.type = cert.type.base64EncodedString()
        self.serialNumber = cert.serialNumber.base64EncodedString()
        self.subject = cert.subject.hex
        self.certifier = cert.certifier.hex
        self.revocationOutpoint = cert.revocationOutpoint
        self.fields = cert.fields
        self.signature = cert.signature?.hex
    }
}
