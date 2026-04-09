import XCTest
@testable import BSV

final class SessionManagerTests: XCTestCase {

    private func makeSession(
        sessionNonce: String,
        identity: PrivateKey? = nil,
        authenticated: Bool = true,
        peerIdentityKeyVerified: Bool = true,
        lastUpdate: Date = Date()
    ) -> PeerSession {
        let peerIdentity = identity.map { PublicKey.fromPrivateKey($0) }
        return PeerSession(
            isAuthenticated: authenticated,
            sessionNonce: sessionNonce,
            peerIdentityKey: peerIdentity,
            peerIdentityKeyVerified: peerIdentityKeyVerified,
            lastUpdate: lastUpdate
        )
    }

    func testLookupBySessionNonce() {
        let manager = SessionManager()
        let session = makeSession(sessionNonce: "nonce-1")
        manager.addSession(session)

        let fetched = manager.getSession("nonce-1")
        XCTAssertNotNil(fetched)
        XCTAssertEqual(fetched?.sessionNonce, "nonce-1")
    }

    func testLookupByIdentityKey() {
        let manager = SessionManager()
        let identity = PrivateKey.random()!
        let session = makeSession(sessionNonce: "s1", identity: identity)
        manager.addSession(session)

        let fetchedByHex = manager.getSession(PublicKey.fromPrivateKey(identity).hex)
        XCTAssertEqual(fetchedByHex?.sessionNonce, "s1")
    }

    func testMostRecentSessionWinsForDuplicateIdentity() {
        let manager = SessionManager()
        let identity = PrivateKey.random()!
        let older = Date(timeIntervalSince1970: 1000)
        let newer = Date(timeIntervalSince1970: 2000)

        manager.addSession(makeSession(sessionNonce: "old", identity: identity, lastUpdate: older))
        manager.addSession(makeSession(sessionNonce: "new", identity: identity, lastUpdate: newer))

        let fetched = manager.getSession(PublicKey.fromPrivateKey(identity).hex)
        XCTAssertEqual(fetched?.sessionNonce, "new")
    }

    func testRemoveSession() {
        let manager = SessionManager()
        let identity = PrivateKey.random()!
        let session = makeSession(sessionNonce: "remove-me", identity: identity)
        manager.addSession(session)

        XCTAssertTrue(manager.hasSession("remove-me"))
        manager.removeSession(session)
        XCTAssertFalse(manager.hasSession("remove-me"))
        XCTAssertNil(manager.getSession(PublicKey.fromPrivateKey(identity).hex))
    }

    func testUpdateSessionReplacesIdentityIndexWhenChanged() {
        let manager = SessionManager()
        let originalIdentity = PrivateKey.random()!
        let newIdentity = PrivateKey.random()!

        var session = makeSession(sessionNonce: "mut", identity: originalIdentity)
        manager.addSession(session)

        session.peerIdentityKey = PublicKey.fromPrivateKey(newIdentity)
        manager.updateSession(session)

        XCTAssertNil(manager.getSession(PublicKey.fromPrivateKey(originalIdentity).hex))
        XCTAssertEqual(
            manager.getSession(PublicKey.fromPrivateKey(newIdentity).hex)?.sessionNonce,
            "mut"
        )
    }

    // MARK: - Vuln 2: identity-key indexing requires verification

    /// A session with `peerIdentityKeyVerified = false` (e.g. created from
    /// an unsigned BRC-66 `initialRequest`) must be reachable by nonce but
    /// NOT by identity-key lookup. Otherwise an attacker could seed a
    /// session claiming any identity key and have a later
    /// `getSession(<victim identity hex>)` call return it.
    func testUnverifiedSessionIsNotIndexedByIdentity() {
        let manager = SessionManager()
        let victim = PrivateKey.random()!
        let session = makeSession(
            sessionNonce: "attacker-seeded",
            identity: victim,
            peerIdentityKeyVerified: false
        )
        manager.addSession(session)

        // Nonce lookup still works — it's how the BRC-66 handshake
        // continues processing messages in this session.
        XCTAssertNotNil(manager.getSession("attacker-seeded"))

        // Identity lookup must not find it.
        XCTAssertNil(manager.getSession(PublicKey.fromPrivateKey(victim).hex))
    }

    /// Identity-key lookup must only return sessions that have been
    /// verified. When both a claimed-only and a verified session exist
    /// for the same identity key, only the verified one should be
    /// reachable via identity lookup.
    func testIdentityLookupOnlyReturnsVerifiedSessions() {
        let manager = SessionManager()
        let identity = PrivateKey.random()!
        let identityHex = PublicKey.fromPrivateKey(identity).hex

        // Attacker-seeded (responder path, unsigned initialRequest).
        let unverified = makeSession(
            sessionNonce: "unverified",
            identity: identity,
            peerIdentityKeyVerified: false,
            lastUpdate: Date(timeIntervalSince1970: 2_000)
        )
        // Legitimate (initiator path — signature verified).
        let verified = makeSession(
            sessionNonce: "verified",
            identity: identity,
            peerIdentityKeyVerified: true,
            lastUpdate: Date(timeIntervalSince1970: 1_000)
        )
        manager.addSession(unverified)
        manager.addSession(verified)

        // Even though the unverified session is more recent, only the
        // verified one is reachable by identity-key lookup.
        XCTAssertEqual(manager.getSession(identityHex)?.sessionNonce, "verified")
    }
}
