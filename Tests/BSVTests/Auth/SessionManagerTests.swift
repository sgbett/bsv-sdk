import XCTest
@testable import BSV

final class SessionManagerTests: XCTestCase {

    private func makeSession(
        sessionNonce: String,
        identity: PrivateKey? = nil,
        authenticated: Bool = true,
        lastUpdate: Date = Date()
    ) -> PeerSession {
        let peerIdentity = identity.map { PublicKey.fromPrivateKey($0) }
        return PeerSession(
            isAuthenticated: authenticated,
            sessionNonce: sessionNonce,
            peerIdentityKey: peerIdentity,
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
}
