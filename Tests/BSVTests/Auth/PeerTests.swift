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
