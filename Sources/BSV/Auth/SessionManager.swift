import Foundation

/// Thread-safe BRC-66 session tracker.
///
/// Sessions are keyed by their unique `sessionNonce`, and a secondary index
/// keeps track of which session(s) belong to a given `peerIdentityKey` so the
/// lookup `getSession(:)` can accept either a nonce or an identity key.
///
/// Multiple simultaneous sessions per peer are allowed; `getSession(byIdentity:)`
/// returns the most recently updated one.
public final class SessionManager: @unchecked Sendable {
    private let lock = NSLock()
    private var sessionsByNonce: [String: PeerSession] = [:]
    private var nonceByIdentity: [String: Set<String>] = [:]

    public init() {}

    /// Insert or update a session, re-indexing the identity lookup if needed.
    public func addSession(_ session: PeerSession) {
        lock.lock()
        defer { lock.unlock() }
        upsertLocked(session)
    }

    /// Refresh an existing session. If no session exists with this nonce, it
    /// is inserted (matching the ts-sdk behaviour).
    public func updateSession(_ session: PeerSession) {
        lock.lock()
        defer { lock.unlock() }
        upsertLocked(session)
    }

    /// Look up a session by nonce or by peer identity key (compressed hex).
    ///
    /// When `key` matches a stored `sessionNonce` the corresponding session
    /// is returned. Otherwise the key is treated as a peer identity hex and
    /// the most recently updated session for that peer is returned.
    public func getSession(_ key: String) -> PeerSession? {
        lock.lock()
        defer { lock.unlock() }
        if let direct = sessionsByNonce[key] {
            return direct
        }
        guard let nonces = nonceByIdentity[key.lowercased()] else { return nil }
        var latest: PeerSession?
        for nonce in nonces {
            guard let candidate = sessionsByNonce[nonce] else { continue }
            if latest == nil || candidate.lastUpdate > latest!.lastUpdate {
                latest = candidate
            }
        }
        return latest
    }

    /// Does a session exist for this nonce or identity key?
    public func hasSession(_ key: String) -> Bool {
        getSession(key) != nil
    }

    /// Remove a session and any associated identity-index entries.
    public func removeSession(_ session: PeerSession) {
        lock.lock()
        defer { lock.unlock() }
        sessionsByNonce.removeValue(forKey: session.sessionNonce)
        if let identity = session.peerIdentityKey?.hex.lowercased() {
            nonceByIdentity[identity]?.remove(session.sessionNonce)
            if nonceByIdentity[identity]?.isEmpty == true {
                nonceByIdentity.removeValue(forKey: identity)
            }
        }
    }

    // MARK: - Internal

    private func upsertLocked(_ session: PeerSession) {
        // Clear previous identity index for this nonce (in case the peer's
        // identity changed during an upgrade from unauthenticated to
        // authenticated).
        if let existing = sessionsByNonce[session.sessionNonce],
           let oldIdentity = existing.peerIdentityKey?.hex.lowercased() {
            nonceByIdentity[oldIdentity]?.remove(session.sessionNonce)
            if nonceByIdentity[oldIdentity]?.isEmpty == true {
                nonceByIdentity.removeValue(forKey: oldIdentity)
            }
        }

        sessionsByNonce[session.sessionNonce] = session

        // Only index a session under its peer identity once we have
        // cryptographic evidence the peer controls that key. Sessions
        // created from an unsigned `initialRequest` carry only a
        // self-asserted identity claim, and must therefore not be
        // reachable via identity-key lookup — otherwise a later
        // `getSession(<victim identity>)` could return an attacker-seeded
        // session. See BRC-66 security note on Vuln 2.
        if session.peerIdentityKeyVerified,
           let identity = session.peerIdentityKey?.hex.lowercased() {
            nonceByIdentity[identity, default: []].insert(session.sessionNonce)
        }
    }
}
