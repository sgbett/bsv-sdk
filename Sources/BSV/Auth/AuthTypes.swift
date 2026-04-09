import Foundation

/// Current BRC-66 authentication protocol version supported by this SDK.
public let AUTH_VERSION = "0.1"

/// The kind of message exchanged during a BRC-66 handshake / general session.
public enum AuthMessageType: String, Sendable, Codable {
    case initialRequest
    case initialResponse
    case certificateRequest
    case certificateResponse
    case general
}

/// A structured description of the certificates a peer wishes to receive
/// during the handshake.
///
/// `certifiers` is a list of hex-encoded public keys identifying acceptable
/// certificate issuers, and `types` maps certificate type (base64) to the
/// list of field names the peer wants to see.
public struct RequestedCertificateSet: Sendable, Equatable, Codable {
    public var certifiers: [String]
    public var types: [String: [String]]

    public init(certifiers: [String] = [], types: [String: [String]] = [:]) {
        self.certifiers = certifiers
        self.types = types
    }

    /// Convenience: is this request "empty"?
    public var isEmpty: Bool { certifiers.isEmpty }
}

/// A BRC-66 authentication message exchanged over a transport.
///
/// Field presence depends on the `messageType`:
/// - `initialRequest`: `identityKey`, `initialNonce`, optional `requestedCertificates`
/// - `initialResponse`: `identityKey`, `initialNonce`, `yourNonce`, `signature`, optional certs
/// - `certificateRequest`: `identityKey`, `nonce`, `yourNonce`, `requestedCertificates`, `signature`
/// - `certificateResponse`: `identityKey`, `nonce`, `yourNonce`, `certificates`, `signature`
/// - `general`: `identityKey`, `nonce`, `yourNonce`, `payload`, `signature`
public struct AuthMessage: Sendable, Equatable {
    public var version: String
    public var messageType: AuthMessageType
    public var identityKey: PublicKey
    public var nonce: String?
    public var initialNonce: String?
    public var yourNonce: String?
    public var certificates: [Certificate]?
    public var requestedCertificates: RequestedCertificateSet?
    public var payload: Data?
    public var signature: Data?

    public init(
        version: String = AUTH_VERSION,
        messageType: AuthMessageType,
        identityKey: PublicKey,
        nonce: String? = nil,
        initialNonce: String? = nil,
        yourNonce: String? = nil,
        certificates: [Certificate]? = nil,
        requestedCertificates: RequestedCertificateSet? = nil,
        payload: Data? = nil,
        signature: Data? = nil
    ) {
        self.version = version
        self.messageType = messageType
        self.identityKey = identityKey
        self.nonce = nonce
        self.initialNonce = initialNonce
        self.yourNonce = yourNonce
        self.certificates = certificates
        self.requestedCertificates = requestedCertificates
        self.payload = payload
        self.signature = signature
    }
}

/// A BRC-66 session tracked by a `Peer`.
///
/// Sessions are keyed by `sessionNonce` in `SessionManager` and additionally
/// indexed by `peerIdentityKey` so that callers can look one up by either.
///
/// `peerIdentityKeyVerified` distinguishes a *claimed* peer identity (e.g.
/// an unsigned `initialRequest` where the peer told us its key but we
/// haven't checked anything) from a *verified* one (a signed message has
/// been received that proves control of the claimed key). Only verified
/// sessions are reachable via identity-key lookup; claimed-only sessions
/// can only be found by `sessionNonce`, which prevents an attacker from
/// seeding a session under a victim's identity and then hijacking a later
/// `getAuthenticatedSession(identityKey:)` lookup.
public struct PeerSession: Sendable, Equatable {
    public var isAuthenticated: Bool
    public var sessionNonce: String
    public var peerNonce: String?
    public var peerIdentityKey: PublicKey?
    public var peerIdentityKeyVerified: Bool
    public var lastUpdate: Date
    public var certificatesRequired: Bool
    public var certificatesValidated: Bool

    public init(
        isAuthenticated: Bool,
        sessionNonce: String,
        peerNonce: String? = nil,
        peerIdentityKey: PublicKey? = nil,
        peerIdentityKeyVerified: Bool = false,
        lastUpdate: Date = Date(),
        certificatesRequired: Bool = false,
        certificatesValidated: Bool = true
    ) {
        self.isAuthenticated = isAuthenticated
        self.sessionNonce = sessionNonce
        self.peerNonce = peerNonce
        self.peerIdentityKey = peerIdentityKey
        self.peerIdentityKeyVerified = peerIdentityKeyVerified
        self.lastUpdate = lastUpdate
        self.certificatesRequired = certificatesRequired
        self.certificatesValidated = certificatesValidated
    }
}

/// Transport abstraction used by `Peer` to send and receive `AuthMessage`s.
///
/// Mirrors the ts-sdk `Transport` interface: `send` dispatches an outbound
/// message, and `onData` registers a callback invoked for every inbound
/// message.
///
/// Implementations are expected to be `Sendable` so they can be held by the
/// actor-isolated `Peer`.
public protocol Transport: Sendable {
    /// Send an authenticated message to the remote peer.
    func send(_ message: AuthMessage) async throws

    /// Register a callback to receive inbound messages.
    ///
    /// The callback is async and may itself perform work that dispatches
    /// further outbound messages (e.g. responding to a handshake).
    func onData(_ callback: @escaping @Sendable (AuthMessage) async throws -> Void) async throws
}
