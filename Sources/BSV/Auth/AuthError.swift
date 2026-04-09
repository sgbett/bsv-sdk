import Foundation

/// Errors raised by the BRC-66/103/104 authentication layer.
///
/// Mirrors the ts-sdk `auth` error taxonomy: nonce validation failures, signature
/// verification failures, session-lookup problems, and transport-level issues.
public enum AuthError: Error, Equatable, Sendable {
    /// The inbound `AuthMessage` used an unsupported `version` string.
    case unsupportedVersion(received: String, expected: String)

    /// A required field on the `AuthMessage` was missing or malformed.
    case malformedMessage(String)

    /// Nonce verification failed for the message. The nonce did not decode as
    /// a valid HMAC envelope signed by the local wallet.
    case invalidNonce

    /// Signature verification against the expected peer public key failed.
    case invalidSignature

    /// No session could be found for the supplied lookup key (session nonce
    /// or identity key).
    case sessionNotFound(String)

    /// Certificate signature or field validation failed.
    case certificateInvalid(String)

    /// Transport failed to send or receive an authenticated message.
    case transportFailure(String)

    /// Timed out waiting for an initial response or certificate validation.
    case timeout(String)

    /// A general / wrapped remote error.
    case remote(String)
}
