import Foundation

/// A transport that ferries BRC-100 JSON-shaped wallet calls to an external wallet.
///
/// Substrates are responsible for framing, transport, authentication with the
/// wallet process, and translating any wire-level errors into `WalletError`.
/// They receive JSON argument bodies and return JSON result bodies — semantic
/// decoding is done by `WalletClient`.
public protocol WalletSubstrate: Sendable {
    /// Invoke a BRC-100 method by name, passing a JSON argument payload.
    ///
    /// - Parameters:
    ///   - method: The BRC-100 method name (e.g. `"getPublicKey"`).
    ///   - body: The encoded JSON argument payload.
    ///   - originator: The FQDN of the calling application, if any.
    /// - Returns: The raw JSON response body from the remote wallet.
    /// - Throws: `WalletError` on transport, protocol, or decode failures.
    func invoke(method: String, body: Data, originator: String?) async throws -> Data
}
