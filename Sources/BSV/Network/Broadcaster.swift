import Foundation

/// Result of a successful transaction broadcast.
public struct BroadcastResponse: Sendable, Equatable {
    /// The transaction ID as reported by the broadcaster (display order hex).
    public let txid: String
    /// The current status of the transaction (broadcaster-specific).
    public let status: String
    /// Optional human-readable description or message.
    public let description: String?

    public init(txid: String, status: String, description: String? = nil) {
        self.txid = txid
        self.status = status
        self.description = description
    }
}

/// A broadcaster that can submit transactions to the BSV network.
public protocol Broadcaster {
    /// Broadcast a transaction.
    ///
    /// - Parameter transaction: The transaction to broadcast.
    /// - Returns: The broadcast response on success.
    /// - Throws: `BroadcasterError` on failure.
    func broadcast(_ transaction: Transaction) async throws -> BroadcastResponse
}

/// Errors that can occur during broadcasting.
public enum BroadcasterError: Error, LocalizedError {
    case invalidURL(String)
    case networkError(Error)
    case httpStatus(code: Int, body: String)
    case invalidResponse(String)
    case rejected(reason: String)

    public var errorDescription: String? {
        switch self {
        case .invalidURL(let url):
            return "Invalid URL: \(url)"
        case .networkError(let err):
            return "Network error: \(err.localizedDescription)"
        case .httpStatus(let code, let body):
            return "HTTP \(code): \(body)"
        case .invalidResponse(let msg):
            return "Invalid response: \(msg)"
        case .rejected(let reason):
            return "Transaction rejected: \(reason)"
        }
    }
}
