import Foundation

/// A ChainTracker verifies that a Merkle root is valid for a given block height.
public protocol ChainTracker {
    /// Verify that `root` is the Merkle root of the block at `height`.
    ///
    /// - Parameters:
    ///   - root: The Merkle root in internal byte order (32 bytes).
    ///   - height: The block height.
    /// - Returns: `true` if the root matches the recorded block header at that height.
    func isValidRootForHeight(root: Data, height: UInt32) async throws -> Bool

    /// Return the current best chain height.
    func currentHeight() async throws -> UInt32
}

/// Errors that can occur while interacting with a chain tracker.
public enum ChainTrackerError: Error, LocalizedError {
    case invalidURL(String)
    case networkError(Error)
    case httpStatus(code: Int)
    case notFound(height: UInt32)
    case invalidResponse(String)

    public var errorDescription: String? {
        switch self {
        case .invalidURL(let url):
            return "Invalid URL: \(url)"
        case .networkError(let err):
            return "Network error: \(err.localizedDescription)"
        case .httpStatus(let code):
            return "HTTP \(code)"
        case .notFound(let height):
            return "No block header for height \(height)"
        case .invalidResponse(let msg):
            return "Invalid response: \(msg)"
        }
    }
}
