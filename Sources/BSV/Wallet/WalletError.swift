import Foundation

/// Errors thrown by wallet operations.
///
/// Mirrors the ts-sdk `WERR_*` hierarchy. The underlying `code` values match
/// the ts-sdk `walletErrors` enum so wire protocols can round-trip the code.
public enum WalletError: Error, Equatable, Sendable {
    case unknown(String)
    case unsupportedAction(String)
    case invalidHmac
    case invalidSignature
    case reviewActions(message: String)
    case invalidParameter(name: String, message: String)
    case insufficientFunds(totalSatoshisNeeded: Int, moreSatoshisNeeded: Int)
    case keyDeriverUnavailable
    case transportFailure(String)

    /// Numeric error code matching the ts-sdk `walletErrors` enum.
    public var code: Int {
        switch self {
        case .unknown, .keyDeriverUnavailable, .transportFailure: return 1
        case .unsupportedAction: return 2
        case .invalidHmac: return 3
        case .invalidSignature: return 4
        case .reviewActions: return 5
        case .invalidParameter: return 6
        case .insufficientFunds: return 7
        }
    }

    /// A human-readable name matching the ts-sdk `WERR_*` class names.
    public var name: String {
        switch self {
        case .unknown, .keyDeriverUnavailable, .transportFailure: return "WERR_UNKNOWN"
        case .unsupportedAction: return "WERR_UNSUPPORTED_ACTION"
        case .invalidHmac: return "WERR_INVALID_HMAC"
        case .invalidSignature: return "WERR_INVALID_SIGNATURE"
        case .reviewActions: return "WERR_REVIEW_ACTIONS"
        case .invalidParameter: return "WERR_INVALID_PARAMETER"
        case .insufficientFunds: return "WERR_INSUFFICIENT_FUNDS"
        }
    }
}

extension WalletError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unknown(let message): return message
        case .unsupportedAction(let message): return message
        case .invalidHmac: return "HMAC is not valid"
        case .invalidSignature: return "Signature is not valid"
        case .reviewActions(let message): return message
        case .invalidParameter(let name, let message): return "Invalid parameter \(name): \(message)"
        case .insufficientFunds(let needed, let more):
            return "Insufficient funds: need \(needed) sats, short \(more) sats"
        case .keyDeriverUnavailable: return "keyDeriver is undefined"
        case .transportFailure(let message): return "Transport failure: \(message)"
        }
    }
}
