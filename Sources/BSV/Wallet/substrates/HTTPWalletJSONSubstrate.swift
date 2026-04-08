import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A `WalletSubstrate` that POSTs JSON to `<baseURL>/<method>` over HTTP.
///
/// Matches the wire format of the ts-sdk `HTTPWalletJSON` substrate. On a 2xx
/// response whose body contains `{"status":"error",...}` it raises a
/// `WalletError` that mirrors the remote wallet's error code and name.
public struct HTTPWalletJSONSubstrate: WalletSubstrate {
    public let baseURL: URL
    public let session: URLSession

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    public func invoke(method: String, body: Data, originator: String?) async throws -> Data {
        let url = baseURL.appendingPathComponent(method)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let originator {
            // The remote wallet uses this to scope permissions to the caller.
            request.setValue(originator, forHTTPHeaderField: "Originator")
        }
        request.httpBody = body

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw WalletError.transportFailure("non-HTTP response from \(url)")
        }

        // Try to detect an error envelope regardless of HTTP status code.
        if let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let status = payload["status"] as? String, status == "error" {
            let message = (payload["description"] as? String)
                ?? (payload["message"] as? String)
                ?? "remote wallet error"
            let code = payload["code"] as? Int ?? 1
            throw Self.walletError(for: code, message: message)
        }

        guard (200..<300).contains(http.statusCode) else {
            throw WalletError.transportFailure(
                "HTTP \(http.statusCode) from \(url)"
            )
        }

        return data
    }

    /// Map a ts-sdk `walletErrors` numeric code to a Swift `WalletError` case.
    private static func walletError(for code: Int, message: String) -> WalletError {
        switch code {
        case 2: return .unsupportedAction(message)
        case 3: return .invalidHmac
        case 4: return .invalidSignature
        case 5: return .reviewActions(message: message)
        case 6: return .invalidParameter(name: "unknown", message: message)
        case 7: return .insufficientFunds(totalSatoshisNeeded: 0, moreSatoshisNeeded: 0)
        default: return .unknown(message)
        }
    }
}
