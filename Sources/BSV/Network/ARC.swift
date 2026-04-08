import Foundation

/// ARC (Arc Transaction Processor) broadcaster.
///
/// Posts a raw transaction to an ARC-compatible endpoint at `<apiURL>/v1/tx`
/// using the `application/octet-stream` content type.
public struct ARC: Broadcaster {
    /// The ARC API base URL, e.g. `https://arc.taal.com`.
    public let apiURL: String
    /// Optional bearer token used in the `Authorization` header.
    public let apiKey: String?
    /// Optional deployment ID sent via the `XDeployment-ID` header.
    public let deploymentID: String?
    /// Optional callback URL for push status updates.
    public let callbackURL: String?
    /// Optional callback token sent alongside the callback URL.
    public let callbackToken: String?
    /// URL session used for HTTP requests. Defaults to `URLSession.shared`.
    public let urlSession: URLSession

    public init(
        apiURL: String,
        apiKey: String? = nil,
        deploymentID: String? = nil,
        callbackURL: String? = nil,
        callbackToken: String? = nil,
        urlSession: URLSession = .shared
    ) {
        self.apiURL = apiURL
        self.apiKey = apiKey
        self.deploymentID = deploymentID
        self.callbackURL = callbackURL
        self.callbackToken = callbackToken
        self.urlSession = urlSession
    }

    // MARK: - Broadcaster

    public func broadcast(_ transaction: Transaction) async throws -> BroadcastResponse {
        guard let url = URL(string: apiURL + "/v1/tx") else {
            throw BroadcasterError.invalidURL(apiURL + "/v1/tx")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        if let apiKey {
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        if let deploymentID {
            request.setValue(deploymentID, forHTTPHeaderField: "XDeployment-ID")
        }
        if let callbackURL {
            request.setValue(callbackURL, forHTTPHeaderField: "X-CallbackUrl")
        }
        if let callbackToken {
            request.setValue(callbackToken, forHTTPHeaderField: "X-CallbackToken")
        }

        request.httpBody = transaction.toBinary()

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw BroadcasterError.networkError(error)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw BroadcasterError.invalidResponse("Not an HTTPURLResponse")
        }

        return try ARC.parseResponse(data: data, statusCode: httpResponse.statusCode)
    }

    // MARK: - Response parsing

    /// Parse an ARC JSON response body into a `BroadcastResponse`.
    ///
    /// - ARC returns `200 OK` on success with at least `{ "txid": "...", "txStatus": "..." }`
    /// - Failures are returned as HTTP errors with a JSON body containing `title`, `detail`, etc.
    static func parseResponse(data: Data, statusCode: Int) throws -> BroadcastResponse {
        let json: [String: Any]
        do {
            guard let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw BroadcasterError.invalidResponse("Response is not a JSON object")
            }
            json = parsed
        } catch let err as BroadcasterError {
            throw err
        } catch {
            throw BroadcasterError.invalidResponse("Failed to parse JSON: \(error.localizedDescription)")
        }

        if (200..<300).contains(statusCode) {
            guard let txid = json["txid"] as? String else {
                throw BroadcasterError.invalidResponse("Missing txid in response")
            }
            let status = (json["txStatus"] as? String) ?? "UNKNOWN"
            let detail = json["extraInfo"] as? String ?? json["title"] as? String
            return BroadcastResponse(txid: txid, status: status, description: detail)
        }

        // Error response.
        let title = json["title"] as? String ?? "Unknown error"
        let detail = json["detail"] as? String
        let message = detail.map { "\(title): \($0)" } ?? title
        throw BroadcasterError.rejected(reason: message)
    }
}
