import Foundation

/// The BSV network that a chain tracker queries.
public enum BSVNetwork: String, Sendable {
    case mainnet = "main"
    case testnet = "test"
}

/// A ChainTracker that queries the WhatsOnChain API to validate Merkle roots.
public struct WhatsOnChainTracker: ChainTracker {
    /// The network being queried.
    public let network: BSVNetwork
    /// Optional API key sent in the `Authorization` header.
    public let apiKey: String?
    /// URL session used for HTTP requests.
    public let urlSession: URLSession

    /// Base URL for the WhatsOnChain API.
    public var baseURL: String {
        "https://api.whatsonchain.com/v1/bsv/\(network.rawValue)"
    }

    public init(
        network: BSVNetwork = .mainnet,
        apiKey: String? = nil,
        urlSession: URLSession = .shared
    ) {
        self.network = network
        self.apiKey = apiKey
        self.urlSession = urlSession
    }

    // MARK: - ChainTracker

    public func isValidRootForHeight(root: Data, height: UInt32) async throws -> Bool {
        let header = try await fetchBlockHeader(height: height)
        guard let merkleRootHex = header["merkleroot"] as? String,
              let merkleRootDisplay = Data(hex: merkleRootHex)
        else {
            throw ChainTrackerError.invalidResponse("Missing or invalid merkleroot field")
        }
        // WhatsOnChain returns merkleroot in display (big-endian) hex;
        // convert to internal byte order for comparison.
        let merkleRootInternal = Data(merkleRootDisplay.reversed())
        return merkleRootInternal == root
    }

    public func currentHeight() async throws -> UInt32 {
        guard let url = URL(string: baseURL + "/chain/info") else {
            throw ChainTrackerError.invalidURL(baseURL + "/chain/info")
        }
        let data = try await performGET(url: url)

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let blocks = json["blocks"] as? Int
        else {
            throw ChainTrackerError.invalidResponse("Missing or invalid 'blocks' field")
        }
        return UInt32(blocks)
    }

    // MARK: - Helpers

    /// Fetch the block header JSON object for a given height.
    func fetchBlockHeader(height: UInt32) async throws -> [String: Any] {
        guard let url = URL(string: "\(baseURL)/block/\(height)/header") else {
            throw ChainTrackerError.invalidURL("\(baseURL)/block/\(height)/header")
        }
        let data = try await performGET(url: url, notFoundHeight: height)

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ChainTrackerError.invalidResponse("Response is not a JSON object")
        }
        return json
    }

    /// Perform a GET request, returning response data.
    private func performGET(url: URL, notFoundHeight: UInt32? = nil) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let apiKey {
            request.setValue(apiKey, forHTTPHeaderField: "Authorization")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw ChainTrackerError.networkError(error)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ChainTrackerError.invalidResponse("Not an HTTPURLResponse")
        }

        if httpResponse.statusCode == 404, let height = notFoundHeight {
            throw ChainTrackerError.notFound(height: height)
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw ChainTrackerError.httpStatus(code: httpResponse.statusCode)
        }
        return data
    }
}
