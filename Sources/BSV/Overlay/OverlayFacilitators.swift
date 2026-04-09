// SPDX-License-Identifier: Open BSV License Version 5
// Overlay broadcast and lookup facilitators.
//
// Ported from ts-sdk src/overlay-tools/SHIPBroadcaster.ts and
// src/overlay-tools/LookupResolver.ts. Facilitators abstract the transport
// that talks to a single overlay host so the broadcast/lookup logic can be
// unit-tested without network access.

import Foundation

/// A broadcast facilitator pushes a tagged BEEF payload to a single overlay
/// host and returns the per-topic admittance instructions.
public protocol OverlayBroadcastFacilitator: Sendable {
    /// Submit `taggedBEEF` to `host` and return the STEAK response.
    ///
    /// - Parameters:
    ///   - host: The base URL of the overlay host (without `/submit` suffix).
    ///   - taggedBEEF: The BEEF payload, the targeted topics, and any
    ///     off-chain values required by the overlay service.
    ///   - timeout: Optional request timeout in seconds.
    func send(
        host: String,
        taggedBEEF: TaggedBEEF,
        timeout: TimeInterval?
    ) async throws -> STEAK
}

/// A lookup facilitator forwards a `LookupQuestion` to a single overlay host
/// and returns the decoded `LookupAnswer`.
public protocol OverlayLookupFacilitator: Sendable {
    /// Query `host` with `question`.
    ///
    /// - Parameters:
    ///   - host: The base URL of the overlay host (without `/lookup` suffix).
    ///   - question: The structured lookup question.
    ///   - timeout: Optional request timeout in seconds.
    func lookup(
        host: String,
        question: LookupQuestion,
        timeout: TimeInterval?
    ) async throws -> LookupAnswer
}

// MARK: - HTTPS broadcast facilitator

/// HTTPS implementation of `OverlayBroadcastFacilitator`. Posts the BEEF to
/// `<host>/submit` with the `X-Topics` header, matching ts-sdk's
/// `HTTPSOverlayBroadcastFacilitator`.
public struct HTTPSOverlayBroadcastFacilitator: OverlayBroadcastFacilitator {
    public let urlSession: URLSession

    public init(urlSession: URLSession = .shared) {
        self.urlSession = urlSession
    }

    public func send(
        host: String,
        taggedBEEF: TaggedBEEF,
        timeout: TimeInterval?
    ) async throws -> STEAK {
        guard let url = URL(string: host.trimmingTrailingSlash() + "/submit") else {
            throw OverlayError.invalidURL(host)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let timeout { request.timeoutInterval = timeout }

        // The X-Topics header is a JSON-encoded array of topic names.
        let topicsJSON = try JSONSerialization.data(withJSONObject: taggedBEEF.topics)
        if let topicsString = String(data: topicsJSON, encoding: .utf8) {
            request.setValue(topicsString, forHTTPHeaderField: "X-Topics")
        }
        request.httpBody = taggedBEEF.beef

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw OverlayError.networkFailure(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw OverlayError.networkFailure("response is not HTTP")
        }
        guard (200..<300).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw OverlayError.networkFailure("HTTP \(http.statusCode): \(body)")
        }

        return try Self.decodeSTEAK(data: data)
    }

    /// Decode a STEAK JSON body of the form:
    /// `{ "<topic>": { "outputsToAdmit": [...], "coinsToRetain": [...], "coinsRemoved": [...] } }`.
    static func decodeSTEAK(data: Data) throws -> STEAK {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw OverlayError.networkFailure("STEAK response is not a JSON object")
        }
        var steak: STEAK = [:]
        for (topic, raw) in json {
            guard let entry = raw as? [String: Any] else {
                throw OverlayError.networkFailure("STEAK entry for \(topic) is not an object")
            }
            let outputs = (entry["outputsToAdmit"] as? [Any])?.compactMap { value -> UInt32? in
                if let n = value as? Int { return UInt32(exactly: n) }
                if let n = value as? Double { return UInt32(exactly: n) }
                return nil
            } ?? []
            let retain = (entry["coinsToRetain"] as? [String]) ?? []
            let removed = entry["coinsRemoved"] as? [String]
            steak[topic] = AdmittanceInstructions(
                outputsToAdmit: outputs,
                coinsToRetain: retain,
                coinsRemoved: removed
            )
        }
        return steak
    }
}

// MARK: - HTTPS lookup facilitator

/// HTTPS implementation of `OverlayLookupFacilitator`. Posts the question
/// to `<host>/lookup` and parses the JSON response.
public struct HTTPSOverlayLookupFacilitator: OverlayLookupFacilitator {
    public let urlSession: URLSession

    public init(urlSession: URLSession = .shared) {
        self.urlSession = urlSession
    }

    public func lookup(
        host: String,
        question: LookupQuestion,
        timeout: TimeInterval?
    ) async throws -> LookupAnswer {
        guard let url = URL(string: host.trimmingTrailingSlash() + "/lookup") else {
            throw OverlayError.invalidURL(host)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("yes", forHTTPHeaderField: "X-Aggregation")
        if let timeout { request.timeoutInterval = timeout }

        // Body shape matches ts-sdk: { service, query }
        let queryAny: Any
        if let queryObject = try? JSONSerialization.jsonObject(with: question.query) {
            queryAny = queryObject
        } else if let queryString = String(data: question.query, encoding: .utf8) {
            queryAny = queryString
        } else {
            queryAny = question.query.hex
        }
        let body: [String: Any] = [
            "service": question.service,
            "query": queryAny
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw OverlayError.networkFailure(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw OverlayError.networkFailure("response is not HTTP")
        }
        guard (200..<300).contains(http.statusCode) else {
            let bodyString = String(data: data, encoding: .utf8) ?? ""
            throw OverlayError.networkFailure("HTTP \(http.statusCode): \(bodyString)")
        }
        return try Self.decodeAnswer(data: data)
    }

    /// Parse a lookup answer from either JSON or the binary aggregated
    /// format described in ts-sdk's `HTTPSOverlayLookupFacilitator`.
    static func decodeAnswer(data: Data) throws -> LookupAnswer {
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let type = (json["type"] as? String) ?? "output-list"
            let rawOutputs = (json["outputs"] as? [[String: Any]]) ?? []
            var outputs: [LookupOutput] = []
            for raw in rawOutputs {
                guard let beefHex = raw["beef"] as? String,
                      let beef = Data(hex: beefHex) else {
                    throw OverlayError.invalidLookupResponse("missing or invalid beef field")
                }
                let index: UInt32
                if let n = raw["outputIndex"] as? Int {
                    index = UInt32(n)
                } else if let n = raw["outputIndex"] as? Double {
                    index = UInt32(n)
                } else {
                    throw OverlayError.invalidLookupResponse("missing outputIndex")
                }
                var context: Data?
                if let ctxString = raw["context"] as? String {
                    context = Data(hex: ctxString) ?? Data(ctxString.utf8)
                }
                outputs.append(LookupOutput(beef: beef, outputIndex: index, context: context))
            }
            return LookupAnswer(type: type, outputs: outputs)
        }
        throw OverlayError.invalidLookupResponse("response is not valid JSON")
    }
}

// MARK: - Helpers

extension String {
    fileprivate func trimmingTrailingSlash() -> String {
        var result = self
        while result.hasSuffix("/") { result.removeLast() }
        return result
    }
}
