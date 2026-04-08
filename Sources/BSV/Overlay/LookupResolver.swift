// SPDX-License-Identifier: Open BSV License Version 5
// Overlay lookup resolver.
//
// Ported from ts-sdk src/overlay-tools/LookupResolver.ts. The resolver
// takes a `LookupQuestion`, discovers overlay hosts that host the named
// lookup service, queries a subset of them in parallel, and merges
// responses — preferring the first response and then waiting a short
// grace window for additional answers.

import Foundation

/// Resolves overlay hosts that host a given lookup service.
public protocol LookupHostResolver: Sendable {
    /// Return the overlay hosts that currently host `service`.
    func hosts(forService service: String) async throws -> [String]
}

/// Default SLAP trackers used on mainnet, matching the ts-sdk defaults.
public enum OverlayDefaultTrackers {
    public static let mainnetSLAPTrackers: [String] = [
        "https://overlay-us-1.bsvb.tech",
        "https://overlay-eu-1.bsvb.tech",
        "https://overlay-ap-1.bsvb.tech",
        "https://users.bapp.dev"
    ]
    public static let testnetSLAPTrackers: [String] = [
        "https://testnet-overlay-us-1.bsvb.tech",
        "https://testnet-overlay-eu-1.bsvb.tech",
        "https://testnet-users.bapp.dev"
    ]
}

/// Configuration for a `LookupResolver`.
public struct LookupResolverConfig: Sendable {
    /// Network preset used when picking the default SLAP trackers.
    public var networkPreset: OverlayNetworkPreset
    /// Override the SLAP trackers used to discover hosts.
    public var slapTrackers: [String]?
    /// Per-host request timeout in seconds.
    public var timeout: TimeInterval
    /// Extra time (in seconds) to wait after the first response before
    /// returning a merged answer.
    public var graceWindow: TimeInterval
    /// Maximum number of hosts queried in parallel.
    public var maxParallelQueries: Int

    public init(
        networkPreset: OverlayNetworkPreset = .mainnet,
        slapTrackers: [String]? = nil,
        timeout: TimeInterval = 10,
        graceWindow: TimeInterval = 0.08,
        maxParallelQueries: Int = 5
    ) {
        self.networkPreset = networkPreset
        self.slapTrackers = slapTrackers
        self.timeout = timeout
        self.graceWindow = graceWindow
        self.maxParallelQueries = maxParallelQueries
    }
}

/// Lookup resolver that queries overlay hosts for a `LookupQuestion`.
public struct LookupResolver: Sendable {
    public let hostResolver: LookupHostResolver
    public let facilitator: OverlayLookupFacilitator
    public let reputation: HostReputationTracker
    public let config: LookupResolverConfig

    public init(
        hostResolver: LookupHostResolver,
        facilitator: OverlayLookupFacilitator = HTTPSOverlayLookupFacilitator(),
        reputation: HostReputationTracker = HostReputationTracker(),
        config: LookupResolverConfig = LookupResolverConfig()
    ) {
        self.hostResolver = hostResolver
        self.facilitator = facilitator
        self.reputation = reputation
        self.config = config
    }

    /// Query overlay hosts for `question`.
    ///
    /// Validates the `ls_` prefix, resolves hosts, ranks them via the
    /// reputation tracker, then queries the top `maxParallelQueries` hosts
    /// in parallel. The first response starts a grace window during which
    /// additional responses may also be merged into the result. Outputs
    /// are deduplicated by `txid.outputIndex`.
    public func query(_ question: LookupQuestion) async throws -> LookupAnswer {
        guard question.service.hasPrefix("ls_") else {
            throw OverlayError.invalidServiceName(question.service)
        }

        let hosts = try await hostResolver.hosts(forService: question.service)
        var filtered: [String] = []
        for host in hosts where !(await reputation.isInBackoff(host: host)) {
            filtered.append(host)
        }
        if filtered.isEmpty {
            throw OverlayError.noHostsInterested("no hosts for service \(question.service)")
        }
        let ranked = await reputation.rank(hosts: filtered)
        let selected = Array(ranked.prefix(config.maxParallelQueries))

        let answers = try await gatherAnswers(hosts: selected, question: question)
        return mergeAnswers(answers)
    }

    // MARK: - Internal helpers

    private func gatherAnswers(
        hosts: [String],
        question: LookupQuestion
    ) async throws -> [LookupAnswer] {
        await withTaskGroup(of: LookupAnswer?.self) { group in
            for host in hosts {
                group.addTask { [facilitator, config, reputation] in
                    let started = Date()
                    do {
                        let answer = try await facilitator.lookup(
                            host: host,
                            question: question,
                            timeout: config.timeout
                        )
                        let elapsed = Date().timeIntervalSince(started) * 1000
                        await reputation.recordSuccess(host: host, latencyMs: elapsed)
                        return answer
                    } catch {
                        await reputation.recordFailure(host: host, immediate: true)
                        return nil
                    }
                }
            }

            var results: [LookupAnswer] = []
            var firstArrivedAt: Date?
            for await maybeAnswer in group {
                if let answer = maybeAnswer {
                    results.append(answer)
                    if firstArrivedAt == nil {
                        firstArrivedAt = Date()
                    }
                }
                if let first = firstArrivedAt, Date().timeIntervalSince(first) >= config.graceWindow {
                    group.cancelAll()
                    break
                }
            }
            return results
        }
    }

    /// Merge answers, deduplicating by `(txid,outputIndex)`. The txid is
    /// derived by parsing the BEEF to get the top-level transaction id.
    private func mergeAnswers(_ answers: [LookupAnswer]) -> LookupAnswer {
        var seen = Set<String>()
        var merged: [LookupOutput] = []
        for answer in answers {
            for output in answer.outputs {
                let key = Self.dedupeKey(for: output)
                if !seen.contains(key) {
                    seen.insert(key)
                    merged.append(output)
                }
            }
        }
        return LookupAnswer(type: "output-list", outputs: merged)
    }

    /// Generate a deduplication key for a lookup output using the top-level
    /// transaction id from its BEEF bundle. Falls back to a raw hash of the
    /// BEEF bytes when parsing fails.
    static func dedupeKey(for output: LookupOutput) -> String {
        if let beef = try? Beef.fromBinary(output.beef) {
            if let lastTx = beef.transactions.last?.transaction {
                return "\(lastTx.txid()).\(output.outputIndex)"
            }
        }
        return "\(output.beef.hex).\(output.outputIndex)"
    }
}
