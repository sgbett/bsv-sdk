// SPDX-License-Identifier: Open BSV License Version 5
// Service Host Interconnect Protocol broadcaster.
//
// Ported from ts-sdk src/overlay-tools/SHIPBroadcaster.ts. A SHIPBroadcaster
// takes a transaction targeted at one or more `tm_*` topics, queries the
// overlay network for hosts that are interested in each topic, and posts
// the BEEF to the intersection of those hosts. It satisfies the Phase 5
// `Broadcaster` protocol so callers can plug it in anywhere a `Broadcaster`
// is expected.
//
// The broadcaster does not itself discover hosts — a `SHIPHostResolver`
// implementation must be provided. In tests this is typically a stub that
// returns a fixed map of topic → hosts. A production `LookupResolver`-based
// implementation can be layered on top.

import Foundation

/// Resolves overlay hosts that are interested in a given set of topics.
public protocol SHIPHostResolver: Sendable {
    /// Return hosts (base URLs, e.g. `https://overlay.example.com`) that
    /// currently claim to host each of the requested topics.
    func hosts(forTopics topics: [String]) async throws -> [String: [String]]
}

/// A SHIP broadcaster that delegates host discovery to a `SHIPHostResolver`
/// and per-host submission to an `OverlayBroadcastFacilitator`.
public struct SHIPBroadcaster: Broadcaster, Sendable {
    /// The topics that every transaction broadcast by this instance targets.
    public let topics: [String]
    /// Resolver used to find hosts interested in the configured topics.
    public let hostResolver: SHIPHostResolver
    /// Per-host submission transport.
    public let facilitator: OverlayBroadcastFacilitator
    /// Reputation tracker used to prefer fast/healthy hosts.
    public let reputation: HostReputationTracker
    /// Acknowledgment policy that determines when a broadcast is successful.
    public let config: SHIPBroadcasterConfig
    /// Optional off-chain values to forward with every submission.
    public let offChainValues: [String: Data]?
    /// Per-request timeout (seconds) forwarded to the facilitator.
    public let timeout: TimeInterval?

    /// Construct a SHIPBroadcaster.
    ///
    /// - Parameters:
    ///   - topics: The overlay topics (`tm_*`) targeted by every broadcast.
    ///   - hostResolver: Component that maps topics to interested hosts.
    ///   - facilitator: Per-host transport. Defaults to HTTPS.
    ///   - reputation: Reputation tracker (defaults to a fresh actor).
    ///   - config: Acknowledgment policy and network preset.
    ///   - offChainValues: Optional off-chain values to forward.
    ///   - timeout: Optional per-host request timeout in seconds.
    /// - Throws: `OverlayError.invalidTopicPrefix` if any topic lacks the
    ///   `tm_` prefix.
    public init(
        topics: [String],
        hostResolver: SHIPHostResolver,
        facilitator: OverlayBroadcastFacilitator = HTTPSOverlayBroadcastFacilitator(),
        reputation: HostReputationTracker = HostReputationTracker(),
        config: SHIPBroadcasterConfig = SHIPBroadcasterConfig(),
        offChainValues: [String: Data]? = nil,
        timeout: TimeInterval? = 30
    ) throws {
        for topic in topics where !topic.hasPrefix("tm_") {
            throw OverlayError.invalidTopicPrefix(topic)
        }
        self.topics = topics
        self.hostResolver = hostResolver
        self.facilitator = facilitator
        self.reputation = reputation
        self.config = config
        self.offChainValues = offChainValues
        self.timeout = timeout
    }

    // MARK: - Broadcaster

    public func broadcast(_ transaction: Transaction) async throws -> BroadcastResponse {
        // Wrap the transaction in a single-tx BEEF.
        let beef = Beef(
            version: beefV2Version,
            bumps: [],
            transactions: [BeefTx(dataFormat: .rawTx, transaction: transaction)]
        )
        let tagged = TaggedBEEF(
            beef: beef.toBinary(),
            topics: topics,
            offChainValues: offChainValues
        )
        let acks = try await broadcastTagged(tagged)
        let txid = transaction.txid()
        return BroadcastResponse(
            txid: txid,
            status: "OVERLAY_BROADCAST_OK",
            description: "\(acks.count) overlay host acknowledgments"
        )
    }

    /// Broadcast an already-built tagged BEEF. Returns the per-host
    /// acknowledgments that satisfied the broadcaster's policy.
    public func broadcastTagged(_ taggedBEEF: TaggedBEEF) async throws -> [String: STEAK] {
        guard !taggedBEEF.topics.isEmpty else {
            throw OverlayError.noHostsInterested("no topics supplied")
        }

        // Discover interested hosts and remove any that are currently in
        // back-off. Each host is queried at most once even if it covers
        // multiple topics.
        let interested = try await hostResolver.hosts(forTopics: taggedBEEF.topics)
        var hosts = Set<String>()
        for (_, list) in interested {
            for host in list { hosts.insert(host) }
        }
        var filtered: [String] = []
        for host in hosts where !(await reputation.isInBackoff(host: host)) {
            filtered.append(host)
        }
        if filtered.isEmpty {
            throw OverlayError.noHostsInterested(
                "no overlay hosts available for topics \(taggedBEEF.topics.joined(separator: ","))"
            )
        }
        let ranked = await reputation.rank(hosts: filtered)

        // Submit to every host in parallel and collect STEAK results.
        var responses: [String: STEAK] = [:]
        var failures: [String: Error] = [:]
        await withTaskGroup(of: (String, Result<STEAK, Error>).self) { group in
            for host in ranked {
                group.addTask { [facilitator, timeout, reputation] in
                    let started = Date()
                    do {
                        let steak = try await facilitator.send(
                            host: host,
                            taggedBEEF: taggedBEEF,
                            timeout: timeout
                        )
                        let elapsed = Date().timeIntervalSince(started) * 1000
                        await reputation.recordSuccess(host: host, latencyMs: elapsed)
                        return (host, .success(steak))
                    } catch {
                        await reputation.recordFailure(host: host, immediate: true)
                        return (host, .failure(error))
                    }
                }
            }
            for await (host, result) in group {
                switch result {
                case .success(let steak): responses[host] = steak
                case .failure(let err): failures[host] = err
                }
            }
        }

        // Evaluate the acknowledgment policy.
        try evaluateAcknowledgments(
            responses: responses,
            requested: taggedBEEF.topics,
            interestMap: interested,
            failures: failures
        )
        return responses
    }

    /// Enforce the configured acknowledgment requirement against the
    /// set of successful STEAK responses.
    private func evaluateAcknowledgments(
        responses: [String: STEAK],
        requested: [String],
        interestMap: [String: [String]],
        failures: [String: Error]
    ) throws {
        switch config.requirement {
        case .allHostsForAllTopics:
            for topic in requested {
                let expected = interestMap[topic] ?? []
                for host in expected {
                    guard let steak = responses[host], steak[topic] != nil else {
                        throw OverlayError.acknowledgmentFailure(
                            "host \(host) did not acknowledge topic \(topic)"
                        )
                    }
                }
            }
        case .anyHostForEachTopic:
            for topic in requested {
                let acknowledged = responses.contains { _, steak in steak[topic] != nil }
                if !acknowledged {
                    throw OverlayError.acknowledgmentFailure(
                        "no host acknowledged topic \(topic)"
                    )
                }
            }
        case .specificHosts(let required):
            for (topic, hosts) in required {
                for host in hosts {
                    guard let steak = responses[host], steak[topic] != nil else {
                        throw OverlayError.acknowledgmentFailure(
                            "host \(host) did not acknowledge topic \(topic)"
                        )
                    }
                }
            }
        }
        _ = failures
    }
}
