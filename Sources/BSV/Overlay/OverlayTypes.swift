// SPDX-License-Identifier: Open BSV License Version 5
// Shared data types used by SHIP broadcasters and overlay lookup resolvers.
//
// Ported from ts-sdk src/overlay-tools/SHIPBroadcaster.ts and
// src/overlay-tools/LookupResolver.ts.

import Foundation

/// A BEEF bundle tagged with the overlay topics it targets.
///
/// Off-chain values may optionally be attached and are forwarded alongside
/// the BEEF payload when overlay services require additional context that
/// does not live on-chain.
public struct TaggedBEEF: Sendable, Equatable {
    /// The raw BEEF bytes (BRC-62 / BRC-96).
    public var beef: Data
    /// Overlay topic names (each of the form `tm_<topic>`).
    public var topics: [String]
    /// Optional off-chain values keyed by an arbitrary string label.
    public var offChainValues: [String: Data]?

    public init(
        beef: Data,
        topics: [String],
        offChainValues: [String: Data]? = nil
    ) {
        self.beef = beef
        self.topics = topics
        self.offChainValues = offChainValues
    }
}

/// Instructions returned by an overlay host describing how it has admitted
/// the submitted transaction into a given topic.
public struct AdmittanceInstructions: Sendable, Equatable {
    /// Output indices admitted by the host for the topic.
    public var outputsToAdmit: [UInt32]
    /// Coin outpoints that the host intends to retain.
    public var coinsToRetain: [String]
    /// Coin outpoints removed by the host as part of admittance.
    public var coinsRemoved: [String]?

    public init(
        outputsToAdmit: [UInt32] = [],
        coinsToRetain: [String] = [],
        coinsRemoved: [String]? = nil
    ) {
        self.outputsToAdmit = outputsToAdmit
        self.coinsToRetain = coinsToRetain
        self.coinsRemoved = coinsRemoved
    }
}

/// Submitted Transaction Execution AcKnowledgment.
///
/// A dictionary keyed by topic where the value is the per-topic
/// admittance instructions returned by a single overlay host.
public typealias STEAK = [String: AdmittanceInstructions]

/// Acknowledgment policy for a SHIP broadcast.
public enum SHIPAcknowledgmentRequirement: Sendable, Equatable {
    /// Every host interested in every topic must acknowledge.
    case allHostsForAllTopics
    /// At least one host must acknowledge each topic.
    case anyHostForEachTopic
    /// Per-topic host-URL lists must acknowledge.
    case specificHosts([String: [String]])
}

/// Configuration for a SHIP broadcaster.
public struct SHIPBroadcasterConfig: Sendable {
    /// Which overlay network to resolve hosts from.
    public var networkPreset: OverlayNetworkPreset
    /// Acknowledgment policy the broadcast must satisfy.
    public var requirement: SHIPAcknowledgmentRequirement
    /// Optional URL overrides for resolving SLAP trackers.
    public var slapTrackers: [String]?

    public init(
        networkPreset: OverlayNetworkPreset = .mainnet,
        requirement: SHIPAcknowledgmentRequirement = .anyHostForEachTopic,
        slapTrackers: [String]? = nil
    ) {
        self.networkPreset = networkPreset
        self.requirement = requirement
        self.slapTrackers = slapTrackers
    }
}

/// Overlay network selector mirroring the ts-sdk `NetworkPreset` enum.
public enum OverlayNetworkPreset: String, Sendable, Equatable {
    case mainnet
    case testnet
    case local
}

/// A structured lookup question submitted to an overlay lookup service.
public struct LookupQuestion: Sendable, Equatable {
    /// The service name (must start with `ls_`).
    public var service: String
    /// The opaque query payload (JSON-encoded by the caller).
    public var query: Data

    public init(service: String, query: Data) {
        self.service = service
        self.query = query
    }
}

/// A single output returned in a lookup answer.
public struct LookupOutput: Sendable, Equatable {
    /// The BEEF bundle that proves the output's provenance.
    public var beef: Data
    /// The index of the output within the top-level transaction of `beef`.
    public var outputIndex: UInt32
    /// Optional opaque context supplied by the lookup service.
    public var context: Data?

    public init(beef: Data, outputIndex: UInt32, context: Data? = nil) {
        self.beef = beef
        self.outputIndex = outputIndex
        self.context = context
    }
}

/// The structured response from a lookup query.
public struct LookupAnswer: Sendable, Equatable {
    /// The response type (mirrors ts-sdk's string discriminator).
    public var type: String
    /// The list of outputs returned by the service.
    public var outputs: [LookupOutput]

    public init(type: String = "output-list", outputs: [LookupOutput]) {
        self.type = type
        self.outputs = outputs
    }
}
