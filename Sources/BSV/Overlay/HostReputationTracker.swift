// SPDX-License-Identifier: Open BSV License Version 5
// Per-host latency/failure scoring used to prefer reliable overlay hosts.
//
// Ported from ts-sdk src/overlay-tools/HostReputationTracker.ts. The
// behaviour matches the TypeScript implementation:
//
//   - Latency is smoothed with an EMA (factor 0.25).
//   - Failures accumulate a per-host back-off penalty with exponential growth
//     up to a maximum, before applying a fixed per-failure penalty.
//   - Score is computed as `latency + failurePenalty + backoffPenalty -
//     successBonus`, where the success bonus is capped so that a host with
//     zero latency is never rewarded below zero.
//
// The tracker is an `actor` so it can be freely shared between asynchronous
// overlay operations without additional locking.

import Foundation

/// Snapshot of the statistics held for a single overlay host.
public struct HostReputationStats: Sendable, Equatable {
    /// The smoothed latency in milliseconds.
    public var smoothedLatencyMs: Double
    /// Consecutive failure count since the last success.
    public var consecutiveFailures: Int
    /// Timestamp when the next request may be attempted.
    public var backoffUntil: Date?
    /// Total successful requests ever recorded.
    public var totalSuccesses: Int

    public init(
        smoothedLatencyMs: Double = HostReputationTracker.defaultLatencyMs,
        consecutiveFailures: Int = 0,
        backoffUntil: Date? = nil,
        totalSuccesses: Int = 0
    ) {
        self.smoothedLatencyMs = smoothedLatencyMs
        self.consecutiveFailures = consecutiveFailures
        self.backoffUntil = backoffUntil
        self.totalSuccesses = totalSuccesses
    }
}

/// Tracks per-host latency, failures, and back-off to rank overlay hosts
/// by relative desirability.
public actor HostReputationTracker {
    /// Default assumed latency for unknown hosts (ms).
    public static let defaultLatencyMs: Double = 1500
    /// EMA smoothing factor applied to new latency samples.
    public static let latencySmoothingFactor: Double = 0.25
    /// Base back-off delay applied after the grace period (ms).
    public static let baseBackoffMs: Double = 1000
    /// Maximum back-off delay (ms).
    public static let maxBackoffMs: Double = 60_000
    /// Constant penalty added per consecutive failure when scoring.
    public static let failurePenaltyMs: Double = 400
    /// Per-success bonus subtracted from a host's score.
    public static let successBonusMs: Double = 30
    /// Grace period (in consecutive failures) before back-off starts.
    public static let failureBackoffGrace: Int = 2

    /// In-memory reputation store keyed by host URL.
    private var stats: [String: HostReputationStats] = [:]

    public init() {}

    /// Replace the tracked stats for a host (primarily for test fixtures).
    public func seed(host: String, stats: HostReputationStats) {
        self.stats[host] = stats
    }

    /// Look up the current snapshot for a host.
    public func snapshot(for host: String) -> HostReputationStats {
        stats[host] ?? HostReputationStats()
    }

    /// Record a successful response from `host` that took `latencyMs` to
    /// complete. The latency is folded into the EMA, consecutive failures
    /// are reset, and total successes is incremented.
    public func recordSuccess(host: String, latencyMs: Double) {
        var entry = stats[host] ?? HostReputationStats()
        let sample = max(latencyMs, 0)
        let alpha = Self.latencySmoothingFactor
        let previous = entry.smoothedLatencyMs
        entry.smoothedLatencyMs = previous == Self.defaultLatencyMs && entry.totalSuccesses == 0
            ? sample
            : previous + alpha * (sample - previous)
        entry.consecutiveFailures = 0
        entry.backoffUntil = nil
        entry.totalSuccesses += 1
        stats[host] = entry
    }

    /// Record a failure against `host`. Consecutive failures past the
    /// grace period accrue exponential back-off capped at `maxBackoffMs`.
    ///
    /// - Parameter immediate: Set to `true` for DNS/fetch-level failures
    ///   which should bypass the grace window entirely.
    public func recordFailure(host: String, immediate: Bool = false) {
        var entry = stats[host] ?? HostReputationStats()
        if immediate {
            entry.consecutiveFailures = max(entry.consecutiveFailures, Self.failureBackoffGrace) + 1
        } else {
            entry.consecutiveFailures += 1
        }
        if entry.consecutiveFailures > Self.failureBackoffGrace {
            let steps = entry.consecutiveFailures - Self.failureBackoffGrace
            let exponent = max(steps - 1, 0)
            let raw = Self.baseBackoffMs * pow(2.0, Double(exponent))
            let backoffMs = min(raw, Self.maxBackoffMs)
            entry.backoffUntil = Date().addingTimeInterval(backoffMs / 1000)
        }
        stats[host] = entry
    }

    /// Whether a host is currently inside its back-off window.
    public func isInBackoff(host: String, now: Date = Date()) -> Bool {
        guard let until = stats[host]?.backoffUntil else { return false }
        return until > now
    }

    /// Numeric score where lower is better. Used to rank hosts.
    public func computeScore(for host: String, now: Date = Date()) -> Double {
        let entry = stats[host] ?? HostReputationStats()
        let backoffRemaining = entry.backoffUntil.map { max($0.timeIntervalSince(now) * 1000, 0) } ?? 0
        let failurePenalty = Double(entry.consecutiveFailures) * Self.failurePenaltyMs
        let bonusCap = entry.smoothedLatencyMs / 2
        let bonus = min(Double(entry.totalSuccesses) * Self.successBonusMs, bonusCap)
        return entry.smoothedLatencyMs + failurePenalty + backoffRemaining - bonus
    }

    /// Return a copy of `hosts` sorted from best to worst by score.
    public func rank(hosts: [String], now: Date = Date()) -> [String] {
        var scored: [(String, Double)] = []
        for host in hosts {
            scored.append((host, computeScore(for: host, now: now)))
        }
        scored.sort { lhs, rhs in
            if lhs.1 == rhs.1 { return lhs.0 < rhs.0 }
            return lhs.1 < rhs.1
        }
        return scored.map { $0.0 }
    }
}
