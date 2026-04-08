import XCTest
@testable import BSV

final class HostReputationTrackerTests: XCTestCase {

    func testSuccessSeedsLatencyFromFirstSample() async {
        let tracker = HostReputationTracker()
        await tracker.recordSuccess(host: "https://a.example", latencyMs: 200)
        let stats = await tracker.snapshot(for: "https://a.example")
        XCTAssertEqual(stats.smoothedLatencyMs, 200, accuracy: 0.001)
        XCTAssertEqual(stats.totalSuccesses, 1)
        XCTAssertEqual(stats.consecutiveFailures, 0)
    }

    func testSubsequentSuccessSmoothesLatency() async {
        let tracker = HostReputationTracker()
        await tracker.recordSuccess(host: "host", latencyMs: 200)
        await tracker.recordSuccess(host: "host", latencyMs: 400)
        let stats = await tracker.snapshot(for: "host")
        // EMA: 200 + 0.25*(400-200) = 250
        XCTAssertEqual(stats.smoothedLatencyMs, 250, accuracy: 0.001)
        XCTAssertEqual(stats.totalSuccesses, 2)
    }

    func testConsecutiveFailuresAccrueBackoffAfterGrace() async {
        let tracker = HostReputationTracker()
        // First two failures sit in the grace window.
        await tracker.recordFailure(host: "host")
        await tracker.recordFailure(host: "host")
        var stats = await tracker.snapshot(for: "host")
        XCTAssertEqual(stats.consecutiveFailures, 2)
        XCTAssertNil(stats.backoffUntil)
        // Third failure triggers back-off.
        await tracker.recordFailure(host: "host")
        stats = await tracker.snapshot(for: "host")
        XCTAssertNotNil(stats.backoffUntil)
        let inBackoff = await tracker.isInBackoff(host: "host")
        XCTAssertTrue(inBackoff)
    }

    func testImmediateFailureBypassesGrace() async {
        let tracker = HostReputationTracker()
        await tracker.recordFailure(host: "host", immediate: true)
        let inBackoff = await tracker.isInBackoff(host: "host")
        XCTAssertTrue(inBackoff)
    }

    func testSuccessClearsBackoff() async {
        let tracker = HostReputationTracker()
        await tracker.recordFailure(host: "host", immediate: true)
        await tracker.recordSuccess(host: "host", latencyMs: 120)
        let stats = await tracker.snapshot(for: "host")
        XCTAssertNil(stats.backoffUntil)
        XCTAssertEqual(stats.consecutiveFailures, 0)
    }

    func testRankPrefersFasterHosts() async {
        let tracker = HostReputationTracker()
        await tracker.recordSuccess(host: "slow", latencyMs: 1000)
        await tracker.recordSuccess(host: "fast", latencyMs: 50)
        let ranked = await tracker.rank(hosts: ["slow", "fast"])
        XCTAssertEqual(ranked, ["fast", "slow"])
    }

    func testRankDemotesFailingHosts() async {
        let tracker = HostReputationTracker()
        await tracker.recordSuccess(host: "good", latencyMs: 800)
        await tracker.recordSuccess(host: "bad", latencyMs: 100)
        // Push "bad" past the grace window so it accrues backoff.
        for _ in 0..<5 {
            await tracker.recordFailure(host: "bad")
        }
        let ranked = await tracker.rank(hosts: ["good", "bad"])
        XCTAssertEqual(ranked.first, "good")
    }
}
