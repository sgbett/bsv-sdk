import XCTest
@testable import BSV

/// A stub facilitator that records calls and returns a canned STEAK.
actor StubBroadcastFacilitator: OverlayBroadcastFacilitator {
    struct Call: Sendable {
        let host: String
        let topics: [String]
    }
    private(set) var calls: [Call] = []
    private let response: STEAK
    private let shouldFail: Set<String>

    init(response: STEAK, failingHosts: Set<String> = []) {
        self.response = response
        self.shouldFail = failingHosts
    }

    func send(host: String, taggedBEEF: TaggedBEEF, timeout: TimeInterval?) async throws -> STEAK {
        calls.append(Call(host: host, topics: taggedBEEF.topics))
        if shouldFail.contains(host) {
            throw OverlayError.networkFailure("stub failure")
        }
        return response
    }
}

/// A simple resolver that maps topics to a fixed host list.
struct StaticHostResolver: SHIPHostResolver {
    let mapping: [String: [String]]
    func hosts(forTopics topics: [String]) async throws -> [String: [String]] {
        var result: [String: [String]] = [:]
        for topic in topics {
            result[topic] = mapping[topic] ?? []
        }
        return result
    }
}

final class SHIPBroadcasterTests: XCTestCase {

    func testRejectsTopicsWithoutTMPrefix() {
        let resolver = StaticHostResolver(mapping: [:])
        XCTAssertThrowsError(try SHIPBroadcaster(
            topics: ["bad_topic"],
            hostResolver: resolver
        )) { error in
            guard case OverlayError.invalidTopicPrefix = error else {
                XCTFail("expected invalidTopicPrefix, got \(error)")
                return
            }
        }
    }

    func testAnyHostPolicyAcceptsSingleResponse() async throws {
        let fac = StubBroadcastFacilitator(response: [
            "tm_demo": AdmittanceInstructions(outputsToAdmit: [0])
        ])
        let resolver = StaticHostResolver(mapping: [
            "tm_demo": ["https://host1.example", "https://host2.example"]
        ])
        let broadcaster = try SHIPBroadcaster(
            topics: ["tm_demo"],
            hostResolver: resolver,
            facilitator: fac,
            config: SHIPBroadcasterConfig(requirement: .anyHostForEachTopic),
            timeout: nil
        )
        let tx = Transaction()
        let response = try await broadcaster.broadcast(tx)
        XCTAssertEqual(response.txid, tx.txid())
        let calls = await fac.calls
        XCTAssertEqual(calls.count, 2)
    }

    func testAllHostPolicyRequiresEveryHostToAcknowledge() async throws {
        let fac = StubBroadcastFacilitator(
            response: ["tm_demo": AdmittanceInstructions(outputsToAdmit: [0])],
            failingHosts: ["https://flaky.example"]
        )
        let resolver = StaticHostResolver(mapping: [
            "tm_demo": ["https://host1.example", "https://flaky.example"]
        ])
        let broadcaster = try SHIPBroadcaster(
            topics: ["tm_demo"],
            hostResolver: resolver,
            facilitator: fac,
            config: SHIPBroadcasterConfig(requirement: .allHostsForAllTopics),
            timeout: nil
        )
        do {
            _ = try await broadcaster.broadcast(Transaction())
            XCTFail("expected acknowledgment failure")
        } catch OverlayError.acknowledgmentFailure {
            // expected
        }
    }

    func testSpecificHostsPolicyChecksNamedHosts() async throws {
        let fac = StubBroadcastFacilitator(response: [
            "tm_demo": AdmittanceInstructions(outputsToAdmit: [0])
        ])
        let resolver = StaticHostResolver(mapping: [
            "tm_demo": ["https://pinned.example", "https://other.example"]
        ])
        let broadcaster = try SHIPBroadcaster(
            topics: ["tm_demo"],
            hostResolver: resolver,
            facilitator: fac,
            config: SHIPBroadcasterConfig(
                requirement: .specificHosts(["tm_demo": ["https://pinned.example"]])
            ),
            timeout: nil
        )
        _ = try await broadcaster.broadcast(Transaction())
    }

    func testNoHostsFails() async throws {
        let fac = StubBroadcastFacilitator(response: [:])
        let resolver = StaticHostResolver(mapping: ["tm_demo": []])
        let broadcaster = try SHIPBroadcaster(
            topics: ["tm_demo"],
            hostResolver: resolver,
            facilitator: fac,
            config: SHIPBroadcasterConfig(),
            timeout: nil
        )
        do {
            _ = try await broadcaster.broadcast(Transaction())
            XCTFail("expected noHostsInterested")
        } catch OverlayError.noHostsInterested {
            // expected
        }
    }
}
