import XCTest
@testable import BSV

private struct StubDoubleSpendError: DoubleSpendReportingError {
    let competingAction: DoubleSpendCompetingAction?
}

private struct PlainError: Error {}

/// Stub broadcaster that records invocations but always succeeds.
private actor CountingBroadcastFacilitator: OverlayBroadcastFacilitator {
    private(set) var sendCount = 0
    func send(host: String, taggedBEEF: TaggedBEEF, timeout: TimeInterval?) async throws -> STEAK {
        sendCount += 1
        return ["tm_demo": AdmittanceInstructions(outputsToAdmit: [0])]
    }
}

private struct SingleHostResolver: SHIPHostResolver {
    let host: String
    func hosts(forTopics topics: [String]) async throws -> [String: [String]] {
        var out: [String: [String]] = [:]
        for topic in topics { out[topic] = [host] }
        return out
    }
}

final class WithDoubleSpendRetryTests: XCTestCase {

    private func makeBroadcaster() throws -> (SHIPBroadcaster, CountingBroadcastFacilitator) {
        let facilitator = CountingBroadcastFacilitator()
        let broadcaster = try SHIPBroadcaster(
            topics: ["tm_demo"],
            hostResolver: SingleHostResolver(host: "https://a.example"),
            facilitator: facilitator,
            timeout: nil
        )
        return (broadcaster, facilitator)
    }

    func testSucceedsWithoutRetryIfOperationSucceeds() async throws {
        let (broadcaster, _) = try makeBroadcaster()
        let result = try await withDoubleSpendRetry(broadcaster: broadcaster) {
            return 42
        }
        XCTAssertEqual(result, 42)
    }

    func testRethrowsNonDoubleSpendErrorImmediately() async throws {
        let (broadcaster, _) = try makeBroadcaster()
        do {
            _ = try await withDoubleSpendRetry(broadcaster: broadcaster) {
                throw PlainError()
            }
            XCTFail("expected PlainError")
        } catch is PlainError {
            // expected
        }
    }

    func testRetriesWhenDoubleSpendWithoutCompetingAction() async throws {
        let (broadcaster, _) = try makeBroadcaster()
        do {
            _ = try await withDoubleSpendRetry(broadcaster: broadcaster) {
                throw StubDoubleSpendError(competingAction: nil)
            }
            XCTFail("expected StubDoubleSpendError")
        } catch is StubDoubleSpendError {
            // expected
        }
    }
}
