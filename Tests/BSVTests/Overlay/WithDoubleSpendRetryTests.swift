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

    /// Build a minimal valid BEEF binary wrapping a single raw transaction
    /// so the retry helper can parse and rebroadcast it.
    private func makeCompetingBeef() -> (Data, String) {
        let tx = Transaction(version: 1, inputs: [], outputs: [], lockTime: 0)
        let beef = Beef(
            version: beefV2Version,
            bumps: [],
            transactions: [BeefTx(dataFormat: .rawTx, transaction: tx)]
        )
        return (beef.toBinary(), tx.txid())
    }

    /// An actor-backed counter so the retry operation closure, which is
    /// `@Sendable`, can bump attempt count across retries.
    private actor AttemptCounter {
        private(set) var count = 0
        func increment() -> Int {
            count += 1
            return count
        }
    }

    func testRetriesAndSucceedsWithCompetingAction() async throws {
        let (broadcaster, facilitator) = try makeBroadcaster()
        let (beefBytes, txid) = makeCompetingBeef()
        let attempts = AttemptCounter()

        let result = try await withDoubleSpendRetry(broadcaster: broadcaster) {
            let n = await attempts.increment()
            if n == 1 {
                throw StubDoubleSpendError(
                    competingAction: DoubleSpendCompetingAction(
                        beef: beefBytes,
                        txid: txid
                    )
                )
            }
            return "ok"
        }

        XCTAssertEqual(result, "ok")
        let attemptCount = await attempts.count
        XCTAssertEqual(attemptCount, 2, "operation should run twice: once failing, once succeeding")
        let sendCount = await facilitator.sendCount
        XCTAssertEqual(sendCount, 1, "competing tx should be broadcast exactly once between attempts")
    }

    func testExhaustsMaxRetries() async throws {
        let (broadcaster, facilitator) = try makeBroadcaster()
        let (beefBytes, txid) = makeCompetingBeef()
        let attempts = AttemptCounter()

        do {
            _ = try await withDoubleSpendRetry(
                maxRetries: 3,
                broadcaster: broadcaster
            ) {
                _ = await attempts.increment()
                throw StubDoubleSpendError(
                    competingAction: DoubleSpendCompetingAction(
                        beef: beefBytes,
                        txid: txid
                    )
                )
            }
            XCTFail("expected StubDoubleSpendError after exhausting retries")
        } catch is StubDoubleSpendError {
            // expected
        }

        let attemptCount = await attempts.count
        XCTAssertEqual(attemptCount, 3, "operation should be attempted exactly maxRetries times")
        // The final attempt short-circuits without broadcasting the competing
        // tx (the retry loop only rebroadcasts when another attempt remains).
        let sendCount = await facilitator.sendCount
        XCTAssertEqual(sendCount, 2, "competing tx should be broadcast between each retry but not after the last failure")
    }
}
