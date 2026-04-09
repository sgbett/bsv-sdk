import XCTest
@testable import BSV

/// A stub lookup facilitator that returns a canned response per host.
actor StubLookupFacilitator: OverlayLookupFacilitator {
    let responses: [String: LookupAnswer]
    let delays: [String: TimeInterval]
    private(set) var calls: [String] = []

    init(responses: [String: LookupAnswer], delays: [String: TimeInterval] = [:]) {
        self.responses = responses
        self.delays = delays
    }

    func lookup(host: String, question: LookupQuestion, timeout: TimeInterval?) async throws -> LookupAnswer {
        calls.append(host)
        if let delay = delays[host], delay > 0 {
            try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
        if let response = responses[host] { return response }
        throw OverlayError.networkFailure("no stub response for \(host)")
    }
}

/// Static host resolver for lookup tests.
struct StaticLookupHostResolver: LookupHostResolver {
    let hosts: [String]
    func hosts(forService service: String) async throws -> [String] { hosts }
}

final class LookupResolverTests: XCTestCase {

    func testRejectsServiceWithoutLsPrefix() async {
        let facilitator = StubLookupFacilitator(responses: [:])
        let resolver = LookupResolver(
            hostResolver: StaticLookupHostResolver(hosts: []),
            facilitator: facilitator,
            config: LookupResolverConfig(graceWindow: 0)
        )
        do {
            _ = try await resolver.query(LookupQuestion(service: "bad", query: Data()))
            XCTFail("expected invalidServiceName")
        } catch OverlayError.invalidServiceName {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testMergesResponsesFromMultipleHosts() async throws {
        let answerA = LookupAnswer(outputs: [
            LookupOutput(beef: Data([0x01]), outputIndex: 0)
        ])
        let answerB = LookupAnswer(outputs: [
            LookupOutput(beef: Data([0x02]), outputIndex: 0),
            // Duplicate of the A entry — should be deduplicated.
            LookupOutput(beef: Data([0x01]), outputIndex: 0)
        ])
        let facilitator = StubLookupFacilitator(responses: [
            "https://a.example": answerA,
            "https://b.example": answerB
        ])
        let resolver = LookupResolver(
            hostResolver: StaticLookupHostResolver(hosts: [
                "https://a.example",
                "https://b.example"
            ]),
            facilitator: facilitator,
            config: LookupResolverConfig(graceWindow: 0.5)
        )
        let answer = try await resolver.query(LookupQuestion(
            service: "ls_demo",
            query: Data()
        ))
        XCTAssertEqual(answer.outputs.count, 2)
    }

    /// Regression test for M3: the grace window must elapse on a timer, not
    /// on the next `for await` iteration. If one host answers fast and the
    /// rest are slow, `query` should return within roughly `graceWindow`
    /// of the first answer — NOT wait for the slow hosts.
    func testGraceWindowElapsesAgainstWallClockNotNextArrival() async throws {
        let fastAnswer = LookupAnswer(outputs: [
            LookupOutput(beef: Data([0x01]), outputIndex: 0)
        ])
        let slowAnswer = LookupAnswer(outputs: [
            LookupOutput(beef: Data([0x02]), outputIndex: 0)
        ])

        // One host answers immediately, the other takes 3 seconds. With a
        // 0.1s grace window the query must return in well under a second.
        let facilitator = StubLookupFacilitator(
            responses: [
                "https://fast.example": fastAnswer,
                "https://slow.example": slowAnswer
            ],
            delays: [
                "https://fast.example": 0,
                "https://slow.example": 3.0
            ]
        )
        let resolver = LookupResolver(
            hostResolver: StaticLookupHostResolver(hosts: [
                "https://fast.example",
                "https://slow.example"
            ]),
            facilitator: facilitator,
            config: LookupResolverConfig(timeout: 10, graceWindow: 0.1)
        )

        let started = Date()
        let answer = try await resolver.query(LookupQuestion(
            service: "ls_demo",
            query: Data()
        ))
        let elapsed = Date().timeIntervalSince(started)

        // Must contain at least the fast answer. The slow answer may
        // or may not have made it in depending on scheduling, but the
        // critical property is that we did NOT wait the full 3s.
        XCTAssertGreaterThanOrEqual(answer.outputs.count, 1)
        XCTAssertLessThan(
            elapsed, 1.0,
            "query should return within ~graceWindow of first answer, not wait for slow hosts"
        )
    }

    func testNoHostsThrows() async {
        let facilitator = StubLookupFacilitator(responses: [:])
        let resolver = LookupResolver(
            hostResolver: StaticLookupHostResolver(hosts: []),
            facilitator: facilitator
        )
        do {
            _ = try await resolver.query(LookupQuestion(
                service: "ls_demo",
                query: Data()
            ))
            XCTFail("expected noHostsInterested")
        } catch OverlayError.noHostsInterested {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
