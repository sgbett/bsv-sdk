import XCTest
@testable import BSV

/// A stub lookup facilitator that returns a canned response per host.
actor StubLookupFacilitator: OverlayLookupFacilitator {
    let responses: [String: LookupAnswer]
    private(set) var calls: [String] = []

    init(responses: [String: LookupAnswer]) {
        self.responses = responses
    }

    func lookup(host: String, question: LookupQuestion, timeout: TimeInterval?) async throws -> LookupAnswer {
        calls.append(host)
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
