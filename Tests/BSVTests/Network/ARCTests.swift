import XCTest
@testable import BSV

final class ARCTests: XCTestCase {

    func testParseSuccessResponse() throws {
        let json = """
        {
          "txid": "a1b2c3d4",
          "txStatus": "SEEN_ON_NETWORK",
          "extraInfo": "broadcast ok"
        }
        """.data(using: .utf8)!

        let response = try ARC.parseResponse(data: json, statusCode: 200)
        XCTAssertEqual(response.txid, "a1b2c3d4")
        XCTAssertEqual(response.status, "SEEN_ON_NETWORK")
        XCTAssertEqual(response.description, "broadcast ok")
    }

    func testParseSuccessMinimalResponse() throws {
        let json = """
        { "txid": "abcd", "txStatus": "STORED" }
        """.data(using: .utf8)!

        let response = try ARC.parseResponse(data: json, statusCode: 200)
        XCTAssertEqual(response.txid, "abcd")
        XCTAssertEqual(response.status, "STORED")
    }

    func testParseErrorResponseThrowsRejected() {
        let json = """
        {
          "title": "Invalid script",
          "detail": "The locking script is invalid"
        }
        """.data(using: .utf8)!

        XCTAssertThrowsError(try ARC.parseResponse(data: json, statusCode: 400)) { error in
            guard case BroadcasterError.rejected(let reason) = error else {
                XCTFail("Expected rejected error, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("Invalid script"))
            XCTAssertTrue(reason.contains("locking script"))
        }
    }

    func testParseMalformedJSONThrows() {
        let data = "not json at all".data(using: .utf8)!
        XCTAssertThrowsError(try ARC.parseResponse(data: data, statusCode: 200)) { error in
            guard case BroadcasterError.invalidResponse = error else {
                XCTFail("Expected invalidResponse error")
                return
            }
        }
    }

    func testMissingTxidThrows() {
        let json = #"{"txStatus": "STORED"}"#.data(using: .utf8)!
        XCTAssertThrowsError(try ARC.parseResponse(data: json, statusCode: 200)) { error in
            guard case BroadcasterError.invalidResponse = error else {
                XCTFail("Expected invalidResponse error")
                return
            }
        }
    }

    func testARCInitialiser() {
        let arc = ARC(
            apiURL: "https://arc.example.com",
            apiKey: "test-key",
            deploymentID: "deploy-1"
        )
        XCTAssertEqual(arc.apiURL, "https://arc.example.com")
        XCTAssertEqual(arc.apiKey, "test-key")
        XCTAssertEqual(arc.deploymentID, "deploy-1")
    }
}
