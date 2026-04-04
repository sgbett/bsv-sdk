import XCTest
@testable import BSV

final class BSVVersionTests: XCTestCase {
    func testVersion() {
        XCTAssertEqual(BSV.version, "0.1.0")
    }
}
