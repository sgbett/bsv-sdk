import XCTest
@testable import BSV

final class OverlayAdminTokenTemplateTests: XCTestCase {

    func testLockProducesDecodableSHIPAdvertisement() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let template = OverlayAdminTokenTemplate(wallet: wallet)

        let script = try await template.lock(
            protocol: .ship,
            domain: "https://overlay.example",
            topicOrService: "tm_demo"
        )

        let decoded = try OverlayAdminTokenTemplate.decode(script)
        XCTAssertEqual(decoded.protocolKind, .ship)
        XCTAssertEqual(decoded.domain, "https://overlay.example")
        XCTAssertEqual(decoded.topicOrService, "tm_demo")

        // identityKey should match the wallet's identity key in compressed hex.
        let identity = try await wallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey
        XCTAssertEqual(decoded.identityKey, identity.toCompressed().hex)
    }

    func testLockProducesDecodableSLAPAdvertisement() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let template = OverlayAdminTokenTemplate(wallet: wallet)

        let script = try await template.lock(
            protocol: .slap,
            domain: "https://lookup.example",
            topicOrService: "ls_demo"
        )

        let decoded = try OverlayAdminTokenTemplate.decode(script)
        XCTAssertEqual(decoded.protocolKind, .slap)
        XCTAssertEqual(decoded.domain, "https://lookup.example")
        XCTAssertEqual(decoded.topicOrService, "ls_demo")
    }

    func testDecodeRejectsNonSHIPSLAPScripts() {
        // Not long enough / wrong structure.
        let script = Script(data: Data([OpCodes.OP_TRUE]))
        XCTAssertThrowsError(try OverlayAdminTokenTemplate.decode(script))
    }
}
