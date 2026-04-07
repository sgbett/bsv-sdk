import XCTest
@testable import BSV

/// A stub ChainTracker for unit tests.
struct StubChainTracker: ChainTracker {
    let validRootHex: String
    let validHeight: UInt32
    let height: UInt32

    func isValidRootForHeight(root: Data, height: UInt32) async throws -> Bool {
        guard let expected = Data(hex: validRootHex) else { return false }
        let expectedInternal = Data(expected.reversed())
        return root == expectedInternal && height == validHeight
    }

    func currentHeight() async throws -> UInt32 {
        height
    }
}

final class ChainTrackerTests: XCTestCase {

    // MARK: - Protocol conformance

    func testStubChainTrackerValidatesRoot() async throws {
        let rootHex = "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4"
        let tracker = StubChainTracker(validRootHex: rootHex, validHeight: 813706, height: 900000)

        let internalRoot = Data(Data(hex: rootHex)!.reversed())
        let valid = try await tracker.isValidRootForHeight(root: internalRoot, height: 813706)
        XCTAssertTrue(valid)

        let invalid = try await tracker.isValidRootForHeight(root: internalRoot, height: 999999)
        XCTAssertFalse(invalid)
    }

    func testStubCurrentHeight() async throws {
        let tracker = StubChainTracker(validRootHex: "", validHeight: 0, height: 850000)
        let height = try await tracker.currentHeight()
        XCTAssertEqual(height, 850000)
    }

    // MARK: - WhatsOnChain URL construction

    func testWhatsOnChainMainnetBaseURL() {
        let tracker = WhatsOnChainTracker(network: .mainnet)
        XCTAssertEqual(tracker.baseURL, "https://api.whatsonchain.com/v1/bsv/main")
    }

    func testWhatsOnChainTestnetBaseURL() {
        let tracker = WhatsOnChainTracker(network: .testnet)
        XCTAssertEqual(tracker.baseURL, "https://api.whatsonchain.com/v1/bsv/test")
    }

    // MARK: - MerklePath verification with a stub tracker

    func testMerklePathVerificationWithTracker() async throws {
        // BRC-74 vector.
        let brc74Hex = "fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4"
        let brc74Root = "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4"
        let brc74TXID1 = "304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711"

        let mp = try MerklePath.fromHex(brc74Hex)
        let tracker = StubChainTracker(validRootHex: brc74Root, validHeight: 813706, height: 900000)

        // Compute the root from the path and verify it against the tracker.
        let txidInternal = Data(Data(hex: brc74TXID1)!.reversed())
        let computedRoot = try mp.computeRoot(txid: txidInternal)

        let isValid = try await tracker.isValidRootForHeight(
            root: computedRoot, height: mp.blockHeight
        )
        XCTAssertTrue(isValid)
    }
}
