import XCTest
@testable import BSV

final class MerklePathTests: XCTestCase {

    // BRC-74 test vectors from the Go SDK.
    static let brc74Hex = "fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4"

    static let brc74Root = "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4"
    static let brc74TXID1 = "304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711"
    static let brc74TXID2 = "d888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00"
    static let brc74TXID3 = "98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e"

    // MARK: - Binary round-trip

    func testParseFromHex() throws {
        let mp = try MerklePath.fromHex(Self.brc74Hex)
        XCTAssertEqual(mp.blockHeight, 813706)
        XCTAssertEqual(mp.path.count, 12)
    }

    func testRoundTrip() throws {
        let mp = try MerklePath.fromHex(Self.brc74Hex)
        let reEncoded = mp.toHex()
        XCTAssertEqual(reEncoded, Self.brc74Hex)
    }

    // MARK: - Root computation

    func testComputeRoot() throws {
        let mp = try MerklePath.fromHex(Self.brc74Hex)
        let root = try mp.computeRootHex(txid: Self.brc74TXID1)
        XCTAssertEqual(root, Self.brc74Root)
    }

    func testComputeRootForAllTxids() throws {
        let mp = try MerklePath.fromHex(Self.brc74Hex)

        let root1 = try mp.computeRootHex(txid: Self.brc74TXID1)
        let root2 = try mp.computeRootHex(txid: Self.brc74TXID2)
        let root3 = try mp.computeRootHex(txid: Self.brc74TXID3)

        XCTAssertEqual(root1, Self.brc74Root)
        XCTAssertEqual(root2, Self.brc74Root)
        XCTAssertEqual(root3, Self.brc74Root)
    }

    func testComputeRootNoTxid() throws {
        let mp = try MerklePath.fromHex(Self.brc74Hex)
        let root = try mp.computeRootHex()
        XCTAssertEqual(root, Self.brc74Root)
    }

    // MARK: - Error cases

    func testInsufficientData() {
        XCTAssertThrowsError(try MerklePath.fromBinary(Data([0x01])))
    }

    func testInvalidHex() {
        XCTAssertThrowsError(try MerklePath.fromHex("zzzz"))
    }

    func testTxidNotFound() throws {
        let mp = try MerklePath.fromHex(Self.brc74Hex)
        let fakeTxid = String(repeating: "ab", count: 32)
        XCTAssertThrowsError(try mp.computeRootHex(txid: fakeTxid))
    }

    // MARK: - Single transaction block

    func testSingleTransactionBlock() throws {
        // A block with only one transaction — the root equals the txid.
        let txidHex = "aabbccdd" + String(repeating: "00", count: 28)
        guard let txidData = Data(hex: txidHex) else {
            XCTFail("Failed to create txid data")
            return
        }
        let internalData = Data(txidData.reversed())

        let mp = MerklePath(
            blockHeight: 100,
            path: [[MerklePathLeaf(offset: 0, hash: internalData, txid: true)]]
        )

        let root = try mp.computeRoot(txid: internalData)
        XCTAssertEqual(root, internalData)
    }
}
