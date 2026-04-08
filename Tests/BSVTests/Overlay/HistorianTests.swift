import XCTest
@testable import BSV

final class HistorianTests: XCTestCase {

    /// Build a simple chain: tip -> parent -> grandparent, each with one output
    /// whose locking script is a 4-byte little-endian encoding of the value.
    private func makeChain() -> Transaction {
        func txWithValue(_ value: UInt32, parent: Transaction?) -> Transaction {
            var data = Data(count: 4)
            data.withUnsafeMutableBytes { bytes in
                bytes.storeBytes(of: value.littleEndian, as: UInt32.self)
            }
            let output = TransactionOutput(
                satoshis: 1,
                lockingScript: Script(data: data)
            )
            var input = TransactionInput()
            if let parent {
                input.sourceTransaction = parent
            }
            return Transaction(
                version: 1,
                inputs: [input],
                outputs: [output],
                lockTime: 0
            )
        }

        let grandparent = txWithValue(1, parent: nil)
        let parent = txWithValue(2, parent: grandparent)
        let tip = txWithValue(3, parent: parent)
        return tip
    }

    func testBuildsChronologicalHistoryFromInputChain() async throws {
        let tip = makeChain()
        let historian = Historian<UInt32, String>(
            interpreter: { tx, outputIndex, _ in
                let data = tx.outputs[outputIndex].lockingScript.toBinary()
                guard data.count == 4 else { return nil }
                return data.withUnsafeBytes { $0.load(as: UInt32.self) }.littleEndian
            }
        )
        let history = try await historian.buildHistory(startTransaction: tip)
        XCTAssertEqual(history, [1, 2, 3])
    }

    func testCacheReusesPreviousResult() async throws {
        let tip = makeChain()
        var counter = 0
        let historian = Historian<UInt32, String>(
            interpreter: { tx, outputIndex, _ in
                counter += 1
                let data = tx.outputs[outputIndex].lockingScript.toBinary()
                guard data.count == 4 else { return nil }
                return data.withUnsafeBytes { $0.load(as: UInt32.self) }.littleEndian
            },
            enableCache: true
        )
        _ = try await historian.buildHistory(startTransaction: tip)
        let callsAfterFirst = counter
        _ = try await historian.buildHistory(startTransaction: tip)
        XCTAssertEqual(counter, callsAfterFirst, "second build should hit the cache")
    }
}
