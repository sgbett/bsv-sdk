// SPDX-License-Identifier: Open BSV License Version 5
// Fee model protocol and standard satoshis-per-kilobyte implementation.

import Foundation

/// Protocol for computing transaction fees.
public protocol FeeModel {
    /// Compute the fee in satoshis for the given transaction.
    func computeFee(tx: Transaction) -> UInt64
}

/// Standard fee model: a fixed rate of satoshis per kilobyte.
public struct SatoshisPerKilobyte: FeeModel {
    /// Fee rate in satoshis per 1000 bytes. Default: 50.
    public let satoshis: UInt64

    public init(satoshis: UInt64 = 50) {
        self.satoshis = satoshis
    }

    public func computeFee(tx: Transaction) -> UInt64 {
        let size = tx.estimatedSize()
        return calculateFee(txSizeBytes: size, satoshisPerKB: satoshis)
    }

    private func calculateFee(txSizeBytes: Int, satoshisPerKB: UInt64) -> UInt64 {
        let fee = Double(txSizeBytes) / 1000.0 * Double(satoshisPerKB)
        return UInt64(ceil(fee))
    }
}
