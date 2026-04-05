// SPDX-License-Identifier: Open BSV License Version 5
// Sighash flag types for Bitcoin transaction signing.

import Foundation

/// Sighash flags used at the end of a signature to indicate which parts
/// of the transaction are covered.
public struct SighashType: OptionSet, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    // Base types
    public static let all            = SighashType(rawValue: 0x01)
    public static let none           = SighashType(rawValue: 0x02)
    public static let single         = SighashType(rawValue: 0x03)
    public static let anyOneCanPay   = SighashType(rawValue: 0x80)

    // ForkID flag (required for BSV post-UAHF)
    public static let forkID         = SighashType(rawValue: 0x40)

    // Common BSV combinations
    public static let allForkID: SighashType = [.all, .forkID]
    public static let noneForkID: SighashType = [.none, .forkID]
    public static let singleForkID: SighashType = [.single, .forkID]

    /// Mask for the base sighash type (lower 5 bits).
    public static let mask: UInt32 = 0x1f

    /// The base type (ALL, NONE, or SINGLE) without modifier flags.
    public var baseType: UInt32 {
        return rawValue & SighashType.mask
    }

    /// Whether this sighash includes the FORKID flag.
    public var hasForkID: Bool {
        return contains(.forkID)
    }

    /// Whether this sighash includes ANYONECANPAY.
    public var hasAnyOneCanPay: Bool {
        return contains(.anyOneCanPay)
    }
}
