// SPDX-License-Identifier: Open BSV License Version 5
// Constant-time byte comparison helpers shared across the SDK.
//
// Used wherever a buffer comparison must not leak information about
// which byte diverged — for example HMAC / MAC verification in
// `ProtoWallet` and `AuthNonce`. Lifting this out of `ProtoWallet`
// avoids cross-module reach-through from the Auth layer.

import Foundation

/// Byte helpers that run in data-independent time.
enum ConstantTime {
    /// Compare two byte buffers without early-exit, so the comparison
    /// takes the same time regardless of where they first differ. Returns
    /// `false` immediately when the lengths differ — length is not a
    /// secret in the SDK's use cases.
    static func equal(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return diff == 0
    }
}
