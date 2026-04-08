import Foundation

/// Pure-Swift implementation of the RIPEMD-160 hash function.
///
/// Reference: https://homes.esat.kuleuven.be/~bosMDpi/ripemd160.html
public enum RIPEMD160 {

    /// Compute the RIPEMD-160 digest of the given data.
    public static func hash(_ data: Data) -> Data {
        var h0: UInt32 = 0x67452301
        var h1: UInt32 = 0xefcdab89
        var h2: UInt32 = 0x98badcfe
        var h3: UInt32 = 0x10325476
        var h4: UInt32 = 0xc3d2e1f0

        // Pre-processing: adding padding bits
        var message = Array(data)
        let originalLength = message.count
        message.append(0x80)
        while message.count % 64 != 56 {
            message.append(0x00)
        }
        // Append length in bits as 64-bit little-endian
        let bitLength = UInt64(originalLength) * 8
        for i in 0..<8 {
            message.append(UInt8(truncatingIfNeeded: bitLength >> (i * 8)))
        }

        // Process each 512-bit block
        let blockCount = message.count / 64
        for i in 0..<blockCount {
            var x = [UInt32](repeating: 0, count: 16)
            for j in 0..<16 {
                let offset = i * 64 + j * 4
                x[j] = UInt32(message[offset])
                    | (UInt32(message[offset + 1]) << 8)
                    | (UInt32(message[offset + 2]) << 16)
                    | (UInt32(message[offset + 3]) << 24)
            }

            var al = h0, bl = h1, cl = h2, dl = h3, el = h4
            var ar = h0, br = h1, cr = h2, dr = h3, er = h4

            // Left rounds
            for j in 0..<80 {
                var f: UInt32
                var k: UInt32
                let r: Int
                let s: Int

                if j < 16 {
                    f = bl ^ cl ^ dl
                    k = 0x00000000
                    r = rl[j]; s = sl[j]
                } else if j < 32 {
                    f = (bl & cl) | (~bl & dl)
                    k = 0x5a827999
                    r = rl[j]; s = sl[j]
                } else if j < 48 {
                    f = (bl | ~cl) ^ dl
                    k = 0x6ed9eba1
                    r = rl[j]; s = sl[j]
                } else if j < 64 {
                    f = (bl & dl) | (cl & ~dl)
                    k = 0x8f1bbcdc
                    r = rl[j]; s = sl[j]
                } else {
                    f = bl ^ (cl | ~dl)
                    k = 0xa953fd4e
                    r = rl[j]; s = sl[j]
                }

                let t = (al &+ f &+ x[r] &+ k).rotatedLeft(by: s) &+ el
                al = el; el = dl; dl = cl.rotatedLeft(by: 10); cl = bl; bl = t
            }

            // Right rounds
            for j in 0..<80 {
                var f: UInt32
                var k: UInt32
                let r: Int
                let s: Int

                if j < 16 {
                    f = br ^ (cr | ~dr)
                    k = 0x50a28be6
                    r = rr[j]; s = sr[j]
                } else if j < 32 {
                    f = (br & dr) | (cr & ~dr)
                    k = 0x5c4dd124
                    r = rr[j]; s = sr[j]
                } else if j < 48 {
                    f = (br | ~cr) ^ dr
                    k = 0x6d703ef3
                    r = rr[j]; s = sr[j]
                } else if j < 64 {
                    f = (br & cr) | (~br & dr)
                    k = 0x7a6d76e9
                    r = rr[j]; s = sr[j]
                } else {
                    f = br ^ cr ^ dr
                    k = 0x00000000
                    r = rr[j]; s = sr[j]
                }

                let t = (ar &+ f &+ x[r] &+ k).rotatedLeft(by: s) &+ er
                ar = er; er = dr; dr = cr.rotatedLeft(by: 10); cr = br; br = t
            }

            let t = h1 &+ cl &+ dr
            h1 = h2 &+ dl &+ er
            h2 = h3 &+ el &+ ar
            h3 = h4 &+ al &+ br
            h4 = h0 &+ bl &+ cr
            h0 = t
        }

        var result = Data(capacity: 20)
        for value in [h0, h1, h2, h3, h4] {
            result.append(UInt8(truncatingIfNeeded: value))
            result.append(UInt8(truncatingIfNeeded: value >> 8))
            result.append(UInt8(truncatingIfNeeded: value >> 16))
            result.append(UInt8(truncatingIfNeeded: value >> 24))
        }
        return result
    }

    // MARK: - Constants

    // Left message word selection
    private static let rl: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
    ]

    // Right message word selection
    private static let rr: [Int] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
    ]

    // Left rotation amounts
    private static let sl: [Int] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
    ]

    // Right rotation amounts
    private static let sr: [Int] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
    ]
}

private extension UInt32 {
    func rotatedLeft(by count: Int) -> UInt32 {
        (self << count) | (self >> (32 - count))
    }
}
