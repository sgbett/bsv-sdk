import Foundation

/// An ECDSA signature with r and s components.
struct Signature: Sendable, Equatable {
    /// The r component (32 bytes, big-endian).
    let r: Data
    /// The s component (32 bytes, big-endian).
    let s: Data

    init(r: Data, s: Data) {
        self.r = r
        self.s = s
    }

    // MARK: - Low-S

    /// Whether the s value is in the lower half of the curve order.
    var isLowS: Bool {
        scalarCompare(s, Secp256k1.halfN) <= 0
    }

    /// Return a normalised copy with low-S.
    func lowSNormalised() -> Signature {
        if isLowS { return self }
        let newS = scalarSubN(Secp256k1.N, s)
        return Signature(r: r, s: newS)
    }

    // MARK: - DER encoding

    /// Encode the signature in DER format.
    ///
    /// Format: `0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]`
    func toDER() -> Data {
        let rb = canonicaliseInteger(r)
        let sb = canonicaliseInteger(s)
        let totalLen = rb.count + sb.count + 4 // 2 * (tag + length)

        var result = Data(capacity: totalLen + 2)
        result.append(0x30)
        result.append(UInt8(totalLen))
        result.append(0x02)
        result.append(UInt8(rb.count))
        result.append(rb)
        result.append(0x02)
        result.append(UInt8(sb.count))
        result.append(sb)
        return result
    }

    /// Parse a signature from DER format (BIP-66 strict).
    static func fromDER(_ data: Data) -> Signature? {
        // Minimum DER signature: 0x30 06 0x02 01 XX 0x02 01 XX = 8 bytes
        guard data.count >= 8 else { return nil }
        guard data[0] == 0x30 else { return nil }

        let totalLen = Int(data[1])
        guard totalLen + 2 == data.count else { return nil }
        guard totalLen + 2 >= 8 else { return nil }

        var index = 2

        // Parse R.
        guard data[index] == 0x02 else { return nil }
        index += 1
        let rLen = Int(data[index])
        index += 1
        guard rLen > 0, index + rLen <= data.count - 3 else { return nil }
        let rBytes = data[index..<(index + rLen)]
        guard isCanonicalPadding(Data(rBytes)) else { return nil }
        index += rLen

        // Parse S.
        guard data[index] == 0x02 else { return nil }
        index += 1
        let sLen = Int(data[index])
        index += 1
        guard sLen > 0, index + sLen == data.count else { return nil }
        let sBytes = data[index..<(index + sLen)]
        guard isCanonicalPadding(Data(sBytes)) else { return nil }

        // Convert to 32-byte padded values.
        let r = padTo32Bytes(Data(rBytes))
        let s = padTo32Bytes(Data(sBytes))

        // r and s must be in [1, N-1].
        guard !scalarIsZero(r), scalarCompare(r, Secp256k1.N) < 0 else { return nil }
        guard !scalarIsZero(s), scalarCompare(s, Secp256k1.N) < 0 else { return nil }

        return Signature(r: r, s: s)
    }

    // MARK: - Compact format

    /// Encode as compact format (64 bytes: r || s).
    func toCompact() -> Data {
        var result = Data(capacity: 64)
        result.append(r)
        result.append(s)
        return result
    }

    /// Parse from compact format (64 bytes: r || s).
    static func fromCompact(_ data: Data) -> Signature? {
        guard data.count == 64 else { return nil }
        let r = Data(data[0..<32])
        let s = Data(data[32..<64])
        guard !scalarIsZero(r), scalarCompare(r, Secp256k1.N) < 0 else { return nil }
        guard !scalarIsZero(s), scalarCompare(s, Secp256k1.N) < 0 else { return nil }
        return Signature(r: r, s: s)
    }
}

// MARK: - DER helpers

/// Produce the minimal DER integer encoding of a big-endian unsigned integer.
/// Strips leading zeros and adds a 0x00 pad if the high bit is set (to avoid
/// being interpreted as negative).
private func canonicaliseInteger(_ value: Data) -> Data {
    // Strip leading zero bytes.
    var trimmed = value
    while trimmed.count > 1 && trimmed[0] == 0x00 {
        trimmed = trimmed.dropFirst().asData
    }
    // If the high bit is set, prepend 0x00.
    if trimmed[0] & 0x80 != 0 {
        var padded = Data([0x00])
        padded.append(trimmed)
        return padded
    }
    return trimmed
}

/// Check BIP-66 canonical padding: no negative values, no excessive padding.
private func isCanonicalPadding(_ bytes: Data) -> Bool {
    guard !bytes.isEmpty else { return false }
    // Negative: high bit set without leading zero.
    if bytes[0] & 0x80 != 0 { return false }
    // Excessively padded: leading zero followed by a byte without high bit set.
    if bytes.count > 1 && bytes[0] == 0x00 && bytes[1] & 0x80 == 0 { return false }
    return true
}

/// Left-pad data to exactly 32 bytes, stripping any leading zero pad byte.
private func padTo32Bytes(_ data: Data) -> Data {
    // Strip leading zero bytes that are DER padding.
    var stripped = data
    while stripped.count > 32 && stripped[0] == 0x00 {
        stripped = stripped.dropFirst().asData
    }
    guard stripped.count <= 32 else { return Data(count: 32) }
    if stripped.count == 32 { return stripped }
    var padded = Data(count: 32 - stripped.count)
    padded.append(stripped)
    return padded
}

private extension Data.SubSequence {
    var asData: Data { Data(self) }
}
