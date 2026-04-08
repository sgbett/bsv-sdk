import Foundation

// MARK: - Constants

/// Number of words in the internal representation.
private let fieldWords = 10

/// Exponent for the numeric base of each word (2^26).
private let fieldBase: UInt32 = 26

/// Mask for the bits in each word (except the most significant).
private let fieldBaseMask: UInt64 = (1 << 26) - 1

/// Number of bits in the most significant word: 256 - (26 * 9) = 22.
private let fieldMSBBits: UInt32 = 256 - (26 * 9)

/// Mask for the bits in the most significant word.
private let fieldMSBMask: UInt64 = (1 << 22) - 1

/// Word zero of the secp256k1 prime in the internal representation.
private let fieldPrimeWordZero: UInt32 = 0x3FFFC2F

/// Word one of the secp256k1 prime in the internal representation.
private let fieldPrimeWordOne: UInt32 = 0x3FFFFBF

/// Q = (P+1)/4 for computing square roots via exponentiation.
private let fieldQBytes: [UInt8] = [
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c,
]

// MARK: - FieldElement

/// Fixed-precision arithmetic over the secp256k1 finite field.
///
/// All arithmetic is performed modulo the secp256k1 prime:
/// p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
///
/// Internally represents each 256-bit value as 10 UInt32 words in base 2^26.
/// This provides 6 bits of overflow per word (10 in the MSW), totalling 64 bits
/// of overflow across the entire value.
struct FieldElement: Sendable, Equatable {
    var n: (UInt32, UInt32, UInt32, UInt32, UInt32,
            UInt32, UInt32, UInt32, UInt32, UInt32)

    /// Create a zero field element.
    init() {
        n = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }

    /// Create a field element from an integer.
    init(_ value: UInt32) {
        n = (value, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }

    // MARK: - Subscript access

    /// Access individual words by index.
    subscript(index: Int) -> UInt32 {
        get {
            switch index {
            case 0: return n.0
            case 1: return n.1
            case 2: return n.2
            case 3: return n.3
            case 4: return n.4
            case 5: return n.5
            case 6: return n.6
            case 7: return n.7
            case 8: return n.8
            case 9: return n.9
            default: fatalError("FieldElement index out of range")
            }
        }
        set {
            switch index {
            case 0: n.0 = newValue
            case 1: n.1 = newValue
            case 2: n.2 = newValue
            case 3: n.3 = newValue
            case 4: n.4 = newValue
            case 5: n.5 = newValue
            case 6: n.6 = newValue
            case 7: n.7 = newValue
            case 8: n.8 = newValue
            case 9: n.9 = newValue
            default: fatalError("FieldElement index out of range")
            }
        }
    }

    // MARK: - Initialisation from bytes

    /// Initialise from a 32-byte big-endian representation.
    init(bytes b: Data) {
        precondition(b.count == 32, "Field element requires exactly 32 bytes")
        self.init()

        // Pack 256 bits across 10 words of base 2^26 (unrolled for performance).
        n.0 = UInt32(b[31]) | UInt32(b[30]) << 8 | UInt32(b[29]) << 16 |
              (UInt32(b[28]) & 0x3) << 24
        n.1 = UInt32(b[28]) >> 2 | UInt32(b[27]) << 6 | UInt32(b[26]) << 14 |
              (UInt32(b[25]) & 0xF) << 22
        n.2 = UInt32(b[25]) >> 4 | UInt32(b[24]) << 4 | UInt32(b[23]) << 12 |
              (UInt32(b[22]) & 0x3F) << 20
        n.3 = UInt32(b[22]) >> 6 | UInt32(b[21]) << 2 | UInt32(b[20]) << 10 |
              UInt32(b[19]) << 18
        n.4 = UInt32(b[18]) | UInt32(b[17]) << 8 | UInt32(b[16]) << 16 |
              (UInt32(b[15]) & 0x3) << 24
        n.5 = UInt32(b[15]) >> 2 | UInt32(b[14]) << 6 | UInt32(b[13]) << 14 |
              (UInt32(b[12]) & 0xF) << 22
        n.6 = UInt32(b[12]) >> 4 | UInt32(b[11]) << 4 | UInt32(b[10]) << 12 |
              (UInt32(b[9]) & 0x3F) << 20
        n.7 = UInt32(b[9]) >> 6 | UInt32(b[8]) << 2 | UInt32(b[7]) << 10 |
              UInt32(b[6]) << 18
        n.8 = UInt32(b[5]) | UInt32(b[4]) << 8 | UInt32(b[3]) << 16 |
              (UInt32(b[2]) & 0x3) << 24
        n.9 = UInt32(b[2]) >> 2 | UInt32(b[1]) << 6 | UInt32(b[0]) << 14
    }

    /// Initialise from a hex string.
    init?(hex: String) {
        guard let data = Data(hex: hex), data.count <= 32 else { return nil }
        // Left-pad to 32 bytes.
        var padded = Data(count: 32 - data.count)
        padded.append(data)
        self.init(bytes: padded)
    }

    // MARK: - Serialisation

    /// Serialise to a 32-byte big-endian representation.
    /// The field element must be normalised before calling this.
    func toBytes() -> Data {
        var b = Data(count: 32)
        b[31] = UInt8(n.0 & 0xFF)
        b[30] = UInt8((n.0 >> 8) & 0xFF)
        b[29] = UInt8((n.0 >> 16) & 0xFF)
        b[28] = UInt8((n.0 >> 24) & 0x3 | (n.1 & 0x3F) << 2)
        b[27] = UInt8((n.1 >> 6) & 0xFF)
        b[26] = UInt8((n.1 >> 14) & 0xFF)
        b[25] = UInt8((n.1 >> 22) & 0xF | (n.2 & 0xF) << 4)
        b[24] = UInt8((n.2 >> 4) & 0xFF)
        b[23] = UInt8((n.2 >> 12) & 0xFF)
        b[22] = UInt8((n.2 >> 20) & 0x3F | (n.3 & 0x3) << 6)
        b[21] = UInt8((n.3 >> 2) & 0xFF)
        b[20] = UInt8((n.3 >> 10) & 0xFF)
        b[19] = UInt8((n.3 >> 18) & 0xFF)
        b[18] = UInt8(n.4 & 0xFF)
        b[17] = UInt8((n.4 >> 8) & 0xFF)
        b[16] = UInt8((n.4 >> 16) & 0xFF)
        b[15] = UInt8((n.4 >> 24) & 0x3 | (n.5 & 0x3F) << 2)
        b[14] = UInt8((n.5 >> 6) & 0xFF)
        b[13] = UInt8((n.5 >> 14) & 0xFF)
        b[12] = UInt8((n.5 >> 22) & 0xF | (n.6 & 0xF) << 4)
        b[11] = UInt8((n.6 >> 4) & 0xFF)
        b[10] = UInt8((n.6 >> 12) & 0xFF)
        b[9]  = UInt8((n.6 >> 20) & 0x3F | (n.7 & 0x3) << 6)
        b[8]  = UInt8((n.7 >> 2) & 0xFF)
        b[7]  = UInt8((n.7 >> 10) & 0xFF)
        b[6]  = UInt8((n.7 >> 18) & 0xFF)
        b[5]  = UInt8(n.8 & 0xFF)
        b[4]  = UInt8((n.8 >> 8) & 0xFF)
        b[3]  = UInt8((n.8 >> 16) & 0xFF)
        b[2]  = UInt8((n.8 >> 24) & 0x3 | (n.9 & 0x3F) << 2)
        b[1]  = UInt8((n.9 >> 6) & 0xFF)
        b[0]  = UInt8((n.9 >> 14) & 0xFF)
        return b
    }

    /// Hex string representation (normalises first).
    var hex: String {
        normalised().toBytes().hex
    }

    // MARK: - Predicates

    /// Whether this field element is zero (must be normalised).
    var isZero: Bool {
        (n.0 | n.1 | n.2 | n.3 | n.4 | n.5 | n.6 | n.7 | n.8 | n.9) == 0
    }

    /// Whether this field element is one (must be normalised).
    var isOne: Bool {
        n.0 == 1 &&
        (n.1 | n.2 | n.3 | n.4 | n.5 | n.6 | n.7 | n.8 | n.9) == 0
    }

    /// Whether the field element is odd (must be normalised).
    var isOdd: Bool {
        n.0 & 1 == 1
    }

    static func == (lhs: FieldElement, rhs: FieldElement) -> Bool {
        let bits = (lhs.n.0 ^ rhs.n.0) | (lhs.n.1 ^ rhs.n.1) |
                   (lhs.n.2 ^ rhs.n.2) | (lhs.n.3 ^ rhs.n.3) |
                   (lhs.n.4 ^ rhs.n.4) | (lhs.n.5 ^ rhs.n.5) |
                   (lhs.n.6 ^ rhs.n.6) | (lhs.n.7 ^ rhs.n.7) |
                   (lhs.n.8 ^ rhs.n.8) | (lhs.n.9 ^ rhs.n.9)
        return bits == 0
    }

    // MARK: - Normalisation

    /// Normalise the field element — propagate carries and reduce mod p.
    mutating func normalise() {
        // Propagate carries through all words.
        var t9 = UInt64(n.9)
        let m = t9 >> fieldMSBBits
        t9 = t9 & fieldMSBMask
        var t0 = UInt64(n.0) + m * 977
        var t1 = (t0 >> UInt64(fieldBase)) + UInt64(n.1) + (m << 6)
        t0 = t0 & fieldBaseMask
        var t2 = (t1 >> UInt64(fieldBase)) + UInt64(n.2)
        t1 = t1 & fieldBaseMask
        var t3 = (t2 >> UInt64(fieldBase)) + UInt64(n.3)
        t2 = t2 & fieldBaseMask
        var t4 = (t3 >> UInt64(fieldBase)) + UInt64(n.4)
        t3 = t3 & fieldBaseMask
        var t5 = (t4 >> UInt64(fieldBase)) + UInt64(n.5)
        t4 = t4 & fieldBaseMask
        var t6 = (t5 >> UInt64(fieldBase)) + UInt64(n.6)
        t5 = t5 & fieldBaseMask
        var t7 = (t6 >> UInt64(fieldBase)) + UInt64(n.7)
        t6 = t6 & fieldBaseMask
        var t8 = (t7 >> UInt64(fieldBase)) + UInt64(n.8)
        t7 = t7 & fieldBaseMask
        t9 = (t8 >> UInt64(fieldBase)) + t9
        t8 = t8 & fieldBaseMask

        // Final reduction: check if value >= p and subtract p if so.
        var fm: UInt64 = 1
        if t9 == fieldMSBMask { fm &= 1 } else { fm &= 0 }
        if t2 & t3 & t4 & t5 & t6 & t7 & t8 == fieldBaseMask { fm &= 1 } else { fm &= 0 }
        if ((t0 + 977) >> UInt64(fieldBase) + t1 + 64) > fieldBaseMask { fm &= 1 } else { fm &= 0 }
        if t9 >> fieldMSBBits != 0 { fm |= 1 } else { fm |= 0 }

        t0 = t0 + fm * 977
        t1 = (t0 >> UInt64(fieldBase)) + t1 + (fm << 6)
        t0 = t0 & fieldBaseMask
        t2 = (t1 >> UInt64(fieldBase)) + t2
        t1 = t1 & fieldBaseMask
        t3 = (t2 >> UInt64(fieldBase)) + t3
        t2 = t2 & fieldBaseMask
        t4 = (t3 >> UInt64(fieldBase)) + t4
        t3 = t3 & fieldBaseMask
        t5 = (t4 >> UInt64(fieldBase)) + t5
        t4 = t4 & fieldBaseMask
        t6 = (t5 >> UInt64(fieldBase)) + t6
        t5 = t5 & fieldBaseMask
        t7 = (t6 >> UInt64(fieldBase)) + t7
        t6 = t6 & fieldBaseMask
        t8 = (t7 >> UInt64(fieldBase)) + t8
        t7 = t7 & fieldBaseMask
        t9 = (t8 >> UInt64(fieldBase)) + t9
        t8 = t8 & fieldBaseMask
        t9 = t9 & fieldMSBMask

        n.0 = UInt32(t0); n.1 = UInt32(t1); n.2 = UInt32(t2)
        n.3 = UInt32(t3); n.4 = UInt32(t4); n.5 = UInt32(t5)
        n.6 = UInt32(t6); n.7 = UInt32(t7); n.8 = UInt32(t8)
        n.9 = UInt32(t9)
    }

    /// Return a normalised copy.
    func normalised() -> FieldElement {
        var f = self
        f.normalise()
        return f
    }

    // MARK: - Negation

    /// Negate the field value. The caller must provide the magnitude of the
    /// current value for a correct result.
    mutating func negate(magnitude: UInt32) {
        let m = magnitude + 1
        n.0 = m * fieldPrimeWordZero - n.0
        n.1 = m * fieldPrimeWordOne - n.1
        n.2 = m * UInt32(fieldBaseMask) - n.2
        n.3 = m * UInt32(fieldBaseMask) - n.3
        n.4 = m * UInt32(fieldBaseMask) - n.4
        n.5 = m * UInt32(fieldBaseMask) - n.5
        n.6 = m * UInt32(fieldBaseMask) - n.6
        n.7 = m * UInt32(fieldBaseMask) - n.7
        n.8 = m * UInt32(fieldBaseMask) - n.8
        n.9 = m * UInt32(fieldMSBMask) - n.9
    }

    /// Return the negation (assumes magnitude 1).
    func negated(magnitude: UInt32 = 1) -> FieldElement {
        var f = self
        f.negate(magnitude: magnitude)
        return f
    }

    // MARK: - Addition

    /// Add a small integer.
    mutating func addInt(_ ui: UInt32) {
        n.0 += ui
    }

    /// Add another field element.
    mutating func add(_ val: FieldElement) {
        n.0 += val.n.0; n.1 += val.n.1; n.2 += val.n.2; n.3 += val.n.3
        n.4 += val.n.4; n.5 += val.n.5; n.6 += val.n.6; n.7 += val.n.7
        n.8 += val.n.8; n.9 += val.n.9
    }

    /// Return the sum of two field elements.
    static func add(_ a: FieldElement, _ b: FieldElement) -> FieldElement {
        var r = a
        r.add(b)
        return r
    }

    // MARK: - Multiplication by integer

    /// Multiply by a small integer.
    mutating func mulInt(_ val: UInt32) {
        n.0 *= val; n.1 *= val; n.2 *= val; n.3 *= val; n.4 *= val
        n.5 *= val; n.6 *= val; n.7 *= val; n.8 *= val; n.9 *= val
    }

    // MARK: - Multiplication

    /// Multiply two field elements and store the result in self.
    mutating func mul2(_ val: FieldElement, _ val2: FieldElement) {
        let bm = fieldBaseMask
        let msbm = fieldMSBMask

        // Schoolbook multiplication with 10 x 10 cross terms.
        // Terms for 2^(26*0).
        var m = UInt64(val.n.0) &* UInt64(val2.n.0)
        let t0 = m & bm

        // Terms for 2^(26*1).
        m = (m >> 26) &+
            UInt64(val.n.0) &* UInt64(val2.n.1) &+
            UInt64(val.n.1) &* UInt64(val2.n.0)
        let t1 = m & bm

        // Terms for 2^(26*2).
        m = (m >> 26) &+
            UInt64(val.n.0) &* UInt64(val2.n.2) &+
            UInt64(val.n.1) &* UInt64(val2.n.1) &+
            UInt64(val.n.2) &* UInt64(val2.n.0)
        let t2 = m & bm

        // Terms for 2^(26*3).
        m = (m >> 26) &+
            UInt64(val.n.0) &* UInt64(val2.n.3) &+
            UInt64(val.n.1) &* UInt64(val2.n.2) &+
            UInt64(val.n.2) &* UInt64(val2.n.1) &+
            UInt64(val.n.3) &* UInt64(val2.n.0)
        let t3 = m & bm

        // Terms for 2^(26*4).
        m = (m >> 26) &+
            UInt64(val.n.0) &* UInt64(val2.n.4) &+
            UInt64(val.n.1) &* UInt64(val2.n.3) &+
            UInt64(val.n.2) &* UInt64(val2.n.2) &+
            UInt64(val.n.3) &* UInt64(val2.n.1) &+
            UInt64(val.n.4) &* UInt64(val2.n.0)
        let t4 = m & bm

        // Terms for 2^(26*5).
        m = (m >> 26) &+
            UInt64(val.n.0) &* UInt64(val2.n.5) &+
            UInt64(val.n.1) &* UInt64(val2.n.4) &+
            UInt64(val.n.2) &* UInt64(val2.n.3) &+
            UInt64(val.n.3) &* UInt64(val2.n.2) &+
            UInt64(val.n.4) &* UInt64(val2.n.1) &+
            UInt64(val.n.5) &* UInt64(val2.n.0)
        let t5 = m & bm

        // Terms for 2^(26*6).
        m = (m >> 26) &+
            UInt64(val.n.0) &* UInt64(val2.n.6) &+
            UInt64(val.n.1) &* UInt64(val2.n.5) &+
            UInt64(val.n.2) &* UInt64(val2.n.4) &+
            UInt64(val.n.3) &* UInt64(val2.n.3) &+
            UInt64(val.n.4) &* UInt64(val2.n.2) &+
            UInt64(val.n.5) &* UInt64(val2.n.1) &+
            UInt64(val.n.6) &* UInt64(val2.n.0)
        let t6 = m & bm

        // Terms for 2^(26*7).
        m = (m >> 26) &+
            UInt64(val.n.0) &* UInt64(val2.n.7) &+
            UInt64(val.n.1) &* UInt64(val2.n.6) &+
            UInt64(val.n.2) &* UInt64(val2.n.5) &+
            UInt64(val.n.3) &* UInt64(val2.n.4) &+
            UInt64(val.n.4) &* UInt64(val2.n.3) &+
            UInt64(val.n.5) &* UInt64(val2.n.2) &+
            UInt64(val.n.6) &* UInt64(val2.n.1) &+
            UInt64(val.n.7) &* UInt64(val2.n.0)
        let t7 = m & bm

        // Terms for 2^(26*8).
        m = (m >> 26) &+
            UInt64(val.n.0) &* UInt64(val2.n.8) &+
            UInt64(val.n.1) &* UInt64(val2.n.7) &+
            UInt64(val.n.2) &* UInt64(val2.n.6) &+
            UInt64(val.n.3) &* UInt64(val2.n.5) &+
            UInt64(val.n.4) &* UInt64(val2.n.4) &+
            UInt64(val.n.5) &* UInt64(val2.n.3) &+
            UInt64(val.n.6) &* UInt64(val2.n.2) &+
            UInt64(val.n.7) &* UInt64(val2.n.1) &+
            UInt64(val.n.8) &* UInt64(val2.n.0)
        let t8 = m & bm

        // Terms for 2^(26*9).
        m = (m >> 26) &+
            UInt64(val.n.0) &* UInt64(val2.n.9) &+
            UInt64(val.n.1) &* UInt64(val2.n.8) &+
            UInt64(val.n.2) &* UInt64(val2.n.7) &+
            UInt64(val.n.3) &* UInt64(val2.n.6) &+
            UInt64(val.n.4) &* UInt64(val2.n.5) &+
            UInt64(val.n.5) &* UInt64(val2.n.4) &+
            UInt64(val.n.6) &* UInt64(val2.n.3) &+
            UInt64(val.n.7) &* UInt64(val2.n.2) &+
            UInt64(val.n.8) &* UInt64(val2.n.1) &+
            UInt64(val.n.9) &* UInt64(val2.n.0)
        var t9 = m & bm

        // Terms for 2^(26*10).
        m = (m >> 26) &+
            UInt64(val.n.1) &* UInt64(val2.n.9) &+
            UInt64(val.n.2) &* UInt64(val2.n.8) &+
            UInt64(val.n.3) &* UInt64(val2.n.7) &+
            UInt64(val.n.4) &* UInt64(val2.n.6) &+
            UInt64(val.n.5) &* UInt64(val2.n.5) &+
            UInt64(val.n.6) &* UInt64(val2.n.4) &+
            UInt64(val.n.7) &* UInt64(val2.n.3) &+
            UInt64(val.n.8) &* UInt64(val2.n.2) &+
            UInt64(val.n.9) &* UInt64(val2.n.1)
        let t10 = m & bm

        // Terms for 2^(26*11).
        m = (m >> 26) &+
            UInt64(val.n.2) &* UInt64(val2.n.9) &+
            UInt64(val.n.3) &* UInt64(val2.n.8) &+
            UInt64(val.n.4) &* UInt64(val2.n.7) &+
            UInt64(val.n.5) &* UInt64(val2.n.6) &+
            UInt64(val.n.6) &* UInt64(val2.n.5) &+
            UInt64(val.n.7) &* UInt64(val2.n.4) &+
            UInt64(val.n.8) &* UInt64(val2.n.3) &+
            UInt64(val.n.9) &* UInt64(val2.n.2)
        let t11 = m & bm

        // Terms for 2^(26*12).
        m = (m >> 26) &+
            UInt64(val.n.3) &* UInt64(val2.n.9) &+
            UInt64(val.n.4) &* UInt64(val2.n.8) &+
            UInt64(val.n.5) &* UInt64(val2.n.7) &+
            UInt64(val.n.6) &* UInt64(val2.n.6) &+
            UInt64(val.n.7) &* UInt64(val2.n.5) &+
            UInt64(val.n.8) &* UInt64(val2.n.4) &+
            UInt64(val.n.9) &* UInt64(val2.n.3)
        let t12 = m & bm

        // Terms for 2^(26*13).
        m = (m >> 26) &+
            UInt64(val.n.4) &* UInt64(val2.n.9) &+
            UInt64(val.n.5) &* UInt64(val2.n.8) &+
            UInt64(val.n.6) &* UInt64(val2.n.7) &+
            UInt64(val.n.7) &* UInt64(val2.n.6) &+
            UInt64(val.n.8) &* UInt64(val2.n.5) &+
            UInt64(val.n.9) &* UInt64(val2.n.4)
        let t13 = m & bm

        // Terms for 2^(26*14).
        m = (m >> 26) &+
            UInt64(val.n.5) &* UInt64(val2.n.9) &+
            UInt64(val.n.6) &* UInt64(val2.n.8) &+
            UInt64(val.n.7) &* UInt64(val2.n.7) &+
            UInt64(val.n.8) &* UInt64(val2.n.6) &+
            UInt64(val.n.9) &* UInt64(val2.n.5)
        let t14 = m & bm

        // Terms for 2^(26*15).
        m = (m >> 26) &+
            UInt64(val.n.6) &* UInt64(val2.n.9) &+
            UInt64(val.n.7) &* UInt64(val2.n.8) &+
            UInt64(val.n.8) &* UInt64(val2.n.7) &+
            UInt64(val.n.9) &* UInt64(val2.n.6)
        let t15 = m & bm

        // Terms for 2^(26*16).
        m = (m >> 26) &+
            UInt64(val.n.7) &* UInt64(val2.n.9) &+
            UInt64(val.n.8) &* UInt64(val2.n.8) &+
            UInt64(val.n.9) &* UInt64(val2.n.7)
        let t16 = m & bm

        // Terms for 2^(26*17).
        m = (m >> 26) &+
            UInt64(val.n.8) &* UInt64(val2.n.9) &+
            UInt64(val.n.9) &* UInt64(val2.n.8)
        let t17 = m & bm

        // Terms for 2^(26*18).
        m = (m >> 26) &+ UInt64(val.n.9) &* UInt64(val2.n.9)
        let t18 = m & bm

        // Remainder for 2^(26*19).
        let t19 = m >> 26

        // Reduce using p = 2^256 - 4294968273, where 4294968273 in base-2^26
        // is (n[0]=977, n[1]=64). Upper terms are at 260 bits so multiply c by 16.
        m = t0 &+ t10 &* 15632
        var r0 = m & bm
        m = (m >> 26) &+ t1 &+ t10 &* 1024 &+ t11 &* 15632
        var r1 = m & bm
        m = (m >> 26) &+ t2 &+ t11 &* 1024 &+ t12 &* 15632
        var r2 = m & bm
        m = (m >> 26) &+ t3 &+ t12 &* 1024 &+ t13 &* 15632
        let r3 = m & bm
        m = (m >> 26) &+ t4 &+ t13 &* 1024 &+ t14 &* 15632
        let r4 = m & bm
        m = (m >> 26) &+ t5 &+ t14 &* 1024 &+ t15 &* 15632
        let r5 = m & bm
        m = (m >> 26) &+ t6 &+ t15 &* 1024 &+ t16 &* 15632
        let r6 = m & bm
        m = (m >> 26) &+ t7 &+ t16 &* 1024 &+ t17 &* 15632
        let r7 = m & bm
        m = (m >> 26) &+ t8 &+ t17 &* 1024 &+ t18 &* 15632
        let r8 = m & bm
        m = (m >> 26) &+ t9 &+ t18 &* 1024 &+ t19 &* 68719492368
        t9 = m & msbm
        m = m >> fieldMSBBits

        // Final single iteration.
        let d = r0 &+ m &* 977
        r0 = d & bm
        let d2 = (d >> 26) &+ r1 &+ m &* 64
        r1 = d2 & bm
        r2 = (d2 >> 26) &+ r2

        n.0 = UInt32(r0); n.1 = UInt32(r1); n.2 = UInt32(r2)
        n.3 = UInt32(r3); n.4 = UInt32(r4); n.5 = UInt32(r5)
        n.6 = UInt32(r6); n.7 = UInt32(r7); n.8 = UInt32(r8)
        n.9 = UInt32(t9)
    }

    /// Multiply self by val in-place.
    mutating func mul(_ val: FieldElement) {
        mul2(self, val)
    }

    /// Return the product of two field elements.
    static func mul(_ a: FieldElement, _ b: FieldElement) -> FieldElement {
        var r = FieldElement()
        r.mul2(a, b)
        return r
    }

    // MARK: - Squaring

    /// Square the passed value and store the result in self.
    mutating func squareVal(_ val: FieldElement) {
        let bm = fieldBaseMask
        let msbm = fieldMSBMask

        // Terms for 2^(26*0).
        var m = UInt64(val.n.0) &* UInt64(val.n.0)
        let t0 = m & bm

        // Terms for 2^(26*1).
        m = (m >> 26) &+ 2 &* UInt64(val.n.0) &* UInt64(val.n.1)
        let t1 = m & bm

        // Terms for 2^(26*2).
        m = (m >> 26) &+
            2 &* UInt64(val.n.0) &* UInt64(val.n.2) &+
            UInt64(val.n.1) &* UInt64(val.n.1)
        let t2 = m & bm

        // Terms for 2^(26*3).
        m = (m >> 26) &+
            2 &* UInt64(val.n.0) &* UInt64(val.n.3) &+
            2 &* UInt64(val.n.1) &* UInt64(val.n.2)
        let t3 = m & bm

        // Terms for 2^(26*4).
        m = (m >> 26) &+
            2 &* UInt64(val.n.0) &* UInt64(val.n.4) &+
            2 &* UInt64(val.n.1) &* UInt64(val.n.3) &+
            UInt64(val.n.2) &* UInt64(val.n.2)
        let t4 = m & bm

        // Terms for 2^(26*5).
        m = (m >> 26) &+
            2 &* UInt64(val.n.0) &* UInt64(val.n.5) &+
            2 &* UInt64(val.n.1) &* UInt64(val.n.4) &+
            2 &* UInt64(val.n.2) &* UInt64(val.n.3)
        let t5 = m & bm

        // Terms for 2^(26*6).
        m = (m >> 26) &+
            2 &* UInt64(val.n.0) &* UInt64(val.n.6) &+
            2 &* UInt64(val.n.1) &* UInt64(val.n.5) &+
            2 &* UInt64(val.n.2) &* UInt64(val.n.4) &+
            UInt64(val.n.3) &* UInt64(val.n.3)
        let t6 = m & bm

        // Terms for 2^(26*7).
        m = (m >> 26) &+
            2 &* UInt64(val.n.0) &* UInt64(val.n.7) &+
            2 &* UInt64(val.n.1) &* UInt64(val.n.6) &+
            2 &* UInt64(val.n.2) &* UInt64(val.n.5) &+
            2 &* UInt64(val.n.3) &* UInt64(val.n.4)
        let t7 = m & bm

        // Terms for 2^(26*8).
        m = (m >> 26) &+
            2 &* UInt64(val.n.0) &* UInt64(val.n.8) &+
            2 &* UInt64(val.n.1) &* UInt64(val.n.7) &+
            2 &* UInt64(val.n.2) &* UInt64(val.n.6) &+
            2 &* UInt64(val.n.3) &* UInt64(val.n.5) &+
            UInt64(val.n.4) &* UInt64(val.n.4)
        let t8 = m & bm

        // Terms for 2^(26*9).
        m = (m >> 26) &+
            2 &* UInt64(val.n.0) &* UInt64(val.n.9) &+
            2 &* UInt64(val.n.1) &* UInt64(val.n.8) &+
            2 &* UInt64(val.n.2) &* UInt64(val.n.7) &+
            2 &* UInt64(val.n.3) &* UInt64(val.n.6) &+
            2 &* UInt64(val.n.4) &* UInt64(val.n.5)
        var t9 = m & bm

        // Terms for 2^(26*10).
        m = (m >> 26) &+
            2 &* UInt64(val.n.1) &* UInt64(val.n.9) &+
            2 &* UInt64(val.n.2) &* UInt64(val.n.8) &+
            2 &* UInt64(val.n.3) &* UInt64(val.n.7) &+
            2 &* UInt64(val.n.4) &* UInt64(val.n.6) &+
            UInt64(val.n.5) &* UInt64(val.n.5)
        let t10 = m & bm

        // Terms for 2^(26*11).
        m = (m >> 26) &+
            2 &* UInt64(val.n.2) &* UInt64(val.n.9) &+
            2 &* UInt64(val.n.3) &* UInt64(val.n.8) &+
            2 &* UInt64(val.n.4) &* UInt64(val.n.7) &+
            2 &* UInt64(val.n.5) &* UInt64(val.n.6)
        let t11 = m & bm

        // Terms for 2^(26*12).
        m = (m >> 26) &+
            2 &* UInt64(val.n.3) &* UInt64(val.n.9) &+
            2 &* UInt64(val.n.4) &* UInt64(val.n.8) &+
            2 &* UInt64(val.n.5) &* UInt64(val.n.7) &+
            UInt64(val.n.6) &* UInt64(val.n.6)
        let t12 = m & bm

        // Terms for 2^(26*13).
        m = (m >> 26) &+
            2 &* UInt64(val.n.4) &* UInt64(val.n.9) &+
            2 &* UInt64(val.n.5) &* UInt64(val.n.8) &+
            2 &* UInt64(val.n.6) &* UInt64(val.n.7)
        let t13 = m & bm

        // Terms for 2^(26*14).
        m = (m >> 26) &+
            2 &* UInt64(val.n.5) &* UInt64(val.n.9) &+
            2 &* UInt64(val.n.6) &* UInt64(val.n.8) &+
            UInt64(val.n.7) &* UInt64(val.n.7)
        let t14 = m & bm

        // Terms for 2^(26*15).
        m = (m >> 26) &+
            2 &* UInt64(val.n.6) &* UInt64(val.n.9) &+
            2 &* UInt64(val.n.7) &* UInt64(val.n.8)
        let t15 = m & bm

        // Terms for 2^(26*16).
        m = (m >> 26) &+
            2 &* UInt64(val.n.7) &* UInt64(val.n.9) &+
            UInt64(val.n.8) &* UInt64(val.n.8)
        let t16 = m & bm

        // Terms for 2^(26*17).
        m = (m >> 26) &+ 2 &* UInt64(val.n.8) &* UInt64(val.n.9)
        let t17 = m & bm

        // Terms for 2^(26*18).
        m = (m >> 26) &+ UInt64(val.n.9) &* UInt64(val.n.9)
        let t18 = m & bm

        let t19 = m >> 26

        // Reduce.
        m = t0 &+ t10 &* 15632
        var r0 = m & bm
        m = (m >> 26) &+ t1 &+ t10 &* 1024 &+ t11 &* 15632
        var r1 = m & bm
        m = (m >> 26) &+ t2 &+ t11 &* 1024 &+ t12 &* 15632
        var r2 = m & bm
        m = (m >> 26) &+ t3 &+ t12 &* 1024 &+ t13 &* 15632
        let r3 = m & bm
        m = (m >> 26) &+ t4 &+ t13 &* 1024 &+ t14 &* 15632
        let r4 = m & bm
        m = (m >> 26) &+ t5 &+ t14 &* 1024 &+ t15 &* 15632
        let r5 = m & bm
        m = (m >> 26) &+ t6 &+ t15 &* 1024 &+ t16 &* 15632
        let r6 = m & bm
        m = (m >> 26) &+ t7 &+ t16 &* 1024 &+ t17 &* 15632
        let r7 = m & bm
        m = (m >> 26) &+ t8 &+ t17 &* 1024 &+ t18 &* 15632
        let r8 = m & bm
        m = (m >> 26) &+ t9 &+ t18 &* 1024 &+ t19 &* 68719492368
        t9 = m & msbm
        m = m >> fieldMSBBits

        let d = r0 &+ m &* 977
        r0 = d & bm
        let d2 = (d >> 26) &+ r1 &+ m &* 64
        r1 = d2 & bm
        r2 = (d2 >> 26) &+ r2

        n.0 = UInt32(r0); n.1 = UInt32(r1); n.2 = UInt32(r2)
        n.3 = UInt32(r3); n.4 = UInt32(r4); n.5 = UInt32(r5)
        n.6 = UInt32(r6); n.7 = UInt32(r7); n.8 = UInt32(r8)
        n.9 = UInt32(t9)
    }

    /// Square self in-place.
    mutating func square() {
        squareVal(self)
    }

    /// Return the square.
    func squared() -> FieldElement {
        var r = FieldElement()
        r.squareVal(self)
        return r
    }

    // MARK: - Inverse

    /// Compute the modular multiplicative inverse using Fermat's little theorem:
    /// a^(-1) = a^(p-2) mod p.
    ///
    /// Uses an addition chain with 258 squarings and 33 multiplications.
    mutating func inverse() {
        var a2 = FieldElement()
        a2.squareVal(self)
        let a3 = FieldElement.mul(a2, self)
        var a4 = FieldElement()
        a4.squareVal(a2)
        var a10 = FieldElement()
        a10.squareVal(a4)
        a10.mul(a2)
        let a11 = FieldElement.mul(a10, self)
        let a21 = FieldElement.mul(a10, a11)
        var a42 = FieldElement()
        a42.squareVal(a21)
        let a45 = FieldElement.mul(a42, a3)
        let a63 = FieldElement.mul(a42, a21)
        var a1019 = FieldElement()
        a1019.squareVal(a63)
        a1019.square(); a1019.square(); a1019.square()
        a1019.mul(a11)
        let a1023 = FieldElement.mul(a1019, a4)

        self = a63                                          // a^(2^6 - 1)
        square(); square(); square(); square(); square()    // a^(2^11 - 32)
        square(); square(); square(); square(); square()    // a^(2^16 - 1024)
        mul(a1023)                                          // a^(2^16 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^26 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^36 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^46 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^56 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^66 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^76 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^86 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^96 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^106 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^116 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^126 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^136 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^146 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^156 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^166 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^176 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^186 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^196 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^206 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^216 - 1)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1019)                                          // a^(2^226 - 5)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^236 - 4097)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a1023)                                          // a^(2^246 - 4194305)
        square(); square(); square(); square(); square()
        square(); square(); square(); square(); square()
        mul(a45)                                            // a^(2^256 - 4294968275) = a^(p-2)
    }

    /// Return the modular inverse.
    func inversed() -> FieldElement {
        var f = self
        f.inverse()
        return f
    }

    // MARK: - Square root

    /// Compute the square root modulo p via x^((p+1)/4).
    mutating func sqrtVal(_ x: FieldElement) {
        self = FieldElement(1)
        for b in fieldQBytes {
            switch b {
            case 0xFF:
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
            case 0x3F:
                mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
            case 0xBF:
                square(); mul(x)
                square()
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
                square(); mul(x)
            default: // 0x0C
                square()
                square()
                square()
                square()
                square(); mul(x)
                square(); mul(x)
                square()
                square()
            }
        }
    }

    /// Compute the square root of self modulo p.
    mutating func sqrt() {
        var r = FieldElement()
        r.sqrtVal(self)
        self = r
    }

    /// Return the square root modulo p.
    func squareRoot() -> FieldElement {
        var r = FieldElement()
        r.sqrtVal(self)
        return r
    }
}
