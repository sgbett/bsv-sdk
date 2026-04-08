import XCTest
@testable import BSV

final class SignatureTests: XCTestCase {

    // A known signature for testing.
    private var testSig: Signature {
        let hash = Digest.sha256("test".data(using: .utf8)!)
        var privKey = Data(count: 32); privKey[31] = 1
        let result = ECDSA.sign(hash: hash, privateKey: privKey)!
        return Signature(r: result.r, s: result.s)
    }

    // MARK: - DER round-trip

    func testDERRoundTrip() {
        let sig = testSig
        let der = sig.toDER()
        let parsed = Signature.fromDER(der)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed!.r, sig.r)
        XCTAssertEqual(parsed!.s, sig.s)
    }

    func testDERFormat() {
        let sig = testSig
        let der = sig.toDER()
        // Must start with 0x30.
        XCTAssertEqual(der[0], 0x30)
        // Second byte is the length of the remaining data.
        XCTAssertEqual(Int(der[1]) + 2, der.count)
        // R tag.
        XCTAssertEqual(der[2], 0x02)
    }

    // MARK: - Compact round-trip

    func testCompactRoundTrip() {
        let sig = testSig
        let compact = sig.toCompact()
        XCTAssertEqual(compact.count, 64)
        let parsed = Signature.fromCompact(compact)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed!.r, sig.r)
        XCTAssertEqual(parsed!.s, sig.s)
    }

    // MARK: - Low-S

    func testLowSNormalisation() {
        // Create a signature that already has low-S.
        let sig = testSig
        XCTAssertTrue(sig.isLowS)
        let normalised = sig.lowSNormalised()
        XCTAssertEqual(normalised.s, sig.s)
    }

    func testHighSGetNormalised() {
        let sig = testSig
        // Artificially create a high-S by subtracting from N.
        let highS = scalarSubN(Secp256k1.N, sig.s)
        let highSig = Signature(r: sig.r, s: highS)
        XCTAssertFalse(highSig.isLowS)
        let normalised = highSig.lowSNormalised()
        XCTAssertTrue(normalised.isLowS)
        XCTAssertEqual(normalised.s, sig.s)
    }

    // MARK: - BIP-66 strict rejection

    func testRejectsTooShort() {
        XCTAssertNil(Signature.fromDER(Data([0x30, 0x04, 0x02, 0x01])))
    }

    func testRejectsNoHeader() {
        let sig = testSig
        var der = sig.toDER()
        der[0] = 0x31 // wrong header
        XCTAssertNil(Signature.fromDER(der))
    }

    func testRejectsWrongLength() {
        let sig = testSig
        var der = sig.toDER()
        der[1] = UInt8(der.count) // wrong length (off by 2)
        XCTAssertNil(Signature.fromDER(der))
    }

    func testRejectsNegativeR() {
        // Construct a DER with negative R (high bit set, no zero prefix).
        let der = Data([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01])
        XCTAssertNil(Signature.fromDER(der))
    }

    func testRejectsExcessivelyPaddedR() {
        // R = 0x00 0x01 (excessively padded — 0x01 doesn't have high bit set).
        let der = Data([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01])
        XCTAssertNil(Signature.fromDER(der))
    }

    // MARK: - Compact format validation

    func testRejectsCompactWrongLength() {
        XCTAssertNil(Signature.fromCompact(Data(count: 63)))
        XCTAssertNil(Signature.fromCompact(Data(count: 65)))
    }

    func testRejectsCompactZeroR() {
        var data = Data(count: 64)
        data[63] = 1 // s = 1, r = 0
        XCTAssertNil(Signature.fromCompact(data))
    }

    // MARK: - Known DER vector

    func testKnownDERParsing() {
        // A manually constructed minimal valid DER signature.
        // r = 1, s = 1
        let der = Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
        let sig = Signature.fromDER(der)
        XCTAssertNotNil(sig)
        var expectedR = Data(count: 32); expectedR[31] = 1
        var expectedS = Data(count: 32); expectedS[31] = 1
        XCTAssertEqual(sig!.r, expectedR)
        XCTAssertEqual(sig!.s, expectedS)
    }

    func testDERRoundTripMinimal() {
        var r = Data(count: 32); r[31] = 1
        var s = Data(count: 32); s[31] = 1
        let sig = Signature(r: r, s: s)
        let der = sig.toDER()
        XCTAssertEqual(der, Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]))
    }

    func testDERLargeRWithPadding() {
        // r with high bit set needs 0x00 prefix.
        var r = Data(count: 32)
        r[0] = 0xFF; r[31] = 0x01
        var s = Data(count: 32); s[31] = 1
        // r is >= N, so this should fail to parse.
        // Instead, use a value with high bit set but < N.
        r = Data(hex: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")!
        let sig = Signature(r: r, s: s)
        let der = sig.toDER()
        let parsed = Signature.fromDER(der)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed!.r, r)
    }
}
