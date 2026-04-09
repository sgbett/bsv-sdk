import XCTest
@testable import BSV

/// Cross-SDK conformance tests for `CanonicalJSON`.
///
/// The reference fixtures here are captured from a Node.js harness that
/// reproduces ts-sdk's `JSON.stringify` behaviour over `VerifiableCertificate`
/// and `RequestedCertificateSet`. ts-sdk signs the raw UTF-8 bytes of that
/// stringification when building BRC-66 `certificateRequest` /
/// `certificateResponse` pre-images, so any Swift implementation that wants
/// cross-SDK verification to succeed must emit byte-for-byte identical
/// output.
///
/// Key insertion order for certificates follows the ts-sdk constructor:
/// `type`, `serialNumber`, `subject`, `certifier`, `revocationOutpoint`,
/// `fields`, `signature`. Alphabetical ordering (which Swift's
/// `JSONEncoder(.sortedKeys)` would produce) does NOT match.
final class CanonicalJSONTests: XCTestCase {

    // Pinned keys derived from fixed scalars. We can't use arbitrary
    // 33-byte strings for the subject/certifier because `PublicKey(data:)`
    // validates the point is on-curve, so instead we derive the two test
    // keys from scalar 1 and scalar 2 and use their compressed encodings
    // throughout the expected fixtures.
    private var fixedSubject: PublicKey {
        var scalar = Data(count: 32); scalar[31] = 0x01
        return PublicKey.fromPrivateKey(PrivateKey(data: scalar)!)
    }
    private var fixedCertifier: PublicKey {
        var scalar = Data(count: 32); scalar[31] = 0x02
        return PublicKey.fromPrivateKey(PrivateKey(data: scalar)!)
    }
    private var fixedRevocation: String {
        String(repeating: "0", count: 64) + ".0"
    }
    private var fixedType: Data { Data(base64Encoded: "dGVzdA==")! }
    private var fixedSerial: Data { Data(base64Encoded: "c2VyaWFs")! }

    /// Build the expected certificate object body (contents of the `{...}`
    /// excluding braces) matching ts-sdk constructor insertion order.
    private func expectedCertBody(
        fieldsJSON: String,
        signatureHex: String?
    ) -> String {
        let subjectHex = fixedSubject.hex
        let certifierHex = fixedCertifier.hex
        var body = #""type":"dGVzdA==","serialNumber":"c2VyaWFs""#
        body += #","subject":"\#(subjectHex)""#
        body += #","certifier":"\#(certifierHex)""#
        body += #","revocationOutpoint":"\#(fixedRevocation)""#
        body += #","fields":\#(fieldsJSON)"#
        if let sig = signatureHex {
            body += #","signature":"\#(sig)""#
        }
        return body
    }

    private func baseCert(
        fields: [String: String],
        signature: Data? = nil
    ) -> Certificate {
        Certificate(
            type: fixedType,
            serialNumber: fixedSerial,
            subject: fixedSubject,
            certifier: fixedCertifier,
            revocationOutpoint: fixedRevocation,
            fields: fields,
            signature: signature
        )
    }

    // MARK: - Certificate array

    func testCanonicalCertificatesMatchesTSSDKFixtureWithSignature() {
        let cert = baseCert(
            fields: ["name": "Alice"],
            signature: Data([0xDE, 0xAD, 0xBE, 0xEF])
        )
        let expected = "[{" + expectedCertBody(
            fieldsJSON: #"{"name":"Alice"}"#,
            signatureHex: "deadbeef"
        ) + "}]"
        let encoded = CanonicalJSON.encodeCertificates([cert])
        XCTAssertEqual(String(data: encoded, encoding: .utf8), expected)
    }

    func testCanonicalCertificatesOmitsUndefinedSignature() {
        let cert = baseCert(fields: ["name": "Alice"], signature: nil)
        let expected = "[{" + expectedCertBody(
            fieldsJSON: #"{"name":"Alice"}"#,
            signatureHex: nil
        ) + "}]"
        let encoded = CanonicalJSON.encodeCertificates([cert])
        XCTAssertEqual(String(data: encoded, encoding: .utf8), expected)
    }

    func testCanonicalCertificatesEscapesQuotesBackslashesAndNewlines() {
        // JS JSON.stringify escapes " as \", \ as \\, and \n as \n.
        let cert = baseCert(fields: ["name": "He said \"hi\"\nand \\ left"])
        let expected = "[{" + expectedCertBody(
            fieldsJSON: #"{"name":"He said \"hi\"\nand \\ left"}"#,
            signatureHex: nil
        ) + "}]"
        let encoded = CanonicalJSON.encodeCertificates([cert])
        XCTAssertEqual(String(data: encoded, encoding: .utf8), expected)
    }

    func testCanonicalCertificatesEmitsUnicodeAsUTF8Literal() {
        // JS JSON.stringify leaves non-ASCII scalars alone (they are emitted
        // as raw UTF-8 in the output bytes) unless explicitly asked to
        // ASCII-escape them.
        let cert = baseCert(fields: ["greeting": "héllo 日本"])
        let expected = "[{" + expectedCertBody(
            fieldsJSON: #"{"greeting":"héllo 日本"}"#,
            signatureHex: nil
        ) + "}]"
        let encoded = CanonicalJSON.encodeCertificates([cert])
        XCTAssertEqual(String(data: encoded, encoding: .utf8), expected)
    }

    func testCanonicalCertificatesEmptyFields() {
        let cert = baseCert(fields: [:])
        let expected = "[{" + expectedCertBody(
            fieldsJSON: "{}",
            signatureHex: nil
        ) + "}]"
        let encoded = CanonicalJSON.encodeCertificates([cert])
        XCTAssertEqual(String(data: encoded, encoding: .utf8), expected)
    }

    func testCanonicalCertificatesEmptyArray() {
        let encoded = CanonicalJSON.encodeCertificates([])
        XCTAssertEqual(String(data: encoded, encoding: .utf8), "[]")
    }

    func testCanonicalCertificatesKeyOrderIsNotAlphabetical() {
        // This is the regression guard for H3: the previous implementation
        // used JSONEncoder(.sortedKeys), which emits alphabetical key
        // order. That does NOT match ts-sdk. Assert the emitted bytes
        // have `type` BEFORE `certifier` (insertion order) so the test
        // fails if anyone reintroduces a sorted encoder.
        let cert = baseCert(fields: ["name": "Alice"])
        let encoded = CanonicalJSON.encodeCertificates([cert])
        let s = String(data: encoded, encoding: .utf8) ?? ""
        let typeIdx = s.range(of: "\"type\"")?.lowerBound
        let certIdx = s.range(of: "\"certifier\"")?.lowerBound
        XCTAssertNotNil(typeIdx)
        XCTAssertNotNil(certIdx)
        if let t = typeIdx, let c = certIdx {
            XCTAssertTrue(t < c, "type must be serialised before certifier (ts-sdk insertion order)")
        }
    }

    // MARK: - RequestedCertificateSet

    func testCanonicalRequestedCertificateSetSingleType() throws {
        let rcs = RequestedCertificateSet(
            certifiers: ["aaaa", "bbbb"],
            types: ["dHlwZQ==": ["name", "email"]]
        )
        let expected = #"{"certifiers":["aaaa","bbbb"],"types":{"dHlwZQ==":["name","email"]}}"#
        let encoded = try CanonicalJSON.encodeRequestedCertificateSet(rcs)
        XCTAssertEqual(String(data: encoded, encoding: .utf8), expected)
    }

    func testCanonicalRequestedCertificateSetEmpty() throws {
        let rcs = RequestedCertificateSet()
        let expected = #"{"certifiers":[],"types":{}}"#
        let encoded = try CanonicalJSON.encodeRequestedCertificateSet(rcs)
        XCTAssertEqual(String(data: encoded, encoding: .utf8), expected)
    }

    func testCanonicalRequestedCertificateSetNoFieldNames() throws {
        let rcs = RequestedCertificateSet(
            certifiers: ["aabb"],
            types: ["dHlwZQ==": []]
        )
        let expected = #"{"certifiers":["aabb"],"types":{"dHlwZQ==":[]}}"#
        let encoded = try CanonicalJSON.encodeRequestedCertificateSet(rcs)
        XCTAssertEqual(String(data: encoded, encoding: .utf8), expected)
    }
}
