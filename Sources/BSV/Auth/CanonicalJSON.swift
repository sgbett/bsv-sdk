import Foundation

/// Canonical JSON encoders used to compute the pre-image bytes for
/// auth-message signatures. The BRC-66 handshake and follow-up cert/general
/// messages sign over a JSON representation of a domain object, and both
/// ends of the wire MUST agree on the exact byte sequence. Swift's default
/// `JSONEncoder` does not guarantee key order for dictionaries or structs,
/// so we canonicalise explicitly.
///
/// The encoders here are designed to match the ts-sdk reference. ts-sdk
/// signs the output of `JSON.stringify`, which walks an object's own
/// enumerable properties in insertion order. For plain objects built via
/// `{...}` that matches the literal field order; for class instances
/// (`Certificate`) it matches the constructor's `this.x = ...` order.
///
/// For Swift-to-Swift conformance alphabetical keys would suffice, but the
/// whole point of matching ts-sdk is cross-SDK verification, so we emit
/// certificates in ts-sdk constructor order: `type`, `serialNumber`,
/// `subject`, `certifier`, `revocationOutpoint`, `fields`, `signature`.
enum CanonicalJSON {

    /// Canonicalise a `RequestedCertificateSet` for signing/verifying
    /// `certificateRequest` messages.
    ///
    /// ts-sdk emits `{"certifiers":[...],"types":{...}}` — the two property
    /// names happen to be in alphabetical order, so `.sortedKeys` matches
    /// insertion order. The `types` map is `Record<string, string[]>` in
    /// ts-sdk, which JSON.stringify walks in insertion order; Swift cannot
    /// preserve insertion order in `[String: [String]]`, so we sort keys
    /// there as well. Callers building cross-SDK test vectors should keep
    /// `types` to a single key or expect sorted output on the ts-sdk side
    /// too.
    static func encodeRequestedCertificateSet(_ set: RequestedCertificateSet) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(set)
    }

    /// Canonicalise a `[Certificate]` array for signing/verifying
    /// `certificateResponse` messages.
    ///
    /// Emits each certificate in ts-sdk constructor insertion order:
    ///
    /// ```
    /// {"type":"...","serialNumber":"...","subject":"...","certifier":"...",
    ///  "revocationOutpoint":"...","fields":{...},"signature":"..."}
    /// ```
    ///
    /// The `signature` field is omitted entirely when nil, matching
    /// `JSON.stringify`'s behaviour for undefined properties.
    ///
    /// Field keys inside the `fields` record are sorted alphabetically.
    /// ts-sdk itself uses insertion order there, but neither language can
    /// guarantee a stable order without an opinion, so sorted is the
    /// pragmatic cross-SDK choice. For cross-SDK interoperability, keep
    /// certificate field maps to a single key or produce them in sorted
    /// order on the ts-sdk side as well.
    static func encodeCertificates(_ certs: [Certificate]) -> Data {
        var out = Data()
        out.append(0x5B) // '['
        for (i, cert) in certs.enumerated() {
            if i > 0 { out.append(0x2C) } // ','
            appendCertificate(cert, to: &out)
        }
        out.append(0x5D) // ']'
        return out
    }

    // MARK: - Internals

    private static func appendCertificate(_ cert: Certificate, to out: inout Data) {
        out.append(0x7B) // '{'
        var first = true
        appendKeyValue("type", stringValue: cert.type.base64EncodedString(), first: &first, to: &out)
        appendKeyValue("serialNumber", stringValue: cert.serialNumber.base64EncodedString(), first: &first, to: &out)
        appendKeyValue("subject", stringValue: cert.subject.hex, first: &first, to: &out)
        appendKeyValue("certifier", stringValue: cert.certifier.hex, first: &first, to: &out)
        appendKeyValue("revocationOutpoint", stringValue: cert.revocationOutpoint, first: &first, to: &out)

        if !first { out.append(0x2C) }
        first = false
        appendJSONString("fields", to: &out)
        out.append(0x3A) // ':'
        appendFieldsObject(cert.fields, to: &out)

        if let sig = cert.signature {
            appendKeyValue("signature", stringValue: sig.hex, first: &first, to: &out)
        }
        out.append(0x7D) // '}'
    }

    private static func appendFieldsObject(_ fields: [String: String], to out: inout Data) {
        out.append(0x7B) // '{'
        let sortedKeys = fields.keys.sorted()
        for (i, key) in sortedKeys.enumerated() {
            if i > 0 { out.append(0x2C) }
            appendJSONString(key, to: &out)
            out.append(0x3A) // ':'
            appendJSONString(fields[key] ?? "", to: &out)
        }
        out.append(0x7D) // '}'
    }

    private static func appendKeyValue(
        _ key: String,
        stringValue value: String,
        first: inout Bool,
        to out: inout Data
    ) {
        if !first { out.append(0x2C) }
        first = false
        appendJSONString(key, to: &out)
        out.append(0x3A) // ':'
        appendJSONString(value, to: &out)
    }

    /// Encode a string as a JSON string literal. Matches ts-sdk
    /// `JSON.stringify` escaping: quotes, backslash, control characters
    /// 0x00-0x1F, with shorthand for \b, \t, \n, \f, \r. Non-ASCII
    /// characters above 0x7F are emitted literally as UTF-8 — matching
    /// JSON.stringify which only escapes surrogate halves by default.
    private static func appendJSONString(_ s: String, to out: inout Data) {
        out.append(0x22) // '"'
        for scalar in s.unicodeScalars {
            let v = scalar.value
            switch v {
            case 0x22: out.append(contentsOf: [0x5C, 0x22]) // \"
            case 0x5C: out.append(contentsOf: [0x5C, 0x5C]) // \\
            case 0x08: out.append(contentsOf: [0x5C, 0x62]) // \b
            case 0x09: out.append(contentsOf: [0x5C, 0x74]) // \t
            case 0x0A: out.append(contentsOf: [0x5C, 0x6E]) // \n
            case 0x0C: out.append(contentsOf: [0x5C, 0x66]) // \f
            case 0x0D: out.append(contentsOf: [0x5C, 0x72]) // \r
            case 0x00...0x1F:
                let hex = String(format: "%04x", v)
                out.append(contentsOf: [0x5C, 0x75]) // \u
                out.append(contentsOf: hex.utf8)
            default:
                out.append(contentsOf: String(scalar).utf8)
            }
        }
        out.append(0x22) // '"'
    }
}
