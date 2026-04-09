import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A HTTP `Transport` that POSTs serialised `AuthMessage`s to a remote peer.
///
/// Handshake-time messages (`initialRequest`, `initialResponse`,
/// `certificateRequest`, `certificateResponse`) are posted to
/// `<baseURL>/.well-known/auth` as JSON. This matches the ts-sdk
/// `SimplifiedFetchTransport` wire format for non-general messages.
///
/// Note: this Swift implementation currently focuses on the non-general
/// handshake path used by `Peer` end-to-end tests. The full
/// header-tunnelled `general` message mode (which re-packages the HTTP
/// request as the signed payload) is not yet supported — users who need it
/// should implement a custom `Transport` until parity is added.
public final class SimplifiedFetchTransport: Transport, @unchecked Sendable {
    public let baseURL: URL
    public let session: URLSession
    private let lock = NSLock()
    private var onDataCallback: (@Sendable (AuthMessage) async throws -> Void)?

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    // MARK: - Transport conformance

    public func send(_ message: AuthMessage) async throws {
        if message.messageType == .general {
            throw AuthError.transportFailure(
                "SimplifiedFetchTransport: general message tunnelling is not yet supported"
            )
        }

        let body = try SimplifiedFetchTransport.encodeAuthMessage(message)
        var request = URLRequest(url: baseURL.appendingPathComponent(".well-known/auth"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = body

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw AuthError.transportFailure("non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw AuthError.transportFailure("HTTP \(http.statusCode) from \(baseURL)")
        }

        if data.isEmpty { return }

        let inbound = try SimplifiedFetchTransport.decodeAuthMessage(data)
        let cb = lock.withLock { onDataCallback }
        if let cb { try await cb(inbound) }
    }

    public func onData(_ callback: @escaping @Sendable (AuthMessage) async throws -> Void) async throws {
        lock.withLock { self.onDataCallback = callback }
    }

    // MARK: - Wire format

    /// Encode an `AuthMessage` to JSON matching the ts-sdk shape.
    static func encodeAuthMessage(_ message: AuthMessage) throws -> Data {
        var body: [String: Any] = [
            "version": message.version,
            "messageType": message.messageType.rawValue,
            "identityKey": message.identityKey.hex
        ]
        if let n = message.nonce { body["nonce"] = n }
        if let i = message.initialNonce { body["initialNonce"] = i }
        if let y = message.yourNonce { body["yourNonce"] = y }
        if let payload = message.payload { body["payload"] = Array(payload) }
        if let signature = message.signature { body["signature"] = Array(signature) }
        if let reqs = message.requestedCertificates {
            body["requestedCertificates"] = [
                "certifiers": reqs.certifiers,
                "types": reqs.types
            ]
        }
        if let certs = message.certificates {
            body["certificates"] = certs.map { encodeCertificate($0) }
        }
        return try JSONSerialization.data(withJSONObject: body, options: [])
    }

    static func encodeCertificate(_ cert: Certificate) -> [String: Any] {
        var dict: [String: Any] = [
            "type": cert.type.base64EncodedString(),
            "serialNumber": cert.serialNumber.base64EncodedString(),
            "subject": cert.subject.hex,
            "certifier": cert.certifier.hex,
            "revocationOutpoint": cert.revocationOutpoint,
            "fields": cert.fields
        ]
        if let sig = cert.signature { dict["signature"] = sig.hex }
        return dict
    }

    /// Decode a single `AuthMessage` from a JSON body.
    static func decodeAuthMessage(_ data: Data) throws -> AuthMessage {
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AuthError.malformedMessage("body is not a JSON object")
        }
        let version = obj["version"] as? String ?? AUTH_VERSION
        guard let typeRaw = obj["messageType"] as? String,
              let type = AuthMessageType(rawValue: typeRaw) else {
            throw AuthError.malformedMessage("missing or invalid messageType")
        }
        guard let idHex = obj["identityKey"] as? String,
              let identity = PublicKey(hex: idHex) else {
            throw AuthError.malformedMessage("missing or invalid identityKey")
        }

        var message = AuthMessage(version: version, messageType: type, identityKey: identity)
        message.nonce = obj["nonce"] as? String
        message.initialNonce = obj["initialNonce"] as? String
        message.yourNonce = obj["yourNonce"] as? String
        if let payload = decodeByteArray(obj["payload"]) { message.payload = payload }
        if let signature = decodeByteArray(obj["signature"]) { message.signature = signature }
        if let reqs = obj["requestedCertificates"] as? [String: Any] {
            let certifiers = reqs["certifiers"] as? [String] ?? []
            let types = reqs["types"] as? [String: [String]] ?? [:]
            message.requestedCertificates = RequestedCertificateSet(certifiers: certifiers, types: types)
        }
        if let certs = obj["certificates"] as? [[String: Any]] {
            message.certificates = certs.compactMap(decodeCertificate)
        }
        return message
    }

    static func decodeCertificate(_ obj: [String: Any]) -> Certificate? {
        guard
            let typeStr = obj["type"] as? String,
            let type = Data(base64Encoded: typeStr),
            let serialStr = obj["serialNumber"] as? String,
            let serial = Data(base64Encoded: serialStr),
            let subjectHex = obj["subject"] as? String,
            let subject = PublicKey(hex: subjectHex),
            let certifierHex = obj["certifier"] as? String,
            let certifier = PublicKey(hex: certifierHex),
            let revocation = obj["revocationOutpoint"] as? String,
            let fields = obj["fields"] as? [String: String]
        else { return nil }
        let signature = (obj["signature"] as? String).flatMap { Data(hex: $0) }
        return Certificate(
            type: type,
            serialNumber: serial,
            subject: subject,
            certifier: certifier,
            revocationOutpoint: revocation,
            fields: fields,
            signature: signature
        )
    }

    static func decodeByteArray(_ value: Any?) -> Data? {
        if let ints = value as? [Int] {
            return Data(ints.map { UInt8(truncatingIfNeeded: $0) })
        }
        if let numbers = value as? [NSNumber] {
            return Data(numbers.map { UInt8(truncatingIfNeeded: $0.intValue) })
        }
        if let hex = value as? String {
            return Data(hex: hex)
        }
        return nil
    }
}

// MARK: - NSLock convenience

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T {
        lock()
        defer { unlock() }
        return body()
    }
}
