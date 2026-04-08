import Foundation

/// A BRC-103 identity certificate.
///
/// Certificates are signed assertions made by a `certifier` about a
/// `subject`, binding a set of named fields (any UTF-8 values) to a
/// revocable on-chain outpoint. Verifiers can check the signature is valid
/// and consult the revocation outpoint before trusting the fields.
///
/// Binary format (matches ts-sdk):
/// ```
/// type (32 bytes, raw)
/// serialNumber (32 bytes, raw)
/// subject (33 bytes, compressed pubkey)
/// certifier (33 bytes, compressed pubkey)
/// revocationOutpoint: TXID (32 bytes) || VarInt(outputIndex)
/// VarInt(field count)
/// for each field (sorted lexicographically):
///   VarInt(name byte length) || name bytes
///   VarInt(value byte length) || value bytes
/// signature (DER, remainder of buffer) — optional
/// ```
public struct Certificate: Sendable, Equatable {
    public var type: Data                // 32 bytes
    public var serialNumber: Data        // 32 bytes
    public var subject: PublicKey
    public var certifier: PublicKey
    public var revocationOutpoint: String // "<txid>.<vout>"
    public var fields: [String: String]
    public var signature: Data?

    public init(
        type: Data,
        serialNumber: Data,
        subject: PublicKey,
        certifier: PublicKey,
        revocationOutpoint: String,
        fields: [String: String],
        signature: Data? = nil
    ) {
        self.type = type
        self.serialNumber = serialNumber
        self.subject = subject
        self.certifier = certifier
        self.revocationOutpoint = revocationOutpoint
        self.fields = fields
        self.signature = signature
    }

    // MARK: - Serialisation

    /// Serialise to the BRC-103 binary format.
    public func toBinary(includeSignature: Bool = true) -> Data {
        var out = Data()
        out.append(type)
        out.append(serialNumber)
        out.append(subject.toCompressed())
        out.append(certifier.toCompressed())

        let parts = revocationOutpoint.split(separator: ".", maxSplits: 1).map(String.init)
        let txidHex = parts.first ?? ""
        let outputIndex = UInt64(parts.count > 1 ? parts[1] : "0") ?? 0
        out.append(Data(hex: txidHex) ?? Data(count: 32))
        out.append(VarInt.encode(outputIndex))

        // Field list, sorted by name for deterministic hashing.
        let sortedNames = fields.keys.sorted()
        out.append(VarInt.encode(UInt64(sortedNames.count)))
        for name in sortedNames {
            let value = fields[name] ?? ""
            let nameBytes = Data(name.utf8)
            let valueBytes = Data(value.utf8)
            out.append(VarInt.encode(UInt64(nameBytes.count)))
            out.append(nameBytes)
            out.append(VarInt.encode(UInt64(valueBytes.count)))
            out.append(valueBytes)
        }

        if includeSignature, let sig = signature, !sig.isEmpty {
            out.append(sig)
        }
        return out
    }

    /// Parse a certificate from its BRC-103 binary format.
    public static func fromBinary(_ data: Data) -> Certificate? {
        var reader = ByteReader(data)
        guard let type = reader.read(32) else { return nil }
        guard let serial = reader.read(32) else { return nil }
        guard let subjectBytes = reader.read(33), let subject = PublicKey(data: subjectBytes) else { return nil }
        guard let certifierBytes = reader.read(33), let certifier = PublicKey(data: certifierBytes) else { return nil }
        guard let txid = reader.read(32) else { return nil }
        guard let outputIndex = reader.readVarInt() else { return nil }
        let revocation = "\(txid.hex).\(outputIndex)"

        guard let nFields = reader.readVarInt() else { return nil }
        var fields: [String: String] = [:]
        for _ in 0..<nFields {
            guard let nameLen = reader.readVarInt() else { return nil }
            guard let nameBytes = reader.read(Int(nameLen)) else { return nil }
            guard let valueLen = reader.readVarInt() else { return nil }
            guard let valueBytes = reader.read(Int(valueLen)) else { return nil }
            let name = String(data: nameBytes, encoding: .utf8) ?? ""
            let value = String(data: valueBytes, encoding: .utf8) ?? ""
            fields[name] = value
        }

        // Remaining bytes (if any) are the DER signature.
        let signature = reader.remaining().isEmpty ? nil : reader.remaining()
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

    // MARK: - Signing / verifying

    /// Key ID used to sign and verify the certificate. Uses base64 encodings
    /// of `type` and `serialNumber` to match the ts-sdk convention.
    internal var signatureKeyID: String {
        "\(type.base64EncodedString()) \(serialNumber.base64EncodedString())"
    }

    internal static let signatureProtocol = WalletProtocol(
        securityLevel: .counterparty,
        protocol: "certificate signature"
    )

    /// Sign the certificate using the certifier wallet. This populates
    /// `signature` and sets `certifier` to the wallet's identity key.
    public mutating func sign(certifierWallet: WalletInterface) async throws {
        guard signature == nil || signature?.isEmpty == true else {
            throw AuthError.certificateInvalid("certificate is already signed")
        }
        let id = try await certifierWallet.getPublicKey(args: GetPublicKeyArgs(identityKey: true))
        self.certifier = id.publicKey

        let preimage = toBinary(includeSignature: false)
        // ts-sdk omits `counterparty` on sign, which defaults to `anyone`.
        // Pair that with `counterparty: certifier` on the anyone-side verify
        // and BRC-42 key agreement recovers the same derived public key.
        let result = try await certifierWallet.createSignature(args: CreateSignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: Self.signatureProtocol,
                keyID: signatureKeyID,
                counterparty: .anyone
            ),
            data: preimage
        ))
        self.signature = result.signature
    }

    /// Verify the certifier's signature over the certificate body.
    public func verify() async throws -> Bool {
        guard let sig = signature, !sig.isEmpty else {
            throw AuthError.certificateInvalid("certificate is not signed")
        }
        // Verification uses the "anyone" wallet (BRC-42 scalar-1 key) paired
        // against the certifier identity key.
        let verifier = ProtoWallet(keyDeriver: KeyDeriver.anyone)
        let preimage = toBinary(includeSignature: false)
        do {
            let result = try await verifier.verifySignature(args: VerifySignatureArgs(
                encryption: WalletEncryptionArgs(
                    protocolID: Self.signatureProtocol,
                    keyID: signatureKeyID,
                    counterparty: .publicKey(certifier)
                ),
                signature: sig,
                data: preimage
            ))
            return result.valid
        } catch WalletError.invalidSignature {
            return false
        }
    }
}

// MARK: - Small internal byte reader

/// Minimal cursor-based reader used by certificate parsing. Lives here to
/// keep Certificate self-contained; the wider SDK already has its own
/// transaction reader, but that one is geared at big-integer bitcoin varints.
struct ByteReader {
    private let buffer: Data
    private var cursor: Int

    init(_ buffer: Data) {
        self.buffer = buffer
        self.cursor = 0
    }

    mutating func read(_ count: Int) -> Data? {
        guard count >= 0, cursor + count <= buffer.count else { return nil }
        let slice = buffer.subdata(in: (buffer.startIndex + cursor)..<(buffer.startIndex + cursor + count))
        cursor += count
        return slice
    }

    mutating func readVarInt() -> UInt64? {
        guard let decoded = VarInt.decode(buffer, offset: cursor) else { return nil }
        cursor += decoded.bytesRead
        return decoded.value
    }

    func remaining() -> Data {
        guard cursor < buffer.count else { return Data() }
        return buffer.subdata(in: (buffer.startIndex + cursor)..<buffer.endIndex)
    }
}
