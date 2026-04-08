import Foundation

/// A BRC-103 verifiable certificate.
///
/// A `VerifiableCertificate` pairs a signed `Certificate` with a
/// verifier-specific keyring that enables selective disclosure: for each
/// field the verifier is allowed to see, the keyring contains the field
/// revelation key re-encrypted for the verifier.
public struct VerifiableCertificate: Sendable {
    public var certificate: Certificate
    /// Field name → base64-encoded encrypted field revelation key.
    public var keyring: [String: String]
    /// Lazily populated cache of decrypted field values (plaintext UTF-8).
    public private(set) var decryptedFields: [String: String]?

    public init(
        certificate: Certificate,
        keyring: [String: String],
        decryptedFields: [String: String]? = nil
    ) {
        self.certificate = certificate
        self.keyring = keyring
        self.decryptedFields = decryptedFields
    }

    // MARK: - Decryption

    /// Decrypt every field listed in the keyring using the verifier's wallet.
    ///
    /// The verifier wallet must be able to decrypt the keyring entries
    /// (which were encrypted against the verifier's identity key by the
    /// subject), and then each resulting symmetric key is used to unwrap the
    /// corresponding field value.
    @discardableResult
    public mutating func decryptFields(verifierWallet: WalletInterface) async throws -> [String: String] {
        guard !keyring.isEmpty else {
            throw AuthError.certificateInvalid("verifiable certificate has no keyring")
        }

        var decrypted: [String: String] = [:]
        for (fieldName, encryptedKey) in keyring {
            guard let encKeyData = Data(base64Encoded: encryptedKey) else {
                throw AuthError.certificateInvalid("keyring entry for \(fieldName) is not base64")
            }

            let keyBytes = try await verifierWallet.decrypt(args: WalletDecryptArgs(
                encryption: WalletEncryptionArgs(
                    protocolID: MasterCertificate.fieldProtocol,
                    keyID: MasterCertificate.fieldKeyID(
                        fieldName: fieldName,
                        serialNumber: certificate.serialNumber
                    ),
                    counterparty: .publicKey(certificate.subject)
                ),
                ciphertext: encKeyData
            )).plaintext

            guard let symKey = SymmetricKey(key: keyBytes) else {
                throw AuthError.certificateInvalid("invalid field revelation key for \(fieldName)")
            }

            guard let encField = certificate.fields[fieldName],
                  let encFieldData = Data(base64Encoded: encField) else {
                throw AuthError.certificateInvalid("encrypted field value for \(fieldName) is missing or malformed")
            }

            let plain = try symKey.decrypt(encFieldData)
            decrypted[fieldName] = String(data: plain, encoding: .utf8) ?? ""
        }

        self.decryptedFields = decrypted
        return decrypted
    }
}
