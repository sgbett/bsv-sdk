import Foundation

/// A BRC-103 master certificate.
///
/// Extends `Certificate` with a *master keyring*: for every field, the
/// creating wallet stores an encrypted field-revelation key addressed to a
/// counterparty (typically the subject or certifier). The subject can later
/// decrypt the master keyring to recover field values, or re-encrypt a
/// subset of the keys for a verifier to form a `VerifiableCertificate`.
public struct MasterCertificate: Sendable {
    public var certificate: Certificate
    /// Field name → base64-encoded encrypted symmetric key for that field.
    public var masterKeyring: [String: String]

    public init(certificate: Certificate, masterKeyring: [String: String]) {
        self.certificate = certificate
        self.masterKeyring = masterKeyring
    }

    // MARK: - Field-level helpers

    /// Protocol used for certificate-field encryption in the wallet layer.
    internal static let fieldProtocol = WalletProtocol(
        securityLevel: .counterparty,
        protocol: "certificate field encryption"
    )

    /// For the MasterCertificate, the wallet keyID is just the field name.
    /// For the VerifiableCertificate, the keyID is `"<serialNumberBase64> <fieldName>"`.
    internal static func fieldKeyID(fieldName: String, serialNumber: Data? = nil) -> String {
        if let serial = serialNumber {
            return "\(serial.base64EncodedString()) \(fieldName)"
        }
        return fieldName
    }

    // MARK: - Creation

    /// Encrypt a set of plaintext fields under random symmetric keys and
    /// return the encrypted fields plus a master keyring.
    ///
    /// Mirrors ts-sdk `MasterCertificate.createCertificateFields`.
    public static func createCertificateFields(
        creatorWallet: WalletInterface,
        certifierOrSubject: WalletCounterparty,
        fields: [String: String]
    ) async throws -> (certificateFields: [String: String], masterKeyring: [String: String]) {
        var certificateFields: [String: String] = [:]
        var masterKeyring: [String: String] = [:]

        for (name, value) in fields {
            let fieldKey = SymmetricKey.random()
            let plaintext = Data(value.utf8)
            let encryptedValue = try fieldKey.encrypt(plaintext)
            certificateFields[name] = encryptedValue.base64EncodedString()

            let encryptedKey = try await creatorWallet.encrypt(args: WalletEncryptArgs(
                encryption: WalletEncryptionArgs(
                    protocolID: fieldProtocol,
                    keyID: fieldKeyID(fieldName: name),
                    counterparty: certifierOrSubject
                ),
                plaintext: fieldKey.key
            ))
            masterKeyring[name] = encryptedKey.ciphertext.base64EncodedString()
        }

        return (certificateFields, masterKeyring)
    }

    /// Issue a full master certificate for a subject: encrypts the fields,
    /// mints the master keyring, assembles a `Certificate`, and signs it.
    public static func issueCertificateForSubject(
        certifierWallet: WalletInterface,
        subject: PublicKey,
        fields: [String: String],
        certificateType: Data,
        serialNumber: Data? = nil,
        revocationOutpoint: String = String(repeating: "0", count: 64) + ".0"
    ) async throws -> MasterCertificate {
        let serial: Data
        if let serialNumber {
            serial = serialNumber
        } else {
            var bytes = Data(count: 32)
            let status = bytes.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
            }
            guard status == errSecSuccess else {
                throw AuthError.certificateInvalid("failed to generate serial number")
            }
            serial = bytes
        }

        let (encryptedFields, masterKeyring) = try await createCertificateFields(
            creatorWallet: certifierWallet,
            certifierOrSubject: .publicKey(subject),
            fields: fields
        )

        let certifierID = try await certifierWallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        ).publicKey

        var cert = Certificate(
            type: certificateType,
            serialNumber: serial,
            subject: subject,
            certifier: certifierID,
            revocationOutpoint: revocationOutpoint,
            fields: encryptedFields,
            signature: nil
        )
        try await cert.sign(certifierWallet: certifierWallet)

        return MasterCertificate(certificate: cert, masterKeyring: masterKeyring)
    }

    // MARK: - Decrypting / keyring transformation

    /// Decrypt a single master-keyring entry, returning the symmetric key
    /// and the decrypted field value.
    public static func decryptField(
        subjectOrCertifierWallet: WalletInterface,
        masterKeyring: [String: String],
        fieldName: String,
        encryptedFieldValue: String,
        counterparty: WalletCounterparty
    ) async throws -> (fieldKey: SymmetricKey, value: String) {
        guard let encKey = masterKeyring[fieldName],
              let encKeyData = Data(base64Encoded: encKey) else {
            throw AuthError.certificateInvalid("missing master keyring entry for \(fieldName)")
        }

        let decryptedKey = try await subjectOrCertifierWallet.decrypt(args: WalletDecryptArgs(
            encryption: WalletEncryptionArgs(
                protocolID: fieldProtocol,
                keyID: fieldKeyID(fieldName: fieldName),
                counterparty: counterparty
            ),
            ciphertext: encKeyData
        )).plaintext

        guard let symKey = SymmetricKey(key: decryptedKey) else {
            throw AuthError.certificateInvalid("master keyring contained invalid key material")
        }

        guard let encValData = Data(base64Encoded: encryptedFieldValue) else {
            throw AuthError.certificateInvalid("field value is not valid base64")
        }
        let plaintext = try symKey.decrypt(encValData)
        return (symKey, String(data: plaintext, encoding: .utf8) ?? "")
    }

    /// Re-encrypt a subset of master keys for a verifier to produce a
    /// verifier-specific keyring suitable for a `VerifiableCertificate`.
    public static func createKeyringForVerifier(
        subjectWallet: WalletInterface,
        certifier: WalletCounterparty,
        verifier: WalletCounterparty,
        fields: [String: String],
        fieldsToReveal: [String],
        masterKeyring: [String: String],
        serialNumber: Data
    ) async throws -> [String: String] {
        var revelation: [String: String] = [:]
        for fieldName in fieldsToReveal {
            guard let encryptedFieldValue = fields[fieldName] else {
                throw AuthError.certificateInvalid("field \(fieldName) is not in the certificate")
            }

            let (fieldKey, _) = try await decryptField(
                subjectOrCertifierWallet: subjectWallet,
                masterKeyring: masterKeyring,
                fieldName: fieldName,
                encryptedFieldValue: encryptedFieldValue,
                counterparty: certifier
            )

            let encryptedForVerifier = try await subjectWallet.encrypt(args: WalletEncryptArgs(
                encryption: WalletEncryptionArgs(
                    protocolID: fieldProtocol,
                    keyID: fieldKeyID(fieldName: fieldName, serialNumber: serialNumber),
                    counterparty: verifier
                ),
                plaintext: fieldKey.key
            ))
            revelation[fieldName] = encryptedForVerifier.ciphertext.base64EncodedString()
        }
        return revelation
    }
}
