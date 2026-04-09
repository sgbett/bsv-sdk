import Foundation

/// BRC-42 invoice-number key derivation.
///
/// Derives child private, public, and symmetric keys deterministically from a
/// long-term root private key, a counterparty reference, a protocol identifier
/// and a key identifier.
///
/// # Security note
///
/// BRC-42 is a lightweight deterministic key hierarchy, not an authenticated key
/// exchange. It provides neither forward secrecy nor replay protection: a leak of
/// the root key compromises every child key, past and future. Callers are
/// expected to already possess and trust one another's long-term public keys.
public protocol KeyDeriverAPI: Sendable {
    /// The root private key used for all derivations.
    var rootKey: PrivateKey { get }
    /// The compressed public key of the root, serving as the deriver's identity.
    var identityKey: PublicKey { get }

    func derivePublicKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty,
        forSelf: Bool
    ) throws -> PublicKey

    func derivePrivateKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty
    ) throws -> PrivateKey

    func deriveSymmetricKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty
    ) throws -> SymmetricKey

    func revealCounterpartySecret(counterparty: WalletCounterparty) throws -> Data

    func revealSpecificSecret(
        counterparty: WalletCounterparty,
        protocolID: WalletProtocol,
        keyID: String
    ) throws -> Data
}

/// Stateless BRC-42 key deriver.
public struct KeyDeriver: KeyDeriverAPI {
    public let rootKey: PrivateKey
    public let identityKey: PublicKey

    public init(rootKey: PrivateKey) {
        self.rootKey = rootKey
        self.identityKey = PublicKey.fromPrivateKey(rootKey)
    }

    /// Construct a deriver whose root key is `1` (the BRC-42 "anyone" key).
    public static var anyone: KeyDeriver {
        // Scalar 1 padded to 32 bytes.
        var one = Data(count: 32)
        one[31] = 1
        return KeyDeriver(rootKey: PrivateKey(data: one)!)
    }

    // MARK: - Derivation

    public func derivePublicKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty,
        forSelf: Bool = false
    ) throws -> PublicKey {
        let normalised = normaliseCounterparty(counterparty)
        let invoiceNumber = try computeInvoiceNumber(protocolID: protocolID, keyID: keyID)

        if forSelf {
            // child = rootKey.deriveChild(counterparty, invoiceNumber).toPublicKey()
            let childPriv = try deriveChildPrivate(
                priv: rootKey,
                counterpartyPub: normalised,
                invoiceNumber: invoiceNumber
            )
            return PublicKey.fromPrivateKey(childPriv)
        } else {
            // child = counterparty.deriveChild(rootKey, invoiceNumber)
            return try deriveChildPublic(
                pub: normalised,
                counterpartyPriv: rootKey,
                invoiceNumber: invoiceNumber
            )
        }
    }

    public func derivePrivateKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty
    ) throws -> PrivateKey {
        let normalised = normaliseCounterparty(counterparty)
        let invoiceNumber = try computeInvoiceNumber(protocolID: protocolID, keyID: keyID)
        return try deriveChildPrivate(
            priv: rootKey,
            counterpartyPub: normalised,
            invoiceNumber: invoiceNumber
        )
    }

    public func deriveSymmetricKey(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty
    ) throws -> SymmetricKey {
        // When counterparty is 'anyone', we use 1*G as the counterparty public key,
        // which means the symmetric key becomes publicly derivable. This mirrors
        // the behaviour of the ts-sdk and should only be used when public
        // disclosure is intended.
        let effectiveCounterparty: WalletCounterparty
        switch counterparty {
        case .anyone:
            effectiveCounterparty = .publicKey(PublicKey.fromPrivateKey(KeyDeriver.anyone.rootKey))
        default:
            effectiveCounterparty = counterparty
        }

        let derivedPub = try derivePublicKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: effectiveCounterparty,
            forSelf: false
        )
        let derivedPriv = try derivePrivateKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: effectiveCounterparty
        )

        // Shared secret x coordinate = derivedPub * derivedPriv.
        let sharedPoint = derivedPub.point.multiplied(by: derivedPriv.data)
        let (x, _) = sharedPoint.affine()
        guard let symmetric = SymmetricKey(key: x.toBytes()) else {
            throw WalletError.unknown("failed to derive symmetric key")
        }
        return symmetric
    }

    public func revealCounterpartySecret(counterparty: WalletCounterparty) throws -> Data {
        if case .`self` = counterparty {
            throw WalletError.invalidParameter(
                name: "counterparty",
                message: "counterparty secrets cannot be revealed for counterparty=self"
            )
        }

        let normalised = normaliseCounterparty(counterparty)

        // Double-check to ensure not revealing the secret for self.
        let selfPub = PublicKey.fromPrivateKey(rootKey)
        let selfDerived = try deriveChildPrivate(priv: rootKey, counterpartyPub: selfPub, invoiceNumber: "test")
        let counterpartyDerived = try deriveChildPrivate(priv: rootKey, counterpartyPub: normalised, invoiceNumber: "test")
        guard selfDerived.data != counterpartyDerived.data else {
            throw WalletError.invalidParameter(
                name: "counterparty",
                message: "counterparty secrets cannot be revealed for counterparty=self"
            )
        }

        // Compressed ECDH point.
        let sharedPoint = normalised.point.multiplied(by: rootKey.data)
        return sharedPoint.compressed()
    }

    public func revealSpecificSecret(
        counterparty: WalletCounterparty,
        protocolID: WalletProtocol,
        keyID: String
    ) throws -> Data {
        let normalised = normaliseCounterparty(counterparty)
        let sharedPoint = normalised.point.multiplied(by: rootKey.data)
        let compressed = sharedPoint.compressed()
        let invoiceNumber = try computeInvoiceNumber(protocolID: protocolID, keyID: keyID)
        let invoiceBytes = invoiceNumber.data(using: .utf8)!
        return Digest.hmacSha256(data: invoiceBytes, key: compressed)
    }

    // MARK: - Raw BRC-42 primitive

    /// Compute the BRC-42 child private key given the root private key, the
    /// counterparty's public key, and a UTF-8 invoice number.
    ///
    /// `childPriv = (rootPriv + HMAC-SHA256(invoice, compressed(rootPriv * counterpartyPub))) mod N`
    ///
    /// Throws `WalletError.unknown` if the derived scalar is invalid (zero
    /// or >= curve order). Matches the BIP-32 / ExtendedKey behaviour: the
    /// previous `?? priv` fallback silently returned the parent key, which
    /// is a correctness and security bug.
    func deriveChildPrivate(
        priv: PrivateKey,
        counterpartyPub: PublicKey,
        invoiceNumber: String
    ) throws -> PrivateKey {
        // Shared secret = priv * counterpartyPub
        let sharedPoint = counterpartyPub.point.multiplied(by: priv.data)
        let compressed = sharedPoint.compressed()
        let invoiceBytes = invoiceNumber.data(using: .utf8)!
        let hmac = Digest.hmacSha256(data: invoiceBytes, key: compressed)
        let child = scalarAddModN(hmac, priv.data)
        // A BRC-42 derivation can in theory produce the zero scalar; the ts-sdk
        // treats that as an invalid state. Guard against it.
        guard let derived = PrivateKey(data: child) else {
            throw WalletError.unknown("BRC-42 derivation produced invalid scalar")
        }
        return derived
    }

    /// Compute the BRC-42 child public key given the counterparty's public key,
    /// the counterparty's private key, and a UTF-8 invoice number.
    ///
    /// `childPub = rootPub + (HMAC-SHA256(invoice, compressed(counterpartyPriv * rootPub))) * G`
    ///
    /// Throws `WalletError.unknown` if the resulting point is the identity
    /// at infinity — the caller must never silently fall back to the parent
    /// key, which would collapse distinct derivations onto the same output.
    func deriveChildPublic(
        pub: PublicKey,
        counterpartyPriv: PrivateKey,
        invoiceNumber: String
    ) throws -> PublicKey {
        let sharedPoint = pub.point.multiplied(by: counterpartyPriv.data)
        let compressed = sharedPoint.compressed()
        let invoiceBytes = invoiceNumber.data(using: .utf8)!
        let hmac = Digest.hmacSha256(data: invoiceBytes, key: compressed)
        let hmacPoint = Secp256k1.G.multiplied(by: hmac)
        let childPoint = pub.point.adding(hmacPoint)
        guard let derived = PublicKey(point: childPoint) else {
            throw WalletError.unknown("BRC-42 derivation produced identity public key")
        }
        return derived
    }

    // MARK: - Helpers

    /// Normalise a counterparty reference to a concrete public key.
    private func normaliseCounterparty(_ counterparty: WalletCounterparty) -> PublicKey {
        switch counterparty {
        case .`self`:
            return PublicKey.fromPrivateKey(rootKey)
        case .anyone:
            return PublicKey.fromPrivateKey(KeyDeriver.anyone.rootKey)
        case .publicKey(let pk):
            return pk
        }
    }

    /// Compute the BRC-43 invoice number string: `"<securityLevel>-<protocolName>-<keyID>"`.
    ///
    /// Enforces the same validation rules as the ts-sdk:
    /// - protocol name must be 5–400 chars (with exception for specific linkage revelation)
    /// - no consecutive spaces, only `[a-z0-9 ]`
    /// - must not end with " protocol"
    /// - key ID must be 1–800 chars
    func computeInvoiceNumber(protocolID: WalletProtocol, keyID: String) throws -> String {
        let securityLevel = protocolID.securityLevel
        let protocolName = protocolID.protocol.lowercased().trimmingCharacters(in: .whitespaces)

        guard !keyID.isEmpty else {
            throw WalletError.invalidParameter(name: "keyID", message: "Key IDs must be 1 character or more")
        }
        guard keyID.count <= 800 else {
            throw WalletError.invalidParameter(name: "keyID", message: "Key IDs must be 800 characters or less")
        }

        if protocolName.count > 400 {
            if protocolName.hasPrefix("specific linkage revelation ") {
                if protocolName.count > 430 {
                    throw WalletError.invalidParameter(
                        name: "protocolID",
                        message: "Specific linkage revelation protocol names must be 430 characters or less"
                    )
                }
            } else {
                throw WalletError.invalidParameter(
                    name: "protocolID",
                    message: "Protocol names must be 400 characters or less"
                )
            }
        }
        guard protocolName.count >= 5 else {
            throw WalletError.invalidParameter(name: "protocolID", message: "Protocol names must be 5 characters or more")
        }
        guard !protocolName.contains("  ") else {
            throw WalletError.invalidParameter(
                name: "protocolID",
                message: "Protocol names cannot contain multiple consecutive spaces"
            )
        }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789 ")
        guard protocolName.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw WalletError.invalidParameter(
                name: "protocolID",
                message: "Protocol names can only contain letters, numbers and spaces"
            )
        }
        guard !protocolName.hasSuffix(" protocol") else {
            throw WalletError.invalidParameter(
                name: "protocolID",
                message: "No need to end your protocol name with \" protocol\""
            )
        }

        return "\(securityLevel.rawValue)-\(protocolName)-\(keyID)"
    }
}
