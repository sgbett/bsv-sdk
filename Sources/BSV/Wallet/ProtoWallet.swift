import Foundation

/// A stateless, in-process BRC-100 wallet.
///
/// `ProtoWallet` owns a root `PrivateKey` and delegates all key derivation to
/// a `KeyDeriverAPI` (by default `KeyDeriver`). It is the foundation for the
/// local-backed `Wallet` implementation and for tests that do not need a
/// full wallet application around them.
///
/// Like its ts-sdk counterpart, `ProtoWallet` does **not** provide permission
/// prompts, persistent storage, or transaction construction. A wallet
/// application is expected to wrap it.
public struct ProtoWallet: WalletInterface {
    public let keyDeriver: KeyDeriverAPI

    public init(rootKey: PrivateKey) {
        self.keyDeriver = KeyDeriver(rootKey: rootKey)
    }

    public init(keyDeriver: KeyDeriverAPI) {
        self.keyDeriver = keyDeriver
    }

    // MARK: - Public key

    public func getPublicKey(args: GetPublicKeyArgs) async throws -> GetPublicKeyResult {
        if args.identityKey {
            return GetPublicKeyResult(publicKey: keyDeriver.identityKey)
        }
        guard let enc = args.encryption else {
            throw WalletError.invalidParameter(
                name: "encryption",
                message: "encryption args are required unless identityKey is true"
            )
        }
        let pk = try keyDeriver.derivePublicKey(
            protocolID: enc.protocolID,
            keyID: enc.keyID,
            counterparty: enc.counterparty,
            forSelf: args.forSelf
        )
        return GetPublicKeyResult(publicKey: pk)
    }

    // MARK: - Symmetric encryption

    public func encrypt(args: WalletEncryptArgs) async throws -> WalletEncryptResult {
        let key = try keyDeriver.deriveSymmetricKey(
            protocolID: args.encryption.protocolID,
            keyID: args.encryption.keyID,
            counterparty: args.encryption.counterparty
        )
        let ciphertext = try key.encrypt(args.plaintext)
        return WalletEncryptResult(ciphertext: ciphertext)
    }

    public func decrypt(args: WalletDecryptArgs) async throws -> WalletDecryptResult {
        let key = try keyDeriver.deriveSymmetricKey(
            protocolID: args.encryption.protocolID,
            keyID: args.encryption.keyID,
            counterparty: args.encryption.counterparty
        )
        let plaintext = try key.decrypt(args.ciphertext)
        return WalletDecryptResult(plaintext: plaintext)
    }

    // MARK: - HMAC

    public func createHmac(args: CreateHmacArgs) async throws -> CreateHmacResult {
        let key = try keyDeriver.deriveSymmetricKey(
            protocolID: args.encryption.protocolID,
            keyID: args.encryption.keyID,
            counterparty: args.encryption.counterparty
        )
        let mac = Digest.hmacSha256(data: args.data, key: key.key)
        return CreateHmacResult(hmac: mac)
    }

    public func verifyHmac(args: VerifyHmacArgs) async throws -> VerifyHmacResult {
        let key = try keyDeriver.deriveSymmetricKey(
            protocolID: args.encryption.protocolID,
            keyID: args.encryption.keyID,
            counterparty: args.encryption.counterparty
        )
        let expected = Digest.hmacSha256(data: args.data, key: key.key)
        let ok = ConstantTime.equal(expected, args.hmac)
        if !ok {
            throw WalletError.invalidHmac
        }
        return VerifyHmacResult(valid: true)
    }

    // MARK: - Signatures

    public func createSignature(args: CreateSignatureArgs) async throws -> CreateSignatureResult {
        // Exactly one of data/hashToDirectlySign must be supplied.
        let hash: Data
        switch (args.data, args.hashToDirectlySign) {
        case (let data?, nil):
            hash = Digest.sha256(data)
        case (nil, let directHash?):
            guard directHash.count == 32 else {
                throw WalletError.invalidParameter(
                    name: "hashToDirectlySign",
                    message: "must be exactly 32 bytes"
                )
            }
            hash = directHash
        default:
            throw WalletError.invalidParameter(
                name: "args",
                message: "exactly one of data or hashToDirectlySign must be provided"
            )
        }

        // NOTE: ts-sdk defaults `counterparty` to 'anyone' for signature creation,
        // but we cannot distinguish "omitted" from "defaulted to .self" at the
        // Swift call-site, so callers must explicitly pass `.anyone` when they
        // intend that semantics. We honour whatever the caller set.
        let child = try keyDeriver.derivePrivateKey(
            protocolID: args.encryption.protocolID,
            keyID: args.encryption.keyID,
            counterparty: args.encryption.counterparty
        )
        guard let sig = child.sign(hash: hash) else {
            throw WalletError.unknown("failed to sign")
        }
        return CreateSignatureResult(signature: sig.toDER())
    }

    public func verifySignature(args: VerifySignatureArgs) async throws -> VerifySignatureResult {
        let hash: Data
        switch (args.data, args.hashToDirectlyVerify) {
        case (let data?, nil):
            hash = Digest.sha256(data)
        case (nil, let directHash?):
            guard directHash.count == 32 else {
                throw WalletError.invalidParameter(
                    name: "hashToDirectlyVerify",
                    message: "must be exactly 32 bytes"
                )
            }
            hash = directHash
        default:
            throw WalletError.invalidParameter(
                name: "args",
                message: "exactly one of data or hashToDirectlyVerify must be provided"
            )
        }

        let pub = try keyDeriver.derivePublicKey(
            protocolID: args.encryption.protocolID,
            keyID: args.encryption.keyID,
            counterparty: args.encryption.counterparty,
            forSelf: args.forSelf
        )
        guard let sig = Signature.fromDER(args.signature) else {
            throw WalletError.invalidSignature
        }
        let ok = pub.verify(hash: hash, signature: sig)
        if !ok {
            throw WalletError.invalidSignature
        }
        return VerifySignatureResult(valid: true)
    }

    // MARK: - Linkage revelation

    public func revealCounterpartyKeyLinkage(
        args: RevealCounterpartyKeyLinkageArgs
    ) async throws -> RevealCounterpartyKeyLinkageResult {
        // BRC-72 counterparty linkage revelation requires the prover to sign
        // the linkage with a Schnorr proof binding the shared secret to the
        // verifier. The Swift SDK does not yet implement Schnorr, so we
        // throw `unsupportedAction` until the primitive lands.
        throw WalletError.unsupportedAction(
            "revealCounterpartyKeyLinkage is not yet implemented in the Swift SDK (requires Schnorr proofs)"
        )
    }

    public func revealSpecificKeyLinkage(
        args: RevealSpecificKeyLinkageArgs
    ) async throws -> RevealSpecificKeyLinkageResult {
        let secret = try keyDeriver.revealSpecificSecret(
            counterparty: args.counterparty,
            protocolID: args.protocolID,
            keyID: args.keyID
        )

        // Encrypt the linkage under a symmetric key shared with the verifier.
        let verifierCp = WalletCounterparty.publicKey(args.verifier)
        let symmetric = try keyDeriver.deriveSymmetricKey(
            protocolID: args.protocolID,
            keyID: args.keyID,
            counterparty: verifierCp
        )
        let encryptedLinkage = try symmetric.encrypt(secret)

        return RevealSpecificKeyLinkageResult(
            prover: keyDeriver.identityKey,
            verifier: args.verifier,
            counterparty: args.counterparty,
            protocolID: args.protocolID,
            keyID: args.keyID,
            encryptedLinkage: encryptedLinkage,
            encryptedLinkageProof: Data(),
            proofType: 0
        )
    }
}
