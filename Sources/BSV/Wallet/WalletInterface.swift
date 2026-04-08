import Foundation

/// The BRC-100 wallet surface used by wallet applications.
///
/// This mirrors the ts-sdk `WalletInterface` type, restricted to the core
/// cryptographic methods that a local `ProtoWallet` or a remote `WalletClient`
/// can fulfil without additional infrastructure (transaction building,
/// certificate storage, and permission management are layered on top).
///
/// Implementations must be `Sendable` so they can be shared across actors.
public protocol WalletInterface: Sendable {
    /// Return the identity public key, or a BRC-42 derived public key.
    func getPublicKey(args: GetPublicKeyArgs) async throws -> GetPublicKeyResult

    /// Encrypt with a derived symmetric key. Output is the raw AES-GCM ciphertext.
    func encrypt(args: WalletEncryptArgs) async throws -> WalletEncryptResult

    /// Decrypt with a derived symmetric key.
    func decrypt(args: WalletDecryptArgs) async throws -> WalletDecryptResult

    /// Compute an HMAC-SHA256 with a derived symmetric key.
    func createHmac(args: CreateHmacArgs) async throws -> CreateHmacResult

    /// Verify an HMAC-SHA256 with a derived symmetric key.
    func verifyHmac(args: VerifyHmacArgs) async throws -> VerifyHmacResult

    /// Produce a DER-encoded ECDSA signature using a derived private key.
    ///
    /// Exactly one of `data` or `hashToDirectlySign` must be supplied.
    func createSignature(args: CreateSignatureArgs) async throws -> CreateSignatureResult

    /// Verify a DER-encoded ECDSA signature.
    func verifySignature(args: VerifySignatureArgs) async throws -> VerifySignatureResult

    /// Reveal the counterparty-level key linkage for BRC-72 audit purposes.
    func revealCounterpartyKeyLinkage(
        args: RevealCounterpartyKeyLinkageArgs
    ) async throws -> RevealCounterpartyKeyLinkageResult

    /// Reveal a specific key linkage for BRC-72 audit purposes.
    func revealSpecificKeyLinkage(
        args: RevealSpecificKeyLinkageArgs
    ) async throws -> RevealSpecificKeyLinkageResult
}
