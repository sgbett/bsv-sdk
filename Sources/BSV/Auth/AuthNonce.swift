import Foundation

/// BRC-66 nonce helpers.
///
/// A server-authenticated nonce is a 32-byte base64 string composed of:
///   * 16 bytes of random data, followed by
///   * a 16-byte HMAC-SHA256 truncation of those bytes, keyed by a derived
///     wallet secret under protocolID `[2, 'server hmac']` with the random
///     prefix as the `keyID`.
///
/// This mirrors the ts-sdk `createNonce` / `verifyNonce` utilities and lets a
/// peer later check that a given nonce was minted by itself, without any
/// external state.
public enum AuthNonce {
    /// Protocol used to scope the nonce HMAC key.
    public static let protocolID = WalletProtocol(securityLevel: .counterparty, protocol: "server hmac")

    /// Generate a base64-encoded self-authenticating nonce.
    ///
    /// - Parameter wallet: the wallet used to create the HMAC envelope.
    /// - Parameter counterparty: optional counterparty. Defaults to `.self`.
    public static func create(
        wallet: WalletInterface,
        counterparty: WalletCounterparty = .`self`
    ) async throws -> String {
        var random = Data(count: 16)
        let status = random.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw AuthError.transportFailure("failed to generate nonce randomness")
        }

        let keyID = random.base64EncodedString()
        let hmacResult = try await wallet.createHmac(args: CreateHmacArgs(
            encryption: WalletEncryptionArgs(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: counterparty
            ),
            data: random
        ))

        var nonce = Data()
        nonce.append(random)
        nonce.append(hmacResult.hmac.prefix(16))
        return nonce.base64EncodedString()
    }

    /// Verify that a base64-encoded nonce was produced by `create` using the
    /// same wallet and counterparty.
    public static func verify(
        _ nonce: String,
        wallet: WalletInterface,
        counterparty: WalletCounterparty = .`self`
    ) async throws -> Bool {
        guard let decoded = Data(base64Encoded: nonce), decoded.count == 32 else {
            return false
        }
        let randomPrefix = decoded.prefix(16)
        let macSuffix = decoded.suffix(16)
        let keyID = Data(randomPrefix).base64EncodedString()

        // Recompute the HMAC and compare against the stored suffix. We call
        // createHmac rather than verifyHmac because we only keep the first 16
        // bytes of the digest on the wire.
        let hmacResult = try await wallet.createHmac(args: CreateHmacArgs(
            encryption: WalletEncryptionArgs(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: counterparty
            ),
            data: Data(randomPrefix)
        ))
        let expected = hmacResult.hmac.prefix(16)
        return ConstantTime.equal(Data(expected), Data(macSuffix))
    }
}
