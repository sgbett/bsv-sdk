import Foundation

// MARK: - BRC-100 scalar type aliases

/// Security level for protocols per BRC-43.
/// - 0 = silent (no user interaction)
/// - 1 = requires approval per application
/// - 2 = requires approval per counterparty per application
public enum SecurityLevel: Int, Sendable, Codable {
    case silent = 0
    case app = 1
    case counterparty = 2
}

/// A BRC-43 wallet protocol identifier: a pair of (security level, protocol name).
public struct WalletProtocol: Sendable, Equatable {
    public let securityLevel: SecurityLevel
    public let `protocol`: String

    public init(securityLevel: SecurityLevel, protocol: String) {
        self.securityLevel = securityLevel
        self.`protocol` = `protocol`
    }
}

/// A BRC-42 counterparty reference: either a specific public key, the current identity ("self"),
/// or the publicly-known "anyone" key (1*G).
public enum WalletCounterparty: Sendable, Equatable {
    case `self`
    case anyone
    case publicKey(PublicKey)

    /// Construct from a hex-encoded compressed public key.
    public static func hex(_ hex: String) -> WalletCounterparty? {
        guard let pk = PublicKey(hex: hex) else { return nil }
        return .publicKey(pk)
    }
}

// MARK: - Common BRC-100 argument shapes

/// Shared encryption-argument fields reused by encrypt/decrypt/hmac/signature/getPublicKey.
public struct WalletEncryptionArgs: Sendable, Equatable {
    public var protocolID: WalletProtocol
    public var keyID: String
    public var counterparty: WalletCounterparty
    public var privileged: Bool
    public var privilegedReason: String?
    public var seekPermission: Bool

    public init(
        protocolID: WalletProtocol,
        keyID: String,
        counterparty: WalletCounterparty = .`self`,
        privileged: Bool = false,
        privilegedReason: String? = nil,
        seekPermission: Bool = true
    ) {
        self.protocolID = protocolID
        self.keyID = keyID
        self.counterparty = counterparty
        self.privileged = privileged
        self.privilegedReason = privilegedReason
        self.seekPermission = seekPermission
    }
}

/// Arguments for `getPublicKey`.
///
/// When `identityKey` is `true`, the root identity key is returned and
/// `encryption` is ignored. Otherwise `encryption` must be supplied.
public struct GetPublicKeyArgs: Sendable {
    public var identityKey: Bool
    public var forSelf: Bool
    public var encryption: WalletEncryptionArgs?

    public init(identityKey: Bool = false, forSelf: Bool = false, encryption: WalletEncryptionArgs? = nil) {
        self.identityKey = identityKey
        self.forSelf = forSelf
        self.encryption = encryption
    }
}

public struct GetPublicKeyResult: Sendable, Equatable {
    public let publicKey: PublicKey
    public init(publicKey: PublicKey) { self.publicKey = publicKey }
}

public struct WalletEncryptArgs: Sendable {
    public var encryption: WalletEncryptionArgs
    public var plaintext: Data
    public init(encryption: WalletEncryptionArgs, plaintext: Data) {
        self.encryption = encryption
        self.plaintext = plaintext
    }
}

public struct WalletEncryptResult: Sendable, Equatable {
    public let ciphertext: Data
    public init(ciphertext: Data) { self.ciphertext = ciphertext }
}

public struct WalletDecryptArgs: Sendable {
    public var encryption: WalletEncryptionArgs
    public var ciphertext: Data
    public init(encryption: WalletEncryptionArgs, ciphertext: Data) {
        self.encryption = encryption
        self.ciphertext = ciphertext
    }
}

public struct WalletDecryptResult: Sendable, Equatable {
    public let plaintext: Data
    public init(plaintext: Data) { self.plaintext = plaintext }
}

public struct CreateHmacArgs: Sendable {
    public var encryption: WalletEncryptionArgs
    public var data: Data
    public init(encryption: WalletEncryptionArgs, data: Data) {
        self.encryption = encryption
        self.data = data
    }
}

public struct CreateHmacResult: Sendable, Equatable {
    public let hmac: Data
    public init(hmac: Data) { self.hmac = hmac }
}

public struct VerifyHmacArgs: Sendable {
    public var encryption: WalletEncryptionArgs
    public var data: Data
    public var hmac: Data
    public init(encryption: WalletEncryptionArgs, data: Data, hmac: Data) {
        self.encryption = encryption
        self.data = data
        self.hmac = hmac
    }
}

public struct VerifyHmacResult: Sendable, Equatable {
    public let valid: Bool
    public init(valid: Bool) { self.valid = valid }
}

public struct CreateSignatureArgs: Sendable {
    public var encryption: WalletEncryptionArgs
    public var data: Data?
    public var hashToDirectlySign: Data?
    public init(encryption: WalletEncryptionArgs, data: Data? = nil, hashToDirectlySign: Data? = nil) {
        self.encryption = encryption
        self.data = data
        self.hashToDirectlySign = hashToDirectlySign
    }
}

public struct CreateSignatureResult: Sendable, Equatable {
    public let signature: Data
    public init(signature: Data) { self.signature = signature }
}

public struct VerifySignatureArgs: Sendable {
    public var encryption: WalletEncryptionArgs
    public var signature: Data
    public var data: Data?
    public var hashToDirectlyVerify: Data?
    public var forSelf: Bool
    public init(
        encryption: WalletEncryptionArgs,
        signature: Data,
        data: Data? = nil,
        hashToDirectlyVerify: Data? = nil,
        forSelf: Bool = false
    ) {
        self.encryption = encryption
        self.signature = signature
        self.data = data
        self.hashToDirectlyVerify = hashToDirectlyVerify
        self.forSelf = forSelf
    }
}

public struct VerifySignatureResult: Sendable, Equatable {
    public let valid: Bool
    public init(valid: Bool) { self.valid = valid }
}

// MARK: - Linkage revelation types

public struct RevealCounterpartyKeyLinkageArgs: Sendable {
    public var counterparty: PublicKey
    public var verifier: PublicKey
    public var privileged: Bool
    public var privilegedReason: String?
    public init(counterparty: PublicKey, verifier: PublicKey, privileged: Bool = false, privilegedReason: String? = nil) {
        self.counterparty = counterparty
        self.verifier = verifier
        self.privileged = privileged
        self.privilegedReason = privilegedReason
    }
}

public struct RevealSpecificKeyLinkageArgs: Sendable {
    public var counterparty: WalletCounterparty
    public var verifier: PublicKey
    public var protocolID: WalletProtocol
    public var keyID: String
    public var privileged: Bool
    public var privilegedReason: String?
    public init(
        counterparty: WalletCounterparty,
        verifier: PublicKey,
        protocolID: WalletProtocol,
        keyID: String,
        privileged: Bool = false,
        privilegedReason: String? = nil
    ) {
        self.counterparty = counterparty
        self.verifier = verifier
        self.protocolID = protocolID
        self.keyID = keyID
        self.privileged = privileged
        self.privilegedReason = privilegedReason
    }
}

public struct RevealCounterpartyKeyLinkageResult: Sendable, Equatable {
    public let prover: PublicKey
    public let verifier: PublicKey
    public let counterparty: PublicKey
    public let revelationTime: String
    public let encryptedLinkage: Data
    public let encryptedLinkageProof: Data
}

public struct RevealSpecificKeyLinkageResult: Sendable, Equatable {
    public let prover: PublicKey
    public let verifier: PublicKey
    public let counterparty: WalletCounterparty
    public let protocolID: WalletProtocol
    public let keyID: String
    public let encryptedLinkage: Data
    public let encryptedLinkageProof: Data
    public let proofType: UInt8
}
