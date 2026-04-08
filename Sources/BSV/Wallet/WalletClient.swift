import Foundation

/// A BRC-100 wallet client that forwards calls to a remote wallet over a `WalletSubstrate`.
///
/// `WalletClient` is the counterpart to `ProtoWallet`: it implements the same
/// `WalletInterface` but instead of doing the cryptography locally it encodes
/// each call as JSON, sends it through a substrate, and decodes the response.
///
/// This mirrors the ts-sdk `WalletClient` class. Byte fields in the JSON
/// wire format are encoded as an array of numbers 0…255 to stay compatible
/// with the ts-sdk substrates.
public struct WalletClient: WalletInterface {
    public let substrate: WalletSubstrate
    public let originator: String?

    public init(substrate: WalletSubstrate, originator: String? = nil) {
        self.substrate = substrate
        self.originator = originator
    }

    // MARK: - Identity / derivation

    public func getPublicKey(args: GetPublicKeyArgs) async throws -> GetPublicKeyResult {
        var payload: [String: Any] = [
            "identityKey": args.identityKey,
            "forSelf": args.forSelf
        ]
        if let enc = args.encryption {
            payload.merge(Self.encodeEncryptionArgs(enc)) { _, new in new }
        }
        let response = try await call("getPublicKey", payload: payload)
        guard let hex = response["publicKey"] as? String,
              let pk = PublicKey(hex: hex) else {
            throw WalletError.unknown("invalid publicKey in getPublicKey response")
        }
        return GetPublicKeyResult(publicKey: pk)
    }

    // MARK: - Encryption

    public func encrypt(args: WalletEncryptArgs) async throws -> WalletEncryptResult {
        var payload = Self.encodeEncryptionArgs(args.encryption)
        payload["plaintext"] = Self.encodeBytes(args.plaintext)
        let response = try await call("encrypt", payload: payload)
        guard let ct = Self.decodeBytes(response["ciphertext"]) else {
            throw WalletError.unknown("missing ciphertext in encrypt response")
        }
        return WalletEncryptResult(ciphertext: ct)
    }

    public func decrypt(args: WalletDecryptArgs) async throws -> WalletDecryptResult {
        var payload = Self.encodeEncryptionArgs(args.encryption)
        payload["ciphertext"] = Self.encodeBytes(args.ciphertext)
        let response = try await call("decrypt", payload: payload)
        guard let pt = Self.decodeBytes(response["plaintext"]) else {
            throw WalletError.unknown("missing plaintext in decrypt response")
        }
        return WalletDecryptResult(plaintext: pt)
    }

    // MARK: - HMAC

    public func createHmac(args: CreateHmacArgs) async throws -> CreateHmacResult {
        var payload = Self.encodeEncryptionArgs(args.encryption)
        payload["data"] = Self.encodeBytes(args.data)
        let response = try await call("createHmac", payload: payload)
        guard let mac = Self.decodeBytes(response["hmac"]) else {
            throw WalletError.unknown("missing hmac in createHmac response")
        }
        return CreateHmacResult(hmac: mac)
    }

    public func verifyHmac(args: VerifyHmacArgs) async throws -> VerifyHmacResult {
        var payload = Self.encodeEncryptionArgs(args.encryption)
        payload["data"] = Self.encodeBytes(args.data)
        payload["hmac"] = Self.encodeBytes(args.hmac)
        let response = try await call("verifyHmac", payload: payload)
        let valid = response["valid"] as? Bool ?? false
        if !valid { throw WalletError.invalidHmac }
        return VerifyHmacResult(valid: true)
    }

    // MARK: - Signature

    public func createSignature(args: CreateSignatureArgs) async throws -> CreateSignatureResult {
        var payload = Self.encodeEncryptionArgs(args.encryption)
        if let data = args.data {
            payload["data"] = Self.encodeBytes(data)
        }
        if let hash = args.hashToDirectlySign {
            payload["hashToDirectlySign"] = Self.encodeBytes(hash)
        }
        let response = try await call("createSignature", payload: payload)
        guard let sig = Self.decodeBytes(response["signature"]) else {
            throw WalletError.unknown("missing signature in createSignature response")
        }
        return CreateSignatureResult(signature: sig)
    }

    public func verifySignature(args: VerifySignatureArgs) async throws -> VerifySignatureResult {
        var payload = Self.encodeEncryptionArgs(args.encryption)
        payload["signature"] = Self.encodeBytes(args.signature)
        payload["forSelf"] = args.forSelf
        if let data = args.data {
            payload["data"] = Self.encodeBytes(data)
        }
        if let hash = args.hashToDirectlyVerify {
            payload["hashToDirectlyVerify"] = Self.encodeBytes(hash)
        }
        let response = try await call("verifySignature", payload: payload)
        let valid = response["valid"] as? Bool ?? false
        if !valid { throw WalletError.invalidSignature }
        return VerifySignatureResult(valid: true)
    }

    // MARK: - Linkage revelation

    public func revealCounterpartyKeyLinkage(
        args: RevealCounterpartyKeyLinkageArgs
    ) async throws -> RevealCounterpartyKeyLinkageResult {
        let payload: [String: Any] = [
            "counterparty": args.counterparty.hex,
            "verifier": args.verifier.hex,
            "privileged": args.privileged,
            "privilegedReason": args.privilegedReason as Any
        ]
        let response = try await call("revealCounterpartyKeyLinkage", payload: payload)
        guard
            let proverHex = response["prover"] as? String,
            let prover = PublicKey(hex: proverHex),
            let verifierHex = response["verifier"] as? String,
            let verifier = PublicKey(hex: verifierHex),
            let cpHex = response["counterparty"] as? String,
            let cp = PublicKey(hex: cpHex),
            let time = response["revelationTime"] as? String,
            let encryptedLinkage = Self.decodeBytes(response["encryptedLinkage"]),
            let proof = Self.decodeBytes(response["encryptedLinkageProof"])
        else {
            throw WalletError.unknown("invalid revealCounterpartyKeyLinkage response")
        }
        return RevealCounterpartyKeyLinkageResult(
            prover: prover,
            verifier: verifier,
            counterparty: cp,
            revelationTime: time,
            encryptedLinkage: encryptedLinkage,
            encryptedLinkageProof: proof
        )
    }

    public func revealSpecificKeyLinkage(
        args: RevealSpecificKeyLinkageArgs
    ) async throws -> RevealSpecificKeyLinkageResult {
        var payload: [String: Any] = [
            "counterparty": Self.encodeCounterparty(args.counterparty),
            "verifier": args.verifier.hex,
            "protocolID": [args.protocolID.securityLevel.rawValue, args.protocolID.protocol] as [Any],
            "keyID": args.keyID,
            "privileged": args.privileged
        ]
        if let reason = args.privilegedReason {
            payload["privilegedReason"] = reason
        }
        let response = try await call("revealSpecificKeyLinkage", payload: payload)
        guard
            let proverHex = response["prover"] as? String,
            let prover = PublicKey(hex: proverHex),
            let verifierHex = response["verifier"] as? String,
            let verifier = PublicKey(hex: verifierHex),
            let encryptedLinkage = Self.decodeBytes(response["encryptedLinkage"]),
            let proof = Self.decodeBytes(response["encryptedLinkageProof"]),
            let proofType = response["proofType"] as? Int
        else {
            throw WalletError.unknown("invalid revealSpecificKeyLinkage response")
        }
        return RevealSpecificKeyLinkageResult(
            prover: prover,
            verifier: verifier,
            counterparty: args.counterparty,
            protocolID: args.protocolID,
            keyID: args.keyID,
            encryptedLinkage: encryptedLinkage,
            encryptedLinkageProof: proof,
            proofType: UInt8(truncatingIfNeeded: proofType)
        )
    }

    // MARK: - Internal helpers

    /// POST a JSON payload to the substrate and decode the response as a JSON object.
    private func call(_ method: String, payload: [String: Any]) async throws -> [String: Any] {
        let body = try JSONSerialization.data(withJSONObject: payload, options: [])
        let responseData = try await substrate.invoke(method: method, body: body, originator: originator)
        if responseData.isEmpty {
            return [:]
        }
        guard let json = try JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
            throw WalletError.unknown("\(method) response was not a JSON object")
        }
        return json
    }

    /// Encode the shared `WalletEncryptionArgs` fields into a BRC-100 payload.
    static func encodeEncryptionArgs(_ args: WalletEncryptionArgs) -> [String: Any] {
        var payload: [String: Any] = [
            "protocolID": [args.protocolID.securityLevel.rawValue, args.protocolID.protocol] as [Any],
            "keyID": args.keyID,
            "counterparty": encodeCounterparty(args.counterparty),
            "privileged": args.privileged,
            "seekPermission": args.seekPermission
        ]
        if let reason = args.privilegedReason {
            payload["privilegedReason"] = reason
        }
        return payload
    }

    static func encodeCounterparty(_ counterparty: WalletCounterparty) -> Any {
        switch counterparty {
        case .`self`: return "self"
        case .anyone: return "anyone"
        case .publicKey(let pk): return pk.hex
        }
    }

    /// Encode raw bytes as an array of byte-valued integers (ts-sdk wire format).
    static func encodeBytes(_ data: Data) -> [UInt8] {
        Array(data)
    }

    /// Decode the ts-sdk wire format for bytes: either an array of integers or a hex string.
    static func decodeBytes(_ value: Any?) -> Data? {
        if let bytes = value as? [UInt8] {
            return Data(bytes)
        }
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
