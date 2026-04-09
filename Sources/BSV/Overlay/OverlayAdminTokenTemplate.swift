// SPDX-License-Identifier: Open BSV License Version 5
// SHIP/SLAP advertisement template (PushDrop-shaped tokens).
//
// Ported from ts-sdk src/overlay-tools/OverlayAdminTokenTemplate.ts. The
// ts-sdk builds these tokens on top of its generic `PushDrop` template;
// because the Swift SDK does not yet expose a generic PushDrop template,
// this file inlines the minimal PushDrop layout that SHIP/SLAP needs:
//
//     <lockingPubKey> OP_CHECKSIG <protocol> <identityKey> <domain>
//     <topicOrService> <signature> OP_2DROP OP_2DROP OP_DROP
//
// The five fields after OP_CHECKSIG are dropped by the `OP_2DROP OP_2DROP
// OP_DROP` tail so that the output is spendable as a bare P2PK from the
// locking key.

import Foundation

/// Result of decoding a SHIP or SLAP advertisement script.
public struct OverlayAdminAdvertisement: Sendable, Equatable {
    /// Either `.ship` or `.slap`.
    public var protocolKind: OverlayAdminProtocol
    /// Identity key of the advertising host (compressed hex).
    public var identityKey: String
    /// Domain under which the host exposes its overlay services.
    public var domain: String
    /// For `.ship`: the topic manager name. For `.slap`: the lookup service name.
    public var topicOrService: String

    public init(
        protocolKind: OverlayAdminProtocol,
        identityKey: String,
        domain: String,
        topicOrService: String
    ) {
        self.protocolKind = protocolKind
        self.identityKey = identityKey
        self.domain = domain
        self.topicOrService = topicOrService
    }
}

/// The two advertisement protocols supported by the overlay admin template.
public enum OverlayAdminProtocol: String, Sendable, Equatable {
    case ship = "SHIP"
    case slap = "SLAP"

    /// The BRC-43 protocol name used when signing the locking script fields.
    public var signingProtocolName: String {
        switch self {
        case .ship: return "Service Host Interconnect"
        case .slap: return "Service Lookup Availability"
        }
    }
}

/// Script template that creates and decodes SHIP/SLAP advertisement tokens.
public struct OverlayAdminTokenTemplate: Sendable {
    /// The wallet used to fetch the host identity key and produce signatures.
    public let wallet: WalletInterface
    /// Optional BRC-100 originator string.
    public let originator: String?

    public init(wallet: WalletInterface, originator: String? = nil) {
        self.wallet = wallet
        self.originator = originator
    }

    // MARK: - Decoding

    /// Decode a SHIP or SLAP advertisement from a locking script.
    public static func decode(_ script: Script) throws -> OverlayAdminAdvertisement {
        let chunks = script.chunks
        // Minimum: pubkey push + OP_CHECKSIG + 4 field pushes + OP_2DROP OP_2DROP OP_DROP
        guard chunks.count >= 10 else {
            throw OverlayError.invalidAdvertisement("script too short")
        }
        // The first chunk is the locking public key push.
        guard chunks[0].isDataPush, chunks[0].data != nil else {
            throw OverlayError.invalidAdvertisement("missing locking public key push")
        }
        guard chunks[1].opcode == OpCodes.OP_CHECKSIG else {
            throw OverlayError.invalidAdvertisement("expected OP_CHECKSIG after locking public key")
        }

        // Locate the tail of OP_2DROP/OP_DROP ops to bound the field region.
        var fieldEnd = chunks.count
        while fieldEnd > 2 {
            let op = chunks[fieldEnd - 1].opcode
            if op == OpCodes.OP_2DROP || op == OpCodes.OP_DROP {
                fieldEnd -= 1
                continue
            }
            break
        }
        // Fields region is [2, fieldEnd) — must contain at least 4 pushes.
        guard fieldEnd - 2 >= 4 else {
            throw OverlayError.invalidAdvertisement("fewer than 4 data fields")
        }

        func pushData(at index: Int) throws -> Data {
            let chunk = chunks[index]
            if let data = chunk.data { return data }
            // Small-int opcodes (OP_0..OP_16, OP_1NEGATE) push conceptually non-empty data.
            if chunk.opcode == OpCodes.OP_0 { return Data([0]) }
            if chunk.opcode >= 0x51 && chunk.opcode <= 0x60 {
                return Data([chunk.opcode - 0x50])
            }
            if chunk.opcode == 0x4f { return Data([0x81]) }
            throw OverlayError.invalidAdvertisement("non-push opcode within fields region")
        }

        let protocolBytes = try pushData(at: 2)
        let identityKeyBytes = try pushData(at: 3)
        let domainBytes = try pushData(at: 4)
        let topicBytes = try pushData(at: 5)

        guard let protocolString = String(data: protocolBytes, encoding: .utf8),
              let kind = OverlayAdminProtocol(rawValue: protocolString) else {
            throw OverlayError.invalidAdvertisement("protocol field is not SHIP or SLAP")
        }
        guard let domain = String(data: domainBytes, encoding: .utf8) else {
            throw OverlayError.invalidAdvertisement("domain is not valid UTF-8")
        }
        guard let topicOrService = String(data: topicBytes, encoding: .utf8) else {
            throw OverlayError.invalidAdvertisement("topicOrService is not valid UTF-8")
        }

        return OverlayAdminAdvertisement(
            protocolKind: kind,
            identityKey: identityKeyBytes.hex,
            domain: domain,
            topicOrService: topicOrService
        )
    }

    // MARK: - Locking

    /// Build a SHIP or SLAP advertisement locking script.
    ///
    /// The script has the shape:
    ///
    ///     <pubkey> OP_CHECKSIG <protocol> <identityKey> <domain>
    ///     <topicOrService> <signature> OP_2DROP OP_2DROP OP_DROP
    public func lock(
        protocol kind: OverlayAdminProtocol,
        domain: String,
        topicOrService: String
    ) async throws -> Script {
        let protocolID = WalletProtocol(
            securityLevel: .counterparty,
            protocol: kind.signingProtocolName
        )
        let encryption = WalletEncryptionArgs(
            protocolID: protocolID,
            keyID: "1",
            counterparty: .`self`
        )

        // Identity key of the advertising host.
        let identityResult = try await wallet.getPublicKey(
            args: GetPublicKeyArgs(identityKey: true)
        )
        let identityKey = identityResult.publicKey

        // Locking public key derived via BRC-42 for this protocol/key/self.
        let lockingKeyResult = try await wallet.getPublicKey(
            args: GetPublicKeyArgs(encryption: encryption)
        )
        let lockingKey = lockingKeyResult.publicKey

        var fields: [Data] = [
            Data(kind.rawValue.utf8),
            identityKey.toCompressed(),
            Data(domain.utf8),
            Data(topicOrService.utf8)
        ]

        // The data signed by PushDrop tokens is the concatenation of the fields.
        var dataToSign = Data()
        for field in fields { dataToSign.append(field) }

        let signatureResult = try await wallet.createSignature(args: CreateSignatureArgs(
            encryption: encryption,
            data: dataToSign
        ))
        fields.append(signatureResult.signature)

        var bytes = Data()

        // <pubkey> OP_CHECKSIG ...
        let lockingKeyBytes = lockingKey.toCompressed()
        bytes.append(ScriptChunk.encodePushData(lockingKeyBytes).toBinary())
        bytes.append(OpCodes.OP_CHECKSIG)

        // Field pushes.
        for field in fields {
            bytes.append(Self.minimalPushChunk(for: field).toBinary())
        }

        // Drop every field with OP_2DROP until at most one remains, then OP_DROP.
        var notYetDropped = fields.count
        while notYetDropped > 1 {
            bytes.append(OpCodes.OP_2DROP)
            notYetDropped -= 2
        }
        if notYetDropped != 0 {
            bytes.append(OpCodes.OP_DROP)
        }

        return Script(data: bytes)
    }

    // MARK: - Helpers

    /// Minimal encoding for a PushDrop-style field push. Matches the
    /// `createMinimallyEncodedScriptChunk` helper in ts-sdk.
    static func minimalPushChunk(for data: Data) -> ScriptChunk {
        if data.isEmpty {
            return ScriptChunk(opcode: OpCodes.OP_0)
        }
        if data.count == 1 {
            let byte = data[data.startIndex]
            if byte == 0 {
                return ScriptChunk(opcode: OpCodes.OP_0)
            }
            if byte > 0 && byte <= 16 {
                return ScriptChunk(opcode: 0x50 + byte)
            }
            if byte == 0x81 {
                // OP_1NEGATE
                return ScriptChunk(opcode: 0x4f)
            }
        }
        return ScriptChunk.encodePushData(data)
    }
}
