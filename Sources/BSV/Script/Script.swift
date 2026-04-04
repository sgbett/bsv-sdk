// SPDX-License-Identifier: Open BSV License Version 5
// Bitcoin script type with lazy chunk parsing, type detection, and template constructors.

import Foundation

/// A Bitcoin script stored as raw bytes with lazy-parsed chunk access.
public struct Script {

    // MARK: - Storage

    /// The raw script bytes.
    public let data: Data

    /// Parsed chunks from the script bytes.
    public var chunks: [ScriptChunk] {
        return (try? ScriptChunk.parseAll(from: data)) ?? []
    }

    // MARK: - Initialisers

    /// Create a script from raw binary data.
    public init(data: Data) {
        self.data = data
    }

    /// Create a script from a hex string.
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.data = data
    }

    /// Create a script from pre-built chunks.
    public static func fromChunks(_ chunks: [ScriptChunk]) -> Script {
        var bytes = Data()
        for chunk in chunks {
            bytes.append(chunk.toBinary())
        }
        return Script(data: bytes)
    }

    /// Parse a script from Bitcoin ASM notation.
    ///
    /// Tokens are space-separated. Known opcode names (e.g. "OP_DUP") map to
    /// their byte value. Everything else is treated as hex data to push.
    public static func fromASM(_ asm: String) -> Script? {
        let asm = asm.trimmingCharacters(in: .whitespaces)
        if asm.isEmpty {
            return Script(data: Data())
        }

        var bytes = Data()
        for token in asm.split(separator: " ") {
            let t = String(token)
            if t == "0" {
                bytes.append(OpCodes.OP_0)
            } else if t == "-1" || t == "OP_1NEGATE" {
                bytes.append(OpCodes.OP_1NEGATE)
            } else if let code = OpCodes.code(for: t) {
                bytes.append(code)
            } else {
                // Treat as hex data push
                guard let pushData = Data(hex: t) else {
                    return nil
                }
                let chunk = ScriptChunk.encodePushData(pushData)
                bytes.append(chunk.toBinary())
            }
        }

        return Script(data: bytes)
    }

    // MARK: - Serialisation

    /// The raw binary representation.
    public func toBinary() -> Data {
        return data
    }

    /// Hex-encoded script bytes.
    public func toHex() -> String {
        return data.hex
    }

    /// ASM string representation.
    public func toASM() -> String {
        if data.isEmpty { return "" }
        return chunks.map { $0.toASM() }.joined(separator: " ")
    }

    // MARK: - Type Detection

    /// Pay-to-Public-Key-Hash: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    public var isP2PKH: Bool {
        let b = data
        return b.count == 25
            && b[0] == OpCodes.OP_DUP
            && b[1] == OpCodes.OP_HASH160
            && b[2] == OpCodes.OP_DATA_20
            && b[23] == OpCodes.OP_EQUALVERIFY
            && b[24] == OpCodes.OP_CHECKSIG
    }

    /// Pay-to-Public-Key: <pubkey> OP_CHECKSIG
    public var isP2PK: Bool {
        let parts = chunks
        guard parts.count == 2,
              let pubkey = parts[0].data,
              parts[1].opcode == OpCodes.OP_CHECKSIG else {
            return false
        }
        let version = pubkey[0]
        if (version == 0x04 || version == 0x06 || version == 0x07) && pubkey.count == 65 {
            return true
        }
        if (version == 0x02 || version == 0x03) && pubkey.count == 33 {
            return true
        }
        return false
    }

    /// Pay-to-Script-Hash (read-only detection, no constructor): OP_HASH160 <20 bytes> OP_EQUAL
    public var isP2SH: Bool {
        let b = data
        return b.count == 23
            && b[0] == OpCodes.OP_HASH160
            && b[1] == OpCodes.OP_DATA_20
            && b[22] == OpCodes.OP_EQUAL
    }

    /// OP_RETURN data output (starts with OP_RETURN or OP_FALSE OP_RETURN).
    public var isOpReturn: Bool {
        let b = data
        return (b.count > 0 && b[0] == OpCodes.OP_RETURN)
            || (b.count > 1 && b[0] == OpCodes.OP_FALSE && b[1] == OpCodes.OP_RETURN)
    }

    /// Multisig output: OP_<m> <pubkeys...> OP_<n> OP_CHECKMULTISIG
    public var isMultisig: Bool {
        let parts = chunks
        guard parts.count >= 3 else { return false }
        guard OpCodes.isSmallInt(parts[0].opcode) else { return false }
        for i in 1..<(parts.count - 2) {
            guard let d = parts[i].data, !d.isEmpty else { return false }
        }
        return OpCodes.isSmallInt(parts[parts.count - 2].opcode)
            && parts[parts.count - 1].opcode == OpCodes.OP_CHECKMULTISIG
    }

    // MARK: - Data Extraction

    /// Extract the 20-byte public key hash from a P2PKH script.
    public func publicKeyHash() -> Data? {
        guard isP2PKH else { return nil }
        return Data(data[3..<23])
    }

    /// Extract the 20-byte script hash from a P2SH script (read-only).
    public func scriptHash() -> Data? {
        guard isP2SH else { return nil }
        return Data(data[2..<22])
    }

    // MARK: - Template Constructors

    /// Create a P2PKH locking script from a 20-byte public key hash.
    /// OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    public static func p2pkhLock(hash160: Data) -> Script {
        var bytes = Data(capacity: 25)
        bytes.append(OpCodes.OP_DUP)
        bytes.append(OpCodes.OP_HASH160)
        bytes.append(OpCodes.OP_DATA_20)
        bytes.append(hash160)
        bytes.append(OpCodes.OP_EQUALVERIFY)
        bytes.append(OpCodes.OP_CHECKSIG)
        return Script(data: bytes)
    }

    /// Create a P2PKH unlocking script from a signature and compressed public key.
    /// <signature> <publicKey>
    public static func p2pkhUnlock(signature: Data, publicKey: Data) -> Script {
        var bytes = Data()
        let sigChunk = ScriptChunk.encodePushData(signature)
        bytes.append(sigChunk.toBinary())
        let pubChunk = ScriptChunk.encodePushData(publicKey)
        bytes.append(pubChunk.toBinary())
        return Script(data: bytes)
    }

    /// Create an OP_RETURN data output script.
    /// OP_FALSE OP_RETURN <data...>
    public static func opReturn(data parts: [Data]) -> Script {
        var bytes = Data()
        bytes.append(OpCodes.OP_FALSE)
        bytes.append(OpCodes.OP_RETURN)
        for part in parts {
            let chunk = ScriptChunk.encodePushData(part)
            bytes.append(chunk.toBinary())
        }
        return Script(data: bytes)
    }

    /// Convenience: single-payload OP_RETURN.
    public static func opReturn(data: Data) -> Script {
        return opReturn(data: [data])
    }
}

// MARK: - Equatable

extension Script: Equatable {
    public static func == (lhs: Script, rhs: Script) -> Bool {
        return lhs.data == rhs.data
    }
}
