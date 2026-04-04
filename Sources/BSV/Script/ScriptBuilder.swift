// SPDX-License-Identifier: Open BSV License Version 5
// Fluent builder for constructing Bitcoin scripts.

import Foundation

/// Fluent builder for constructing Bitcoin scripts incrementally.
///
/// Example:
/// ```swift
/// let script = ScriptBuilder()
///     .addOpcode(OpCodes.OP_DUP)
///     .addOpcode(OpCodes.OP_HASH160)
///     .addData(hash160)
///     .addOpcode(OpCodes.OP_EQUALVERIFY)
///     .addOpcode(OpCodes.OP_CHECKSIG)
///     .build()
/// ```
public class ScriptBuilder {
    private var chunks: [ScriptChunk] = []

    public init() {}

    /// Add a bare opcode (no data).
    @discardableResult
    public func addOpcode(_ opcode: UInt8) -> ScriptBuilder {
        chunks.append(ScriptChunk(opcode: opcode))
        return self
    }

    /// Add a data push with minimal encoding.
    @discardableResult
    public func addData(_ data: Data) -> ScriptBuilder {
        chunks.append(ScriptChunk.encodePushData(data))
        return self
    }

    /// Add a pre-built chunk directly.
    @discardableResult
    public func addChunk(_ chunk: ScriptChunk) -> ScriptBuilder {
        chunks.append(chunk)
        return self
    }

    /// Build the final Script from the accumulated chunks.
    public func build() -> Script {
        return Script.fromChunks(chunks)
    }
}
