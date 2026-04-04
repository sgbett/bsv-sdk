# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Swift SDK for the BSV Blockchain (`BSV` Swift Package). Part of the official BSV SDK family alongside [go-sdk](https://github.com/bsv-blockchain/go-sdk), [ts-sdk](https://github.com/bsv-blockchain/ts-sdk), and [py-sdk](https://github.com/bsv-blockchain/py-sdk). Use those as reference implementations when building features.

**Reference SDK clones** are at `/opt/ruby/bsv-reference-sdks/` (`go-sdk/`, `ts-sdk/`, `py-sdk/`). Search these when implementing new features to match behaviour across SDKs. Run `git -C /opt/ruby/bsv-reference-sdks/<sdk> pull` to update before comparing.

**BSV knowledge sources** (available via MCP in `.mcp.json`):
- **bsv-protocol-docs** — [BSV Hub protocol documentation](https://hub.bsvblockchain.org/bitcoin-protocol-documentation) for verifying protocol conformance
- **bsv-knowledge** — RAG-based knowledge server for BSV-specific queries and context

Licence: Open BSV License Version 5.

## Commands

```bash
swift build                              # build the package
swift test                               # run all tests
swift test --filter BSVTests.DigestTests  # run a specific test class
swift test --filter BSVTests.DigestTests/testSha256  # run a single test
swift package clean                      # clean build artifacts
```

## Swift Version Compatibility

- **Development:** Swift 6+ / Xcode 16+
- **Platforms:** macOS (primary), iOS (secondary)

## Architecture

Package name: `BSV`. Entry point: `Sources/BSV/`.

Three top-level modules:

- **`Primitives`** — keys, curves, hashing, encryption
- **`Script`** — script parsing, opcodes, templates, interpreter
- **`Transaction`** — building, signing, BEEF, merkle proofs

Build order follows the same dependency chain as the other SDKs: primitives → script → transaction → everything else.

### Declarative vs Imperative Split

The SDK is **declarative** — it defines what things *are*: data structures, serialisation formats, cryptographic algorithms, protocol rules. It answers questions like "what is a transaction?", "how do you derive an HD key?", "how is a script encoded?".

The companion macOS wallet application is **imperative** — it defines what to *do*: workflows, use-cases, and orchestration. It answers questions like "set up a wallet from a mnemonic", "broadcast and track a payment".

The SDK should be substantially complete before building complex wallet features. When the SDK covers the declarative layer thoroughly, the wallet becomes a thin orchestration layer that picks and chooses SDK capabilities.

## Protocol Philosophy

BSV preserves the original Bitcoin protocol design. The SDK reflects this: it implements what the BSV network supports today.

**Recognise everything, construct only what's valid.** The SDK provides full parsing and detection of all script types (including legacy and historical outputs), but does not provide constructors for protocol features BSV has removed or never adopted. For example:

- `isP2SH` detection and script hash extraction are supported (read-only)
- P2SH lock/unlock constructors are not provided (P2SH is not valid on BSV)
- SegWit, Taproot (BIP-340), Replace-by-Fee, and bech32 addresses are not implemented

When reference SDKs (Go, TS, Python) include features that conflict with this principle, this principle takes precedence.

### Script Parser vs Interpreter

The script system has two distinct layers with different responsibilities:

- **Parser** (`Script`, `Script.fromASM`, `Script.fromBinary`, `chunks`, type detection) — structural analysis. Understands what a script *is*. Protocol-version-agnostic. This is where the "recognise everything" principle applies: any valid script (including historical pre-genesis constructs) should parse, serialise, and be identifiable.

- **Interpreter** (`Interpreter.evaluate`, `Interpreter.verify`) — behavioural execution. Determines whether a script *succeeds* under current consensus rules. Always operates in post-genesis mode. Scripts that were valid pre-genesis but invalid post-genesis will correctly fail execution — this is consensus enforcement, not a recognition failure.

A script being parseable but failing execution is not a bug — it's the distinction between these two layers working correctly.

## Cryptography

- **CryptoKit** — SHA-256, SHA-512, SHA-1, HMAC-SHA256/512, AES-GCM (Apple system framework)
- **secp256k1.swift** (21-DOT-DEV) — ECDSA, Schnorr, ECDH, key recovery, key tweaking (wraps bitcoin-core/secp256k1)
- **CommonCrypto** — PBKDF2, AES-CBC for ECIES (Apple system framework)
- **RIPEMD-160** — vendored implementation or lightweight package (not in CryptoKit)

Items needing custom implementation: DER signature encoding (BIP-66), Base58Check, BIP-32/39, WIF encoding, address generation.

## Conventions

- Use `Data` for binary buffers throughout (not `[UInt8]`)
- XCTest for all tests
- Test vectors shared across SDKs (JSON files from go-sdk `script/interpreter/data/` and `primitives/ec/testdata/`)
- No external dependencies beyond secp256k1.swift and RIPEMD-160
