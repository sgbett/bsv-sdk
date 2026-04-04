# Swift BSV SDK — Implementation Plan

**Issue**: #1
**Project**: https://github.com/users/sgbett/projects/3

## Context

We're building a Swift BSV SDK at `/opt/xcode/bsv-sdk` to support development of a native macOS wallet application. The SDK joins the official BSV SDK family alongside [ts-sdk](https://github.com/bsv-blockchain/ts-sdk), [go-sdk](https://github.com/bsv-blockchain/go-sdk), and [py-sdk](https://github.com/bsv-blockchain/py-sdk).

**Reference implementations** (primary sources, at `/opt/ruby/bsv-reference-sdks/`):
- **ts-sdk** — zero dependencies, all crypto implemented from scratch (BigNumber, Point, ECDSA, Hash, AES-GCM)
- **go-sdk** — pure Go secp256k1 implementation, stdlib hashing, `golang.org/x/crypto` for RIPEMD-160
- **py-sdk** — uses `coincurve` (libsecp256k1 wrapper) + `pycryptodomex` for crypto

The Ruby SDK at `/opt/ruby/bsv-ruby-sdk` is a sibling implementation, useful as a familiar comparison point but not the reference source.

**Technology decisions:**
- Swift Package (not framework/Xcode project)
- **Zero external dependencies** — pure Swift + Apple system frameworks only
- CryptoKit — hashing (SHA-256, SHA-512, SHA-1), HMAC, AES-GCM
- secp256k1 — pure Swift implementation (same approach as ts-sdk and go-sdk; NOT wrapping a C library)
- RIPEMD-160 — vendored pure-Swift implementation
- CommonCrypto — PBKDF2, AES-CBC (for ECIES compatibility)

**Architecture:** Declarative SDK (what things *are*) — the wallet app is the imperative layer (what to *do*). This matches the ts-sdk's design: primitives → script → transaction → wallet.

---

## Package Structure

```
bsv-sdk/
├── Package.swift
├── Sources/
│   └── BSV/
│       ├── Primitives/
│       ├── Script/
│       │   └── Interpreter/
│       │       └── Operations/
│       ├── Transaction/
│       └── Network/
└── Tests/
    └── BSVTests/
        ├── Primitives/
        ├── Script/
        ├── Transaction/
        ├── Network/
        └── Conformance/
            └── Vectors/          ← JSON vectors from go-sdk/ts-sdk
```

**Dependencies (Package.swift):** None. Pure Swift + Apple system frameworks (CryptoKit, CommonCrypto).

---

## Phase 1: Foundation (Hashing + Encoding) (#2)

No secp256k1 dependency. Testable immediately with known vectors.

| Type | File | Notes |
|------|------|-------|
| `Digest` | `Primitives/Digest.swift` | SHA-256, SHA-256d, SHA-512, SHA-1, RIPEMD-160, Hash160, HMAC-SHA256/512, PBKDF2 |
| `Base58` | `Primitives/Base58.swift` | Encode, decode, checkEncode, checkDecode |
| `VarInt` | `Transaction/VarInt.swift` | Variable-length integer (used by Script and Transaction) |
| `Data+Hex` | `Extensions/Data+Hex.swift` | Hex encode/decode utility |

**Reference:** ts-sdk `src/primitives/Hash.ts`, go-sdk `primitives/hash/`, py-sdk `hash.py`, `base58.py`

**CryptoKit note:** PBKDF2 isn't in CryptoKit. Use `CommonCrypto.CCKeyDerivationPBKDF` (available on all Apple platforms).

**Verify:** Test against NIST hash vectors and Bitcoin-specific vectors (Hash160 of known public keys → known addresses).

---

## Phase 2: Keys and Signatures (#3)

Pure-Swift secp256k1 implementation + key management. Zero external dependencies.

| Type | File | Notes |
|------|------|-------|
| `Field` | `Primitives/Field.swift` | Modular arithmetic over secp256k1 prime field (~1,300 lines in go-sdk) |
| `Point` | `Primitives/Point.swift` | Elliptic curve point operations: add, double, scalar multiply |
| `Curve` | `Primitives/Curve.swift` | secp256k1 constants: p, N, G, HALF_N |
| `ECDSA` | `Primitives/ECDSA.swift` | RFC 6979 deterministic signing, verify, recover |
| `Schnorr` | `Primitives/Schnorr.swift` | Schnorr signature scheme |
| `Signature` | `Primitives/Signature.swift` | DER serialise/parse, low-S normalisation, r/s as Data |
| `PrivateKey` | `Primitives/PrivateKey.swift` | Generate, fromBytes/Hex/WIF, sign, ECDH |
| `PublicKey` | `Primitives/PublicKey.swift` | Derive from private, compressed/uncompressed, hash160, address |

**Reference:** go-sdk `primitives/ec/` (field.go, ec.go ~2,300 lines), ts-sdk `src/primitives/` (BigNumber.ts, Point.ts, Curve.ts, ECDSA.ts)

**What we implement (everything):** Field arithmetic (mod p), point arithmetic, ECDSA with RFC 6979, Schnorr, key recovery, ECDH, DER encoding (BIP-66), WIF encode/decode, address generation.

**Verify:** BRC-42 test vectors from go-sdk (`primitives/ec/testdata/BRC42.*.vectors.json`). ECDSA test vectors. Cross-check key derivation and addresses against all three reference SDKs.

---

## Phase 3: Script Layer (#4)

Parse, construct, and classify Bitcoin scripts.

| Type | File | Notes |
|------|------|-------|
| `Opcodes` | `Script/Opcodes.swift` | All 256 opcodes as `static let OP_X: UInt8` |
| `ScriptChunk` | `Script/ScriptChunk.swift` | Opcode + optional data, binary serialisation |
| `Script` | `Script/Script.swift` | Parse/serialise, type predicates (isP2PKH, isOpReturn, etc.), template constructors |
| `ScriptBuilder` | `Script/ScriptBuilder.swift` | Fluent API |

**Reference:** ts-sdk `src/script/Script.ts`, `Spend.ts`; go-sdk `script/script.go`, `script/opcodes.go`; py-sdk `script/script.py`

**Not included:** Interpreter (deferred to Phase 7 — not needed for signing/broadcasting).

**Verify:** P2PKH script construction matches known hex, ASM round-trip, type detection on known scripts from reference SDK tests.

---

## Phase 4: Transactions (Critical Path Complete) (#5)

Build, sign, serialise P2PKH transactions. **This plus Phases 1–3 enables the wallet app.**

| Type | File | Notes |
|------|------|-------|
| `Transaction` | `Transaction/Transaction.swift` | Construct, serialise, deserialise, txid, sighash (BIP-143 + FORKID), sign |
| `TransactionInput` | `Transaction/TransactionInput.swift` | Outpoint, unlocking script, sequence |
| `TransactionOutput` | `Transaction/TransactionOutput.swift` | Satoshis, locking script |
| `Sighash` | `Transaction/Sighash.swift` | Flag constants (ALL, NONE, SINGLE, ANYONECANPAY, FORKID) |
| `P2PKH` | `Transaction/P2PKH.swift` | Unlocking script template (lock + unlock) |
| `UnlockingScriptTemplate` | `Transaction/UnlockingScriptTemplate.swift` | Protocol for custom signing |
| `FeeModel` | `Transaction/FeeModel.swift` | Protocol + `SatoshisPerKilobyte` |

**Reference:** ts-sdk `src/transaction/Transaction.ts`; go-sdk `transaction/transaction.go`; py-sdk `transaction.py`. P2PKH template: ts-sdk `src/script/templates/P2PKH.ts`, go-sdk `transaction/template/p2pkh/`.

**Verify:** Port sighash vectors from go-sdk (`script/interpreter/data/sighash_bip143.json`, `sighash_legacy.json`). Build and sign known transactions, verify txid and raw hex match reference SDK output.

---

## Phase 5: Network + BEEF (#6)

Broadcast transactions, support BEEF/EF formats for ARC.

| Type | File | Notes |
|------|------|-------|
| `ARC` | `Network/ARC.swift` | HTTP broadcaster via URLSession |
| `BroadcastResponse` | `Network/BroadcastResponse.swift` | Response type |
| `MerklePath` | `Transaction/MerklePath.swift` | BRC-74 BUMP parse/serialise/verify |
| `Beef` | `Transaction/Beef.swift` | BRC-62/95/96 serialisation |
| `ChainTracker` | `Transaction/ChainTracker.swift` | Protocol |
| `WhatsOnChainTracker` | `Transaction/WhatsOnChainTracker.swift` | Concrete tracker |

**Reference:** ts-sdk `src/transaction/MerklePath.ts`, `Beef.ts`; go-sdk `transaction/beef.go`, `transaction/merklepath.go`

**Verify:** Parse known BUMP hex, BEEF round-trip, mock ARC requests. Use tx_valid/tx_invalid vectors from go-sdk.

---

## Phase 6: Extended Primitives (#7)

HD keys, mnemonics, encryption, message signing. Needed for wallet key management.

| Type | File | Notes |
|------|------|-------|
| `ExtendedKey` | `Primitives/ExtendedKey.swift` | BIP-32: from seed, path derivation, xprv/xpub. Key tweaking via secp256k1.swift |
| `Mnemonic` | `Primitives/Mnemonic.swift` | BIP-39: generate, validate, toSeed. 2048-word list embedded |
| `ECIES` | `Primitives/ECIES.swift` | Electrum/BIE1 variant. ECDH + AES-128-CBC (via CommonCrypto) |
| `BSM` | `Primitives/BSM.swift` | Bitcoin Signed Messages. Uses `P256K.Recovery` |
| `SymmetricKey` | `Primitives/SymmetricKey.swift` | AES-GCM wrapper around CryptoKit |
| `EncryptedMessage` | `Primitives/EncryptedMessage.swift` | Message metadata |
| `SignedMessage` | `Primitives/SignedMessage.swift` | Message metadata |

**Reference:** go-sdk `compat/bip32/`, `compat/bip39/`, `compat/ecies/`, `compat/bsm/`; py-sdk `hd/`; ts-sdk `src/primitives/SymmetricKey.ts`, `src/messages/`

**ECIES note:** AES-CBC not in CryptoKit. Use `CommonCrypto.CCCrypt` — standard approach on Apple platforms.

**Verify:** BIP-32 test vectors from the BIP itself, BIP-39 vectors, SymmetricKey vectors from go-sdk (`primitives/ec/testdata/SymmetricKey.vectors.json`), cross-SDK ECIES encrypt/decrypt.

---

## Phase 7: Script Interpreter (#8)

Full stack-based execution engine for SPV verification.

| Type | File | Notes |
|------|------|-------|
| `Interpreter` | `Script/Interpreter/Interpreter.swift` | Stack machine (called `Spend` in ts-sdk/py-sdk) |
| `ScriptStack` | `Script/Interpreter/ScriptStack.swift` | Execution stack |
| `ScriptNumber` | `Script/Interpreter/ScriptNumber.swift` | Bitcoin numeric encoding |
| Operations | `Script/Interpreter/Operations/*.swift` | DataPush, StackOps, Arithmetic, Bitwise, Crypto, FlowControl, Splice |

**Reference:** ts-sdk `src/script/Spend.ts`; go-sdk `script/interpreter/`; py-sdk `script/spend.py`

**Verify:** Port Bitcoin Core script test vectors from go-sdk (`script/interpreter/data/script_tests.json`, `tx_valid.json`, `tx_invalid.json`).

---

## Phase 8: Wallet, Auth, Overlay (Future) (#9)

Deferred until core SDK is stable.

- Wallet — wallet orchestration
- Auth — BRC-66/BRC-104 peer authentication and certificates
- Overlay — SHIP/SLAP services
- Shamir secret sharing (Polynomial, KeyShares)

---

## Build Order Summary

```
Phase 1  Hashing + Encoding          ← no external deps
Phase 2  Keys + Signatures           ← Phase 1 + secp256k1.swift
Phase 3  Script Layer                ← Phase 1
Phase 4  Transactions                ← Phases 1-3  ⬅ WALLET APP UNBLOCKED
Phase 5  Network + BEEF              ← Phase 4
Phase 6  Extended Primitives         ← Phases 1-2  (parallel with 3-5)
Phase 7  Script Interpreter          ← Phases 1-4
Phase 8  Wallet/Auth/Overlay         ← all above
```

Phases 3 and 6 are independent — can be parallelised.

## Conformance Test Vectors (from reference SDKs)

Shared JSON vectors to copy into `Tests/BSVTests/Conformance/Vectors/`:

| Vector File | Source | Used In |
|------------|--------|---------|
| `BRC42.private.vectors.json` | go-sdk `primitives/ec/testdata/` | Phase 2 (key derivation) |
| `BRC42.public.vectors.json` | go-sdk `primitives/ec/testdata/` | Phase 2 (key derivation) |
| `SymmetricKey.vectors.json` | go-sdk `primitives/ec/testdata/` | Phase 6 (encryption) |
| `sighash_bip143.json` | go-sdk `script/interpreter/data/` | Phase 4 (transaction signing) |
| `sighash_legacy.json` | go-sdk `script/interpreter/data/` | Phase 4 (transaction signing) |
| `script_tests.json` | go-sdk `script/interpreter/data/` | Phase 7 (interpreter) |
| `tx_valid.json` | go-sdk `script/interpreter/data/` | Phase 7 (interpreter) |
| `tx_invalid.json` | go-sdk `script/interpreter/data/` | Phase 7 (interpreter) |

## Key Reference Files

**ts-sdk** (primary — most complete, zero deps):
- `src/primitives/PrivateKey.ts`, `PublicKey.ts`, `Signature.ts`, `Hash.ts`
- `src/script/Script.ts`, `Spend.ts`, `templates/P2PKH.ts`
- `src/transaction/Transaction.ts`, `MerklePath.ts`, `Beef.ts`

**go-sdk** (strong reference — canonical test vectors):
- `primitives/ec/`, `primitives/ecdsa/`, `primitives/hash/`
- `script/script.go`, `script/interpreter/`
- `transaction/transaction.go`, `transaction/template/p2pkh/`

**py-sdk** (approach reference — also wraps libsecp256k1 via coincurve):
- `keys.py`, `hash.py`, `curve.py`
- `script/script.py`, `script/spend.py`
- `transaction.py`

---

## Issue Hierarchy

- #1 [HLR] Swift BSV SDK
  - #2 [Phase 1] Foundation (Hashing + Encoding)
    - #10 [Task 1.1] Digest (hashing functions)
    - #11 [Task 1.2] Base58 encoding
    - #12 [Task 1.3] VarInt encoding
    - #13 [Task 1.4] Data+Hex extension
    - #14 [Task 1.5] Phase 1 conformance tests
  - #3 [Phase 2] Keys and Signatures
    - #15 [Task 2.1] PrivateKey
    - #16 [Task 2.2] PublicKey
    - #17 [Task 2.3] Signature and DER encoding
    - #18 [Task 2.4] Curve constants
    - #19 [Task 2.5] Phase 2 conformance tests
  - #4 [Phase 3] Script Layer
    - #20 [Task 3.1] Opcodes
    - #21 [Task 3.2] ScriptChunk
    - #22 [Task 3.3] Script
    - #23 [Task 3.4] ScriptBuilder
    - #24 [Task 3.5] Phase 3 tests
  - #5 [Phase 4] Transactions (Critical Path Complete)
    - #25 [Task 4.1] TransactionInput and TransactionOutput
    - #26 [Task 4.2] Sighash
    - #27 [Task 4.3] Transaction
    - #28 [Task 4.4] P2PKH template
    - #29 [Task 4.5] FeeModel
    - #30 [Task 4.6] Phase 4 conformance tests
  - #6 [Phase 5] Network + BEEF
    - #31 [Task 5.1] MerklePath
    - #32 [Task 5.2] BEEF serialisation
    - #33 [Task 5.3] ARC broadcaster
    - #34 [Task 5.4] ChainTracker protocol and WhatsOnChain
    - #35 [Task 5.5] Phase 5 tests
  - #7 [Phase 6] Extended Primitives
    - #36 [Task 6.1] ExtendedKey (BIP-32)
    - #37 [Task 6.2] Mnemonic (BIP-39)
    - #38 [Task 6.3] ECIES encryption
    - #39 [Task 6.4] Bitcoin Signed Messages (BSM)
    - #40 [Task 6.5] SymmetricKey and message types
    - #41 [Task 6.6] Phase 6 conformance tests
  - #8 [Phase 7] Script Interpreter
    - #42 [Task 7.1] ScriptStack and ScriptNumber
    - #43 [Task 7.2] Interpreter core
    - #44 [Task 7.3] Operation modules
    - #45 [Task 7.4] Phase 7 conformance tests
  - #9 [Phase 8] Wallet, Auth, Overlay (Future)
    - #46 [Task 8.1] Wallet orchestration
    - #47 [Task 8.2] Auth (BRC-66/104)
    - #48 [Task 8.3] Overlay (SHIP/SLAP)
    - #49 [Task 8.4] Shamir secret sharing
