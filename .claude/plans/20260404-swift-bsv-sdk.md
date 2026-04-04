# Swift BSV SDK — Implementation Plan

## Context

We're building a Swift BSV SDK at `/opt/xcode/bsv-sdk` to support development of a native macOS wallet application. The SDK joins the official BSV SDK family alongside [ts-sdk](https://github.com/bsv-blockchain/ts-sdk), [go-sdk](https://github.com/bsv-blockchain/go-sdk), and [py-sdk](https://github.com/bsv-blockchain/py-sdk).

**Reference implementations** (primary sources, at `/opt/ruby/bsv-reference-sdks/`):
- **ts-sdk** — zero dependencies, all crypto implemented from scratch (BigNumber, Point, ECDSA, Hash, AES-GCM)
- **go-sdk** — pure Go secp256k1 implementation, stdlib hashing, `golang.org/x/crypto` for RIPEMD-160
- **py-sdk** — uses `coincurve` (libsecp256k1 wrapper) + `pycryptodomex` for crypto

The Ruby SDK at `/opt/ruby/bsv-ruby-sdk` is a sibling implementation, useful as a familiar comparison point but not the reference source.

**Technology decisions:**
- Swift Package (not framework/Xcode project)
- CryptoKit — hashing (SHA-256, SHA-512, SHA-1), HMAC, AES-GCM
- secp256k1.swift (21-DOT-DEV) — ECDSA, Schnorr, ECDH, key recovery, tweaking (same approach as py-sdk using coincurve)
- RIPEMD-160 — small vendored implementation or lightweight package
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

**Dependencies (Package.swift):**
```swift
.package(url: "https://github.com/21-DOT-DEV/swift-secp256k1.git", from: "0.23.0")
```

Plus a RIPEMD-160 implementation (evaluate vendoring ~150 lines vs a package).

---

## Phase 1: Foundation (Hashing + Encoding)

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

## Phase 2: Keys and Signatures

Core key management. Wraps secp256k1.swift.

| Type | File | Notes |
|------|------|-------|
| `PrivateKey` | `Primitives/PrivateKey.swift` | Generate, fromBytes/Hex/WIF, sign. Wraps `P256K.Signing.PrivateKey` |
| `PublicKey` | `Primitives/PublicKey.swift` | Derive from private, compressed/uncompressed, hash160, address |
| `Signature` | `Primitives/Signature.swift` | DER serialise/parse, low-S normalisation, r/s as Data |
| `Curve` | `Primitives/Curve.swift` | Constants only: N, HALF_N, G |

**Reference:** ts-sdk `src/primitives/PrivateKey.ts`, `PublicKey.ts`, `Signature.ts`; go-sdk `primitives/ec/`; py-sdk `keys.py`

**What secp256k1.swift handles for us:** RFC 6979 nonces, raw ECDSA math, Schnorr sign/verify, key recovery. (Same delegation model as py-sdk's use of coincurve.)

**What we implement:** DER encoding/decoding (BIP-66 strict), WIF encode/decode (Base58Check), address generation (Hash160 + Base58Check), low-S check.

**Verify:** Use BRC-42 test vectors from go-sdk (`primitives/ec/testdata/BRC42.*.vectors.json`). Cross-check key derivation and addresses against all three reference SDKs.

---

## Phase 3: Script Layer

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

## Phase 4: Transactions (Critical Path Complete)

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

## Phase 5: Network + BEEF

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

## Phase 6: Extended Primitives

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

## Phase 7: Script Interpreter

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

## Phase 8: Wallet, Auth, Overlay (Future)

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
