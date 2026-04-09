import XCTest
@testable import BSV

final class ProtoWalletTests: XCTestCase {

    private func makeProtocol() -> WalletProtocol {
        WalletProtocol(securityLevel: .app, protocol: "wallet tests")
    }

    // MARK: - Identity

    func testGetIdentityPublicKey() async throws {
        let root = PrivateKey.random()!
        let wallet = ProtoWallet(rootKey: root)

        let identity = try await wallet.getPublicKey(args: GetPublicKeyArgs(identityKey: true))
        XCTAssertEqual(identity.publicKey, PublicKey.fromPrivateKey(root))
    }

    func testGetPublicKeyRequiresEncryptionArgs() async {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        do {
            _ = try await wallet.getPublicKey(args: GetPublicKeyArgs(identityKey: false))
            XCTFail("expected invalidParameter")
        } catch let err as WalletError {
            if case .invalidParameter = err { } else { XCTFail("unexpected error: \(err)") }
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    // MARK: - Encryption round-trip

    func testEncryptDecryptRoundTrip() async throws {
        let alice = ProtoWallet(rootKey: PrivateKey.random()!)
        let bob = ProtoWallet(rootKey: PrivateKey.random()!)

        let aliceIdentity = (try await alice.getPublicKey(args: GetPublicKeyArgs(identityKey: true))).publicKey
        let bobIdentity = (try await bob.getPublicKey(args: GetPublicKeyArgs(identityKey: true))).publicKey

        let proto = makeProtocol()
        let aliceToBobArgs = WalletEncryptionArgs(
            protocolID: proto,
            keyID: "message-1",
            counterparty: .publicKey(bobIdentity)
        )
        let bobToAliceArgs = WalletEncryptionArgs(
            protocolID: proto,
            keyID: "message-1",
            counterparty: .publicKey(aliceIdentity)
        )

        let plaintext = "BRC-100 round-trip".data(using: .utf8)!
        let ciphertext = try await alice.encrypt(
            args: WalletEncryptArgs(encryption: aliceToBobArgs, plaintext: plaintext)
        ).ciphertext

        let recovered = try await bob.decrypt(
            args: WalletDecryptArgs(encryption: bobToAliceArgs, ciphertext: ciphertext)
        ).plaintext

        XCTAssertEqual(recovered, plaintext)
    }

    func testEncryptDecryptSelf() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let args = WalletEncryptionArgs(protocolID: makeProtocol(), keyID: "self", counterparty: .`self`)

        let plaintext = Data([0x01, 0x02, 0x03, 0xff])
        let ciphertext = try await wallet.encrypt(
            args: WalletEncryptArgs(encryption: args, plaintext: plaintext)
        ).ciphertext
        let recovered = try await wallet.decrypt(
            args: WalletDecryptArgs(encryption: args, ciphertext: ciphertext)
        ).plaintext
        XCTAssertEqual(recovered, plaintext)
    }

    // MARK: - HMAC

    func testHmacCreateVerify() async throws {
        let alice = ProtoWallet(rootKey: PrivateKey.random()!)
        let bob = ProtoWallet(rootKey: PrivateKey.random()!)

        let aliceIdentity = (try await alice.getPublicKey(args: GetPublicKeyArgs(identityKey: true))).publicKey
        let bobIdentity = (try await bob.getPublicKey(args: GetPublicKeyArgs(identityKey: true))).publicKey

        let proto = makeProtocol()
        let payload = "hello".data(using: .utf8)!

        let mac = try await alice.createHmac(args: CreateHmacArgs(
            encryption: WalletEncryptionArgs(
                protocolID: proto,
                keyID: "hmac-1",
                counterparty: .publicKey(bobIdentity)
            ),
            data: payload
        )).hmac

        let ok = try await bob.verifyHmac(args: VerifyHmacArgs(
            encryption: WalletEncryptionArgs(
                protocolID: proto,
                keyID: "hmac-1",
                counterparty: .publicKey(aliceIdentity)
            ),
            data: payload,
            hmac: mac
        )).valid
        XCTAssertTrue(ok)
    }

    func testVerifyHmacFailsForTamperedData() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let args = WalletEncryptionArgs(protocolID: makeProtocol(), keyID: "h", counterparty: .`self`)

        let mac = try await wallet.createHmac(args: CreateHmacArgs(
            encryption: args,
            data: "original".data(using: .utf8)!
        )).hmac

        do {
            _ = try await wallet.verifyHmac(args: VerifyHmacArgs(
                encryption: args,
                data: "tampered".data(using: .utf8)!,
                hmac: mac
            ))
            XCTFail("expected invalidHmac")
        } catch WalletError.invalidHmac {
            // expected
        }
    }

    // MARK: - Signature

    func testSignatureCreateVerifyToSelf() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let enc = WalletEncryptionArgs(protocolID: makeProtocol(), keyID: "sig-1", counterparty: .`self`)

        let message = "sign me".data(using: .utf8)!
        let sig = try await wallet.createSignature(args: CreateSignatureArgs(
            encryption: enc, data: message
        )).signature

        let ok = try await wallet.verifySignature(args: VerifySignatureArgs(
            encryption: enc,
            signature: sig,
            data: message,
            forSelf: true
        )).valid
        XCTAssertTrue(ok)
    }

    func testSignatureCreateToCounterpartyVerify() async throws {
        let alice = ProtoWallet(rootKey: PrivateKey.random()!)
        let bob = ProtoWallet(rootKey: PrivateKey.random()!)

        let aliceIdentity = (try await alice.getPublicKey(args: GetPublicKeyArgs(identityKey: true))).publicKey
        let bobIdentity = (try await bob.getPublicKey(args: GetPublicKeyArgs(identityKey: true))).publicKey

        let proto = makeProtocol()
        let message = "authenticated".data(using: .utf8)!

        // Alice signs a message intended for Bob.
        let sig = try await alice.createSignature(args: CreateSignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: proto,
                keyID: "authkey",
                counterparty: .publicKey(bobIdentity)
            ),
            data: message
        )).signature

        // Bob verifies the signature using Alice as the counterparty.
        let ok = try await bob.verifySignature(args: VerifySignatureArgs(
            encryption: WalletEncryptionArgs(
                protocolID: proto,
                keyID: "authkey",
                counterparty: .publicKey(aliceIdentity)
            ),
            signature: sig,
            data: message,
            forSelf: false
        )).valid
        XCTAssertTrue(ok)
    }

    func testSignatureRequiresOneOfDataOrHash() async {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let enc = WalletEncryptionArgs(protocolID: makeProtocol(), keyID: "sig", counterparty: .`self`)

        // Neither provided.
        do {
            _ = try await wallet.createSignature(args: CreateSignatureArgs(encryption: enc))
            XCTFail("expected invalidParameter")
        } catch WalletError.invalidParameter {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        // Both provided.
        do {
            _ = try await wallet.createSignature(args: CreateSignatureArgs(
                encryption: enc,
                data: Data(repeating: 0x01, count: 10),
                hashToDirectlySign: Data(repeating: 0x02, count: 32)
            ))
            XCTFail("expected invalidParameter")
        } catch WalletError.invalidParameter {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    // MARK: - Linkage

    func testRevealCounterpartyKeyLinkageNotSupported() async {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let args = RevealCounterpartyKeyLinkageArgs(
            counterparty: PublicKey.fromPrivateKey(PrivateKey.random()!),
            verifier: PublicKey.fromPrivateKey(PrivateKey.random()!)
        )
        do {
            _ = try await wallet.revealCounterpartyKeyLinkage(args: args)
            XCTFail("expected unsupportedAction")
        } catch WalletError.unsupportedAction {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testRevealSpecificKeyLinkageRoundTrip() async throws {
        let wallet = ProtoWallet(rootKey: PrivateKey.random()!)
        let counterparty = PublicKey.fromPrivateKey(PrivateKey.random()!)
        let verifier = PublicKey.fromPrivateKey(PrivateKey.random()!)

        let result = try await wallet.revealSpecificKeyLinkage(args: RevealSpecificKeyLinkageArgs(
            counterparty: .publicKey(counterparty),
            verifier: verifier,
            protocolID: makeProtocol(),
            keyID: "linkage-1"
        ))
        XCTAssertEqual(result.verifier, verifier)
        XCTAssertEqual(result.keyID, "linkage-1")
        XCTAssertFalse(result.encryptedLinkage.isEmpty)
    }
}
