import XCTest
@testable import BSV

final class ExtendedKeyTests: XCTestCase {

    // MARK: - BIP-32 Test Vector 1
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1

    func testVector1Master() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed)

        XCTAssertEqual(
            master.serialise(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        )
        XCTAssertEqual(
            master.neuter().serialise(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        )
    }

    func testVector1Chain0H() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed)
        let child = try master.deriveChild(index: 0x80000000)

        XCTAssertEqual(
            child.serialise(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        )
        XCTAssertEqual(
            child.neuter().serialise(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        )
    }

    func testVector1Chain0H1() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let child = try ExtendedKey.fromSeed(seed)
            .derivePath("m/0'/1")

        XCTAssertEqual(
            child.serialise(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        )
        XCTAssertEqual(
            child.neuter().serialise(),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        )
    }

    func testVector1FullPath() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let child = try ExtendedKey.fromSeed(seed)
            .derivePath("m/0'/1/2'/2/1000000000")

        XCTAssertEqual(
            child.serialise(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
        )
        XCTAssertEqual(
            child.neuter().serialise(),
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        )
    }

    // MARK: - BIP-32 Test Vector 2

    func testVector2Master() throws {
        let seed = Data(hex: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")!
        let master = try ExtendedKey.fromSeed(seed)

        XCTAssertEqual(
            master.serialise(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        )
        XCTAssertEqual(
            master.neuter().serialise(),
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        )
    }

    func testVector2FullPath() throws {
        let seed = Data(hex: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")!
        let child = try ExtendedKey.fromSeed(seed)
            .derivePath("m/0/2147483647'/1/2147483646'/2")

        XCTAssertEqual(
            child.serialise(),
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
        )
        XCTAssertEqual(
            child.neuter().serialise(),
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        )
    }

    // MARK: - BIP-32 Test Vector 3 (leading zeros)

    func testVector3Master() throws {
        let seed = Data(hex: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")!
        let master = try ExtendedKey.fromSeed(seed)

        XCTAssertEqual(
            master.serialise(),
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
        )
        XCTAssertEqual(
            master.neuter().serialise(),
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
        )
    }

    func testVector3Chain0H() throws {
        let seed = Data(hex: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")!
        let child = try ExtendedKey.fromSeed(seed).derivePath("m/0'")

        XCTAssertEqual(
            child.serialise(),
            "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
        )
        XCTAssertEqual(
            child.neuter().serialise(),
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
        )
    }

    // MARK: - Round-trip serialisation

    func testSerialiseDeserialisePrivate() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed)
        let serialised = master.serialise()
        let restored = try ExtendedKey.fromString(serialised)

        XCTAssertEqual(master.key, restored.key)
        XCTAssertEqual(master.chainCode, restored.chainCode)
        XCTAssertEqual(master.depth, restored.depth)
        XCTAssertTrue(restored.isPrivate)
    }

    func testSerialiseDeserialisePublic() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed)
        let pub = master.neuter()
        let serialised = pub.serialise()
        let restored = try ExtendedKey.fromString(serialised)

        XCTAssertEqual(pub.key, restored.key)
        XCTAssertEqual(pub.chainCode, restored.chainCode)
        XCTAssertFalse(restored.isPrivate)
    }

    // MARK: - Public key derivation

    func testPublicChildDerivationMatchesPrivate() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed)

        // Derive non-hardened child from private key, then neuter.
        let privChild = try master.deriveChild(index: 0).neuter()

        // Derive the same child from the public key.
        let pubMaster = master.neuter()
        let pubChild = try pubMaster.deriveChild(index: 0)

        XCTAssertEqual(privChild.key, pubChild.key)
        XCTAssertEqual(privChild.chainCode, pubChild.chainCode)
    }

    // MARK: - Error cases

    func testHardenedFromPublicThrows() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed).neuter()

        XCTAssertThrowsError(try master.deriveChild(index: 0x80000000)) { error in
            XCTAssertEqual(error as? ExtendedKey.Error, .cannotDeriveHardenedFromPublic)
        }
    }

    func testInvalidSeedLength() {
        let shortSeed = Data(count: 10)
        XCTAssertThrowsError(try ExtendedKey.fromSeed(shortSeed)) { error in
            XCTAssertEqual(error as? ExtendedKey.Error, .invalidSeedLength)
        }
    }

    // MARK: - Path derivation

    func testDerivePath() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed)

        // Manual step-by-step derivation.
        let manual = try master
            .deriveChild(index: 0x80000000)
            .deriveChild(index: 1)
            .deriveChild(index: 0x80000002)

        // Path-based derivation.
        let fromPath = try master.derivePath("m/0'/1/2'")

        XCTAssertEqual(manual.serialise(), fromPath.serialise())
    }

    // MARK: - Key extraction

    func testPrivateKeyExtraction() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed)

        let privKey = master.privateKey()
        XCTAssertNotNil(privKey)
        XCTAssertEqual(privKey?.data, master.key)
    }

    func testPublicKeyExtraction() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let master = try ExtendedKey.fromSeed(seed)

        let pubKey = master.publicKey()
        XCTAssertNotNil(pubKey)
        XCTAssertEqual(pubKey?.toCompressed(), master.pubKeyBytes)
    }

    func testNeuterHasNoPrivateKey() throws {
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")!
        let pub = try ExtendedKey.fromSeed(seed).neuter()
        XCTAssertNil(pub.privateKey())
    }
}
