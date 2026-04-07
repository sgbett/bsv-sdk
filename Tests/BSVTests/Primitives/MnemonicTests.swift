import XCTest
@testable import BSV

final class MnemonicTests: XCTestCase {

    // MARK: - Wordlist sanity

    func testWordlistHas2048Words() {
        XCTAssertEqual(BIP39Wordlist.english.count, 2048)
    }

    func testWordlistFirstAndLast() {
        XCTAssertEqual(BIP39Wordlist.english.first, "abandon")
        XCTAssertEqual(BIP39Wordlist.english.last, "zoo")
    }

    // MARK: - Entropy to mnemonic

    func testZeroEntropy128() throws {
        let entropy = Data(repeating: 0, count: 16)
        let mnemonic = try Mnemonic.fromEntropy(entropy)
        XCTAssertEqual(
            mnemonic,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
    }

    func testAllSevensEntropy() throws {
        let entropy = Data(repeating: 0x7f, count: 16)
        let mnemonic = try Mnemonic.fromEntropy(entropy)
        XCTAssertEqual(
            mnemonic,
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        )
    }

    func testVectorC0() throws {
        // Trezor vector: 128-bit entropy
        let entropy = Data(hex: "80808080808080808080808080808080")!
        let mnemonic = try Mnemonic.fromEntropy(entropy)
        XCTAssertEqual(
            mnemonic,
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        )
    }

    func testVectorF256() throws {
        // Trezor vector: 256-bit all 0xff
        let entropy = Data(repeating: 0xff, count: 32)
        let mnemonic = try Mnemonic.fromEntropy(entropy)
        XCTAssertEqual(
            mnemonic,
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
        )
    }

    // MARK: - Validation

    func testValidateKnownGood() throws {
        XCTAssertNoThrow(try Mnemonic.validate(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ))
        XCTAssertTrue(Mnemonic.isValid(
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        ))
    }

    func testValidateInvalidChecksum() {
        // Last word changed so checksum is wrong.
        XCTAssertFalse(Mnemonic.isValid(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        ))
    }

    func testValidateInvalidWord() {
        XCTAssertFalse(Mnemonic.isValid(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy"
        ))
    }

    func testValidateBadWordCount() {
        XCTAssertFalse(Mnemonic.isValid("abandon abandon abandon"))
    }

    // MARK: - Seed derivation (Trezor BIP-39 vectors)

    func testSeedAbandon() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let seed = try Mnemonic.toSeed(mnemonic, passphrase: "TREZOR")
        XCTAssertEqual(
            seed.hex,
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        )
    }

    func testSeedLegalWinner() throws {
        let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"
        let seed = try Mnemonic.toSeed(mnemonic, passphrase: "TREZOR")
        XCTAssertEqual(
            seed.hex,
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        )
    }

    func testSeedLetterAdvice() throws {
        let mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        let seed = try Mnemonic.toSeed(mnemonic, passphrase: "TREZOR")
        XCTAssertEqual(
            seed.hex,
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"
        )
    }

    func testSeedAllZooVote() throws {
        let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
        let seed = try Mnemonic.toSeed(mnemonic, passphrase: "TREZOR")
        XCTAssertEqual(
            seed.hex,
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"
        )
    }

    // MARK: - Generation

    func testGenerate128() throws {
        let mnemonic = try Mnemonic.generate(strength: 128)
        let words = mnemonic.split(separator: " ")
        XCTAssertEqual(words.count, 12)
        XCTAssertTrue(Mnemonic.isValid(mnemonic))
    }

    func testGenerate256() throws {
        let mnemonic = try Mnemonic.generate(strength: 256)
        let words = mnemonic.split(separator: " ")
        XCTAssertEqual(words.count, 24)
        XCTAssertTrue(Mnemonic.isValid(mnemonic))
    }

    func testGenerateInvalidStrength() {
        XCTAssertThrowsError(try Mnemonic.generate(strength: 100))
    }

    // MARK: - Round-trip entropy

    func testEntropyRoundTrip() throws {
        let original = Data(hex: "00112233445566778899aabbccddeeff")!
        let mnemonic = try Mnemonic.fromEntropy(original)
        let recovered = try Mnemonic.toEntropy(mnemonic)
        XCTAssertEqual(original, recovered)
    }

    // MARK: - Integration with ExtendedKey

    func testMnemonicToHDKey() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let seed = try Mnemonic.toSeed(mnemonic, passphrase: "TREZOR")
        let master = try ExtendedKey.fromSeed(seed)
        // Should produce a valid xprv matching BIP-39 test vector.
        XCTAssertEqual(
            master.serialise(),
            "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        )
    }
}
