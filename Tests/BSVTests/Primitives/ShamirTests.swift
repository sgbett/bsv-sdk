import XCTest
@testable import BSV

final class ShamirTests: XCTestCase {

    // MARK: - Helpers

    private func randomKey() -> PrivateKey {
        PrivateKey.random()!
    }

    // MARK: - Round-trip

    func testRoundTrip3of5() throws {
        let key = randomKey()
        let shares = try key.toKeyShares(threshold: 3, totalShares: 5)
        XCTAssertEqual(shares.points.count, 5)
        XCTAssertEqual(shares.threshold, 3)

        // Use the first 3 shares.
        let subset = KeyShares(
            points: Array(shares.points.prefix(3)),
            threshold: shares.threshold,
            integrity: shares.integrity
        )
        let recovered = try PrivateKey.fromKeyShares(subset)
        XCTAssertEqual(recovered, key)
    }

    func testKnownKeyRoundTrip() throws {
        // A specific, reproducible private key.
        let key = PrivateKey(hex: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")!
        let shares = try key.toKeyShares(threshold: 3, totalShares: 5)
        let recovered = try PrivateKey.fromKeyShares(
            KeyShares(points: Array(shares.points.prefix(3)), threshold: 3, integrity: shares.integrity)
        )
        XCTAssertEqual(recovered, key)
    }

    // MARK: - Threshold enforcement

    func testInsufficientSharesReconstruction() throws {
        let key = randomKey()
        let shares = try key.toKeyShares(threshold: 3, totalShares: 5)

        // Only 2 shares — should throw.
        let subset = KeyShares(
            points: Array(shares.points.prefix(2)),
            threshold: shares.threshold,
            integrity: shares.integrity
        )
        XCTAssertThrowsError(try PrivateKey.fromKeyShares(subset)) { err in
            guard case Shamir.Error.insufficientShares = err else {
                XCTFail("Expected insufficientShares, got \(err)")
                return
            }
        }
    }

    func testReconstructionWithFewerThanThresholdFails() throws {
        // If the caller lies about the number of shares by trimming threshold,
        // the resulting key must differ (Shamir security property) — this is
        // also indirectly checked by integrity-hash mismatch.
        let key = randomKey()
        let shares = try key.toKeyShares(threshold: 3, totalShares: 5)

        // Pretend threshold is 2 using only 2 shares (lying): integrity check fails.
        let subset = KeyShares(
            points: Array(shares.points.prefix(2)),
            threshold: 2,
            integrity: shares.integrity
        )
        XCTAssertThrowsError(try PrivateKey.fromKeyShares(subset)) { err in
            guard case Shamir.Error.integrityHashMismatch = err else {
                XCTFail("Expected integrityHashMismatch, got \(err)")
                return
            }
        }
    }

    // MARK: - Order independence

    func testOrderIndependence() throws {
        let key = randomKey()
        let shares = try key.toKeyShares(threshold: 3, totalShares: 5)

        // Every 3-of-5 subset should reconstruct the same key.
        let indices = [0, 1, 2, 3, 4]
        var tried = 0
        for i in 0..<indices.count {
            for j in (i + 1)..<indices.count {
                for k in (j + 1)..<indices.count {
                    let subset = KeyShares(
                        points: [shares.points[indices[i]], shares.points[indices[j]], shares.points[indices[k]]],
                        threshold: shares.threshold,
                        integrity: shares.integrity
                    )
                    let recovered = try PrivateKey.fromKeyShares(subset)
                    XCTAssertEqual(recovered, key)
                    tried += 1
                }
            }
        }
        XCTAssertEqual(tried, 10) // C(5, 3) = 10
    }

    func testShuffledOrderProducesSameKey() throws {
        let key = randomKey()
        let shares = try key.toKeyShares(threshold: 3, totalShares: 5)
        let first3 = Array(shares.points.prefix(3))
        let reversed = Array(first3.reversed())
        let a = try PrivateKey.fromKeyShares(
            KeyShares(points: first3, threshold: 3, integrity: shares.integrity)
        )
        let b = try PrivateKey.fromKeyShares(
            KeyShares(points: reversed, threshold: 3, integrity: shares.integrity)
        )
        XCTAssertEqual(a, key)
        XCTAssertEqual(b, key)
    }

    // MARK: - Multiple thresholds

    func testMultipleThresholds() throws {
        let configurations: [(threshold: Int, total: Int)] = [
            (2, 3), (3, 5), (5, 7), (10, 15)
        ]
        for (t, n) in configurations {
            let key = randomKey()
            let shares = try key.toKeyShares(threshold: t, totalShares: n)
            XCTAssertEqual(shares.points.count, n)
            XCTAssertEqual(shares.threshold, t)
            let subset = KeyShares(
                points: Array(shares.points.prefix(t)),
                threshold: t,
                integrity: shares.integrity
            )
            let recovered = try PrivateKey.fromKeyShares(subset)
            XCTAssertEqual(recovered, key, "failed for (threshold: \(t), total: \(n))")
        }
    }

    // MARK: - Edge cases: threshold equals total

    func testThresholdEqualsTotal() throws {
        let key = randomKey()
        let shares = try key.toKeyShares(threshold: 4, totalShares: 4)
        let recovered = try PrivateKey.fromKeyShares(shares)
        XCTAssertEqual(recovered, key)
    }

    // MARK: - Invalid parameters

    func testThresholdTooLow() {
        let key = randomKey()
        XCTAssertThrowsError(try key.toKeyShares(threshold: 1, totalShares: 5)) { err in
            XCTAssertEqual(err as? Shamir.Error, .thresholdTooLow)
        }
    }

    func testTotalSharesTooLow() {
        let key = randomKey()
        XCTAssertThrowsError(try key.toKeyShares(threshold: 2, totalShares: 1)) { err in
            XCTAssertEqual(err as? Shamir.Error, .totalSharesTooLow)
        }
    }

    func testThresholdExceedsTotal() {
        let key = randomKey()
        XCTAssertThrowsError(try key.toKeyShares(threshold: 5, totalShares: 3)) { err in
            XCTAssertEqual(err as? Shamir.Error, .thresholdExceedsTotal)
        }
    }

    // MARK: - Duplicate share detection

    func testDuplicateShareDetected() throws {
        let key = randomKey()
        let shares = try key.toKeyShares(threshold: 3, totalShares: 5)
        let dup = KeyShares(
            points: [shares.points[0], shares.points[1], shares.points[1]],
            threshold: 3,
            integrity: shares.integrity
        )
        XCTAssertThrowsError(try PrivateKey.fromKeyShares(dup)) { err in
            XCTAssertEqual(err as? Shamir.Error, .duplicateShare)
        }
    }

    // MARK: - KeyShares serialisation round-trip

    func testBackupFormatRoundTrip() throws {
        let key = randomKey()
        let shares = try key.toKeyShares(threshold: 3, totalShares: 5)
        let backup = shares.toBackupFormat()
        XCTAssertEqual(backup.count, 5)

        for s in backup {
            let parts = s.split(separator: ".")
            XCTAssertEqual(parts.count, 4, "expected x.y.threshold.integrity")
            XCTAssertEqual(String(parts[2]), "3")
            XCTAssertEqual(String(parts[3]), shares.integrity)
        }

        let parsed = try KeyShares.fromBackupFormat(Array(backup.prefix(3)))
        XCTAssertEqual(parsed.threshold, 3)
        XCTAssertEqual(parsed.integrity, shares.integrity)
        XCTAssertEqual(parsed.points.count, 3)

        let recovered = try PrivateKey.fromKeyShares(parsed)
        XCTAssertEqual(recovered, key)
    }

    func testToBackupSharesAndFromBackupShares() throws {
        let key = randomKey()
        let backup = try key.toBackupShares(threshold: 3, totalShares: 5)
        let recovered = try PrivateKey.fromBackupShares(Array(backup.prefix(3)))
        XCTAssertEqual(recovered, key)
    }

    func testBackupFormatRejectsMalformedShare() {
        XCTAssertThrowsError(try KeyShares.fromBackupFormat(["not-a-share"])) { err in
            XCTAssertEqual(err as? Shamir.Error, .invalidShareFormat)
        }
    }

    func testBackupFormatRejectsMismatchedThreshold() throws {
        let key = randomKey()
        let backup = try key.toBackupShares(threshold: 3, totalShares: 5)
        // Tamper with the threshold on the second share.
        var tampered = backup
        let parts = tampered[1].split(separator: ".").map(String.init)
        tampered[1] = "\(parts[0]).\(parts[1]).4.\(parts[3])"

        XCTAssertThrowsError(try KeyShares.fromBackupFormat(Array(tampered.prefix(3)))) { err in
            XCTAssertEqual(err as? Shamir.Error, .thresholdMismatch)
        }
    }

    func testBackupFormatRejectsMismatchedIntegrity() throws {
        let key = randomKey()
        let backup = try key.toBackupShares(threshold: 3, totalShares: 5)
        // Tamper with the integrity on the second share.
        var tampered = backup
        let parts = tampered[1].split(separator: ".").map(String.init)
        tampered[1] = "\(parts[0]).\(parts[1]).\(parts[2]).deadbeef"

        XCTAssertThrowsError(try KeyShares.fromBackupFormat(Array(tampered.prefix(3)))) { err in
            XCTAssertEqual(err as? Shamir.Error, .integrityMismatch)
        }
    }

    // MARK: - Cross-SDK compatibility

    /// Decode a known-good share bundle from the ts-sdk test suite and verify
    /// it can be parsed. The shares themselves come from ts-sdk's
    /// PrivateKey.split.test.ts so the format must be interoperable.
    func testTsSDKShareBundleParses() throws {
        let backup = [
            "45s4vLL2hFvqmxrarvbRT2vZoQYGZGocsmaEksZ64o5M.A7nZrGux15nEsQGNZ1mbfnMKugNnS6SYYEQwfhfbDZG8.3.2f804d43",
            "7aPzkiGZgvU4Jira5PN9Qf9o7FEg6uwy1zcxd17NBhh3.CCt7NH1sPFgceb6phTRkfviim2WvmUycJCQd2BxauxP9.3.2f804d43",
            "9GaS2Tw5sXqqbuigdjwGPwPsQuEFqzqUXo5MAQhdK3es.8MLh2wyE3huyq6hiBXjSkJRucgyKh4jVY6ESq5jNtXRE.3.2f804d43",
            "GBmoNRbsMVsLmEK5A6G28fktUNonZkn9mDrJJ58FXgsf.HDBRkzVUCtZ38ApEu36fvZtDoDSQTv3TWmbnxwwR7kto.3.2f804d43",
            "2gHebXBgPd7daZbsj6w9TPDta3vQzqvbkLtJG596rdN1.E7ZaHyyHNDCwR6qxZvKkPPWWXzFCiKQFentJtvSSH5Bi.3.2f804d43"
        ]
        let shares = try KeyShares.fromBackupFormat(backup)
        XCTAssertEqual(shares.threshold, 3)
        XCTAssertEqual(shares.integrity, "2f804d43")
        XCTAssertEqual(shares.points.count, 5)

        // Reconstruct using any 3 of the 5 — expect a valid private key whose
        // hash160 prefix matches the integrity tag.
        let subset = KeyShares(
            points: Array(shares.points.prefix(3)),
            threshold: 3,
            integrity: "2f804d43"
        )
        let key = try PrivateKey.fromKeyShares(subset)

        // Reconstructing from a different 3-subset must yield the same key.
        let subset2 = KeyShares(
            points: Array(shares.points.suffix(3)),
            threshold: 3,
            integrity: "2f804d43"
        )
        let key2 = try PrivateKey.fromKeyShares(subset2)
        XCTAssertEqual(key, key2)
    }

    // MARK: - Serialisation of points

    func testPointInFiniteFieldToStringRoundTrip() throws {
        var xBytes = Data(count: 32); xBytes[30] = 0x01; xBytes[31] = 0x23
        var yBytes = Data(count: 32); yBytes[30] = 0xAB; yBytes[31] = 0xCD
        let point = PointInFiniteField(x: xBytes, y: yBytes)
        let encoded = point.toString()
        let decoded = try PointInFiniteField.fromString(encoded)
        XCTAssertEqual(decoded.x, point.x)
        XCTAssertEqual(decoded.y, point.y)
    }

    // MARK: - FieldP sanity checks

    func testFieldPAddSubInverseIdentity() {
        let a = Data(hex: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")!
        let b = Data(hex: "123456789abcdef0fedcba9876543210cafebabedeadbeef0badf00dfeedface")!

        // (a + b) - b == a (mod P)
        let sum = FieldP.add(a, b)
        let recovered = FieldP.sub(sum, b)
        XCTAssertEqual(recovered, a)

        // a * a^(-1) == 1
        let inv = FieldP.inverse(a)
        let product = FieldP.mul(a, inv)
        var one = Data(count: 32); one[31] = 1
        XCTAssertEqual(product, one)
    }
}
