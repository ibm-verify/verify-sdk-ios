//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
import CryptoKit
@testable import MFA

final class SigningAlgorithmTests: XCTestCase {

    /// Tests all valid aliases map to the correct enum case.
    func testValidAliases() {
        let testCases: [(input: String, expected: SigningAlgorithm)] = [
            ("SHA1", .sha1), ("HMACSHA1", .sha1), ("RSASHA1", .sha1), ("SHA1WITHRSA", .sha1),
            ("SHA256", .sha256), ("HMACSHA256", .sha256), ("RSASHA256", .sha256), ("SHA256WITHRSA", .sha256),
            ("SHA384", .sha384), ("HMACSHA384", .sha384), ("RSASHA384", .sha384), ("SHA384WITHRSA", .sha384),
            ("SHA512", .sha512), ("HMACSHA512", .sha512), ("RSASHA512", .sha512), ("SHA512WITHRSA", .sha512)
        ]

        for testCase in testCases {
            let result = SigningAlgorithm(from: testCase.input)
            XCTAssertEqual(result, testCase.expected, "Expected \(testCase.input) to map to \(testCase.expected)")
        }
    }

    /// Tests that alias matching is case-insensitive.
    func testCaseInsensitivity() {
        let result = SigningAlgorithm(from: "sha256")
        XCTAssertEqual(result, .sha256)
    }

    /// Tests that an invalid alias returns nil.
    func testInvalidAliasReturnsNil() {
        let result = SigningAlgorithm(from: "INVALID")
        XCTAssertNil(result, "Expected nil for unrecognized alias")
    }

    /// Tests that each enum case returns the correct CryptoKit hash function.
    func testHashFunctionMapping() {
        XCTAssertTrue(SigningAlgorithm.sha1.hashFunction == Insecure.SHA1.self)
        XCTAssertTrue(SigningAlgorithm.sha256.hashFunction == SHA256.self)
        XCTAssertTrue(SigningAlgorithm.sha384.hashFunction == SHA384.self)
        XCTAssertTrue(SigningAlgorithm.sha512.hashFunction == SHA512.self)
    }
}
