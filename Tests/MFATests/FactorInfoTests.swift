//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
@testable import MFA

final class BiometricFactorInfoTests: XCTestCase {
    // MARK: - 1. Initialization and Computed Properties
    
    // Test constants
    let testUUID = "E851C813-A337-4D90-9E11-37E4B3141F3C"
    let testName = "Test-Biometric-Key"
    let testAlgorithm = SigningAlgorithm.sha256
    
    func testFactorInitializationAndProtocolConformance() throws {
        let factor = BiometricFactorInfo(
            id: testUUID,
            name: testName,
            algorithm: testAlgorithm
        )
        
        // Test Stored Properties
        XCTAssertEqual(factor.id, testUUID, "ID should match the initialized value.")
        XCTAssertEqual(factor.name, testName, "Name should match the initialized value.")
        XCTAssertEqual(factor.algorithm, testAlgorithm, "Algorithm should match the initialized value.")
        
        // Test Computed Properties (Requires MFAAttributeInfo to be correct)
        XCTAssertEqual(factor.displayName, MFAAttributeInfo.biometryName, "Display name should be derived from static attribute info.")
        XCTAssertEqual(factor.imageName, MFAAttributeInfo.biometryImage, "Image name should be derived from static attribute info.")
    }
    
    // MARK: - 2. Codable Compliance (Encoding)
    
    func testFactorEncoding() throws {
        let factor = BiometricFactorInfo(
            id: testUUID,
            displayName: "User presence",
            imageName: "hand.tap",
            name: testName,
            algorithm: testAlgorithm
        )
        
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys // For deterministic JSON output
        let data = try encoder.encode(factor)
        
        // The expected JSON string should only contain the properties defined in CodingKeys:
        // id, name, and algorithm. It must NOT contain displayName or imageName.
        let expectedJSON = """
        {"algorithm":"sha256","displayName":"User presence","id":"E851C813-A337-4D90-9E11-37E4B3141F3C","imageName":"hand.tap","name":"Test-Biometric-Key"}
        """
        
        let actualJSON = String(data: data, encoding: .utf8)
        
        XCTAssertEqual(actualJSON, expectedJSON, "Encoded JSON should match expected structure, excluding computed properties.")
    }
    
    // MARK: - 3. Codable Compliance (Decoding)
    
    func testFactorDecoding() throws {
        let jsonString = """
        {
            "id": "E851C813-A337-4D90-9E11-37E4B3141F3C",
            "name": "Test-Biometric-Key",
            "algorithm": "sha256",
            "imageName":"faceid",
            "displayName":"Face ID"
        }
        """
        guard let data = jsonString.data(using: .utf8) else {
            XCTFail("Could not convert JSON string to Data.")
            return
        }
        
        let decoder = JSONDecoder()
        let decodedFactor = try decoder.decode(BiometricFactorInfo.self, from: data)
        
        // Verify all decoded properties match the JSON source
        XCTAssertEqual(decodedFactor.id, testUUID)
        XCTAssertEqual(decodedFactor.name, testName)
        XCTAssertEqual(decodedFactor.algorithm, testAlgorithm)
        
        // Verify Computed properties are still correct after decoding
        XCTAssertEqual(decodedFactor.displayName, MFAAttributeInfo.biometryName)
        XCTAssertEqual(decodedFactor.imageName, MFAAttributeInfo.biometryImage)
    }
}

final class FactorTypeTests: XCTestCase {
    let biometricFactor = BiometricFactorInfo(
        id: "11111111-1111-1111-1111-111111111111",
        name: "Bio-Key",
        algorithm: .sha256
    )
    
    let userPresenceFactor = UserPresenceFactorInfo(
        id: "22222222-2222-2222-2222-222222222222",
        name: "User-Pres-Key",
        algorithm: .sha512
    )
    
    let totpFactor = TOTPFactorInfo(
        with: "TOTP-SECRET",
        digits: 6,
        algorithm: .sha1,
        period: 30
    )

    let hotpFactor = HOTPFactorInfo(with: "HOTP-SECRET",
        digits: 8,
        algorithm: .sha1,
        counter: 0
    )

    // MARK: - 1. ValueType Access Tests
    
    func testValueTypeAccess() {
        
        // .biometric
        let biometricType = FactorType.biometric(biometricFactor)
        XCTAssertEqual(biometricType.valueType.id, biometricFactor.id)
        XCTAssertTrue(biometricType.valueType is BiometricFactorInfo)
        
        // .userPresence
        let userPresenceType = FactorType.userPresence(userPresenceFactor)
        XCTAssertEqual(userPresenceType.valueType.id, userPresenceFactor.id)
        XCTAssertTrue(userPresenceType.valueType is UserPresenceFactorInfo)
    }
    
    // MARK: - 2. Dynamic Member Access Tests (Subscript)
    
    func testDynamicMemberAccess() {
        let factor = FactorType.biometric(biometricFactor)
        
        // Test ID
        XCTAssertEqual(factor.id, biometricFactor.id, "Dynamic member access for ID failed.")
        
        // Test displayName (computed property)
        XCTAssertEqual(factor.displayName, MFAAttributeInfo.biometryName, "Dynamic member access for displayName failed.")
        
        // Test imageName (computed property)
        XCTAssertEqual(factor.imageName, MFAAttributeInfo.biometryImage, "Dynamic member access for imageName failed.")
    }

    // MARK: - 3. Name and Algorithm Tests
    
    func testNameAndAlgorithm() {
        // Case: .biometric (Should return value)
        let bioResult = FactorType.biometric(biometricFactor).nameAndAlgorithm
        XCTAssertNotNil(bioResult)
        XCTAssertEqual(bioResult?.name, biometricFactor.name)
        XCTAssertEqual(bioResult?.algorithm, .sha256)
        
        // Case: .userPresence (Should return value)
        let upResult = FactorType.userPresence(userPresenceFactor).nameAndAlgorithm
        XCTAssertNotNil(upResult)
        XCTAssertEqual(upResult?.name, userPresenceFactor.name)
        XCTAssertEqual(upResult?.algorithm, .sha512)
        
       
    }
    
    // MARK: - 4. Codable Encoding Tests (all 4 cases)
    
    func testCodableEncoding() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        
        // .biometric encoding
        let bioType = FactorType.biometric(biometricFactor)
        let bioData = try encoder.encode(bioType)
        let expectedBioJSON = """
        {"biometric":{"algorithm":"sha256","displayName":"Face ID","id":"11111111-1111-1111-1111-111111111111","imageName":"faceid","name":"Bio-Key"}}
        """
        XCTAssertEqual(String(data: bioData, encoding: .utf8), expectedBioJSON, "Biometric encoding failed.")

        // .userPresence encoding
        let upType = FactorType.userPresence(userPresenceFactor)
        let upData = try encoder.encode(upType)
        let expectedUPJSON = """
        {"userPresence":{"algorithm":"sha512","displayName":"User presence","id":"22222222-2222-2222-2222-222222222222","imageName":"hand.tap","name":"User-Pres-Key"}}
        """
        XCTAssertEqual(String(data: upData, encoding: .utf8), expectedUPJSON, "UserPresence encoding failed.")
        
        // .totp encoding
        let totpType = FactorType.totp(totpFactor)
        let totpData = try encoder.encode(totpType)
        let expectedTOTPJSON = """
        {"totp":{"algorithm":"sha1","digits":6,"id":"\(totpType.id)","period":30,"secret":"TOTP-SECRET"}}
        """
        XCTAssertEqual(String(data: totpData, encoding: .utf8), expectedTOTPJSON, "TOTP encoding failed.")

        // .hotp encoding
        let hotpType = FactorType.hotp(hotpFactor)
        let hotpData = try encoder.encode(hotpType)
        let expectedHOTPJSON = """
        {"hotp":{"algorithm":"sha1","counter":1,"digits":8,"id":"\(hotpType.id)","secret":"HOTP-SECRET"}}
        """
        XCTAssertEqual(String(data: hotpData, encoding: .utf8), expectedHOTPJSON, "HOTP encoding failed.")
    }

    // MARK: - 5. Codable Decoding Tests (all 4 cases + error)
    
    func testCodableDecoding() throws {
        let decoder = JSONDecoder()

        // .biometric decoding
        let bioJSON = "{\"biometric\":{\"algorithm\":\"sha256\",\"displayName\":\"Face ID\",\"id\":\"11111111-1111-1111-1111-111111111111\",\"imageName\":\"faceid\",\"name\":\"Bio-Key\"}}"
        let decodedBio = try decoder.decode(FactorType.self, from: bioJSON.data(using: .utf8)!)
        XCTAssertEqual(decodedBio, .biometric(biometricFactor), "Biometric decoding failed.")

        // .userPresence decoding
        let upJSON = "{\"userPresence\":{\"algorithm\":\"sha512\",\"displayName\":\"User presence\",\"id\":\"22222222-2222-2222-2222-222222222222\",\"imageName\":\"hand.tap\",\"name\":\"User-Pres-Key\"}}"
        let decodedUP = try decoder.decode(FactorType.self, from: upJSON.data(using: .utf8)!)
        XCTAssertEqual(decodedUP, .userPresence(userPresenceFactor), "UserPresence decoding failed.")
        
        // .totp decoding
        let totpJSON = "{\"totp\":{\"id\":\"\(totpFactor.id)\",\"secret\":\"TOTP-SECRET\",\"algorithm\":\"sha1\",\"digits\":6,\"period\":30}}"
        let decodedTOTP = try decoder.decode(FactorType.self, from: totpJSON.data(using: .utf8)!)
        XCTAssertEqual(decodedTOTP, .totp(totpFactor), "TOTP decoding failed.")

        // .hotp decoding
        let hotpJSON = "{\"hotp\":{\"id\":\"\(hotpFactor.id)\",\"secret\":\"HOTP-SECRET\",\"algorithm\":\"sha1\",\"digits\":8,\"counter\":1}}"
        let decodedHOTP = try decoder.decode(FactorType.self, from: hotpJSON.data(using: .utf8)!)
        XCTAssertEqual(decodedHOTP, .hotp(hotpFactor), "HOTP decoding failed.")
    }

    func testCodableDecodingFailure() {
        let decoder = JSONDecoder()
        
        // Test decoding with an empty or non-matching factor type
        let malformedJSON = "{}"
        
        XCTAssertThrowsError(try decoder.decode(FactorType.self, from: malformedJSON.data(using: .utf8)!)) { error in
            // Ensure the specific expected error type is thrown for 100% coverage on the error path
            if case DecodingError.dataCorrupted(let context) = error {
                XCTAssertTrue(context.debugDescription.contains("No valid factor type found."))
            } else {
                XCTFail("Expected a dataCorrupted error, but received \(error)")
            }
        }
    }
    
    func testBiometricFactorName() {
        // Given
        let factor = FactorType.biometric(biometricFactor)
        
        // When
        let keyName = factor.name

        // Then
        XCTAssertEqual(keyName, "Bio-Key")
    }

    func testUserPresenceFactorName() {
        // Given
        let factor = FactorType.userPresence(userPresenceFactor)
        
        // When
        let keyName = factor.name

        // Then
        XCTAssertEqual(keyName, "User-Pres-Key")
    }

    func testTotpFactorNoName() {
        // Given
        let factor = FactorType.totp(totpFactor)
        
        // When
        let keyName = factor.name

        // Then
        XCTAssertNil(keyName)
    }

    func testHotpFactorNoName() {
        // Given
        let factor = FactorType.hotp(hotpFactor)
        
        // When
        let keyName = factor.name

        // Then
        XCTAssertNil(keyName)
    }
}
