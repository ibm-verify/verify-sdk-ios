//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import XCTest
@testable import FIDO2

class PublicKeyCredentialTest: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // MARK: PublicKeyCredentialRpEntity
    
    func testCreatePublicKeyCredentialRpEntityMin() throws {
        // Given
        let result = PublicKeyCredentialRpEntity(name: "mydomain.com")
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreatePublicKeyCredentialRpEntity() throws {
        // Given
        let result = PublicKeyCredentialRpEntity(id: "mydomain.com", name: "mydomain.com")
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreatePublicKeyCredentialRpEntityEx() throws {
        // Given
        let result = PublicKeyCredentialRpEntity(id: "mydomain.com", name: "mydomain.com", icon: "https://icon.org")
        
        // Then
        XCTAssertNotNil(result)
    }
    
    // MARK: CreatePublicKeyCredentialUserEntity

    func testCreatePublicKeyCredentialUserEntity() throws {
        // Given
        let result = PublicKeyCredentialUserEntity(id: "JohnD", displayName: "John Doe", name: "John Doe")
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreatePublicKeyCredentialUserEntityEx() throws {
        // Given
        let result = PublicKeyCredentialUserEntity(id: "JohnD", displayName: "John Doe", name: "John Doe", icon: "https://emojipedia-us.s3.dualstack.us-west-1.amazonaws.com/thumbs/120/apple/285/grinning-face_1f600.png")
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testEncodePublicKeyCredentialUserEntity() throws {
        // Given
        let result = PublicKeyCredentialUserEntity(id: "JohnD", displayName: "John Doe", name: "John Doe", icon: "icon.org")
        
        let expected = """
        {
          "id" : "JohnD",
          "icon" : "icon.org",
          "displayName" : "John Doe",
          "name" : "John Doe"
        }
        """
        
        do {
            // When
            let encoder = JSONEncoder()
            encoder.outputFormatting = .prettyPrinted
            let data = try encoder.encode(result)
            let json = String(decoding: data, as: UTF8.self)
            
            // Then
            XCTAssertEqual(expected, json)
        }
        catch let error {
            print("Encoding error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    // MARK: AuthenticatorSelectionCriteria
    
    func testDecodeAuthenticatorSelectionCriteria() throws {
        // Given
        let json = """
        {
            "requireResidentKey": false,
            "authenticatorAttachment": "platform",
            "userVerification": "discouraged"
        }
        """
        
        do {
            // When
            guard let data = json.data(using: .utf8) else {
                XCTFail()
                return
            }
            
            let decoder = JSONDecoder()
            let result = try decoder.decode(AuthenticatorSelectionCriteria.self, from: data)
            
            // Then
            XCTAssertNotNil(result)
        }
        catch let error {
            print("Decoding error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    func testDecodeAuthenticatorSelectionCriteriaDefaults() throws {
        // Given
        let json = """
        {
        }
        """
        
        do {
            // When
            guard let data = json.data(using: .utf8) else {
                XCTFail()
                return
            }
            
            let decoder = JSONDecoder()
            let result = try decoder.decode(AuthenticatorSelectionCriteria.self, from: data)
            
            // Then
            XCTAssertNotNil(result)
        }
        catch let error {
            print("Decoding error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    func testDecodeAuthenticatorSelectionCriteriaPartial() throws {
        // Given
        let json = """
        {
            "requireResidentKey": true
        }
        """
        
        let expected = AuthenticatorSelectionCriteria()
        
        do {
            // When
            guard let data = json.data(using: .utf8) else {
                XCTFail()
                return
            }
            
            let decoder = JSONDecoder()
            let result = try decoder.decode(AuthenticatorSelectionCriteria.self, from: data)
            
            // Then
            XCTAssertNotNil(result)
            XCTAssertNotEqual(result.requireResidentKey, expected.requireResidentKey)
        }
        catch let error {
            print("Decoding error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    func testCreateAuthenticatorSelectionCriteria() throws {
        // Given
        let result = AuthenticatorSelectionCriteria()
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreateAuthenticatorSelectionCriteriaEx() throws {
        // Given
        let result = AuthenticatorSelectionCriteria(authenticatorAttachment: .platform, requireResidentKey: false, userVerification: .required)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    // MARK: PublicKeyCredentialParameters
    
    func testCreatePublicKeyCredentialParameters() throws {
        // Given
        let result = PublicKeyCredentialParameters(alg: .es256)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    // MARK: AuthenticatorTransport
    
    func testCreateAuthenticatorTransport() throws {
        // Given
        let result = AuthenticatorTransport(rawValue: "internal")
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testAuthenticatorTransportInvalid() throws {
        // Given
        let result = AuthenticatorTransport(rawValue: "http")
        
        // Then
        XCTAssertNil(result)
    }
    
    
    // MARK: PublicKeyCredentialDescriptor
    
    func testCreatePublicKeyCredentialDescriptor() throws {
        // Given
        let result = PublicKeyCredentialDescriptor(id: UUID().uuidString)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreatePublicKeyCredentialDescriptorEx() throws {
        // Given
        let transports = [AuthenticatorTransport(rawValue: "internal")!,
                          AuthenticatorTransport(rawValue: "nfc")!]
        
        // When
        let result = PublicKeyCredentialDescriptor(id: UUID().uuidString, transports: transports)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    // MARK: PublicKeyCredentialType
    
    func testCreatePublicKeyCredentialType() throws {
        // Given
        let result = PublicKeyCredentialType(rawValue: "public-key")
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testPublicKeyCredentialTypeInvalid() throws {
        // Given
        let result = PublicKeyCredentialType(rawValue: "http")
        
        // Then
        XCTAssertNil(result)
    }
    
    // MARK: COSEAlgorithmIdentifier
    
    func testCreateCOSEAlgorithmIdentifierParse() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -35)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCOSEAlgorithmIdentifierParseInvalid() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -99)
        
        // Then
        XCTAssertNil(result)
    }
    
    func testCOSEAlgorithmIdentifierParseRS1() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -65535)
        
        // Then
        XCTAssertEqual(result, COSEAlgorithmIdentifier.rs1)
    }
    
    func testCOSEAlgorithmIdentifierParseRS256() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -257)
        
        // Then
        XCTAssertEqual(result, COSEAlgorithmIdentifier.rs256)
    }
    
    func testCOSEAlgorithmIdentifierParseRS384() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -258)
        
        // Then
        XCTAssertEqual(result, COSEAlgorithmIdentifier.rs384)
    }
    
    func testCOSEAlgorithmIdentifierParseRS5121() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -259)
        
        // Then
        XCTAssertEqual(result, COSEAlgorithmIdentifier.rs512)
    }
    
    func testCOSEAlgorithmIdentifierParseES256() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -7)
        
        // Then
        XCTAssertEqual(result, COSEAlgorithmIdentifier.es256)
    }
    
    func testCOSEAlgorithmIdentifierParseES384() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -35)
        
        // Then
        XCTAssertEqual(result, COSEAlgorithmIdentifier.es384)
    }
    
    func testCOSEAlgorithmIdentifierParseES512() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -36)
        
        // Then
        XCTAssertEqual(result, COSEAlgorithmIdentifier.es512)
    }
    
    func testCOSEAlgorithmIdentifierParsePS256() throws {
        // Given
        let result = COSEAlgorithmIdentifier.parse(from: -37)
        
        // Then
        XCTAssertEqual(result, COSEAlgorithmIdentifier.ps256)
    }
    
    // MARK: PublicKeyCredential
    func testCreatePublicKeyCredentialAttestationResponse() throws {
        // Given
        let id = UUID().uuidString
        let response = AuthenticatorAttestationResponse(clientDataJSON: "clientDataJSON", attestationObject: UUID().uuidArray)
        
        let result = PublicKeyCredential<AuthenticatorAttestationResponse>(type: .publicKey, rawId: id, id: id, response: response, getClientExtensionResults: PublicKeyCredential.ClientExtensionResults(), getTransports: ["internal"])
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreatePublicKeyCredentialAssertionResponse() throws {
        // Given
        let id = UUID().uuidString
        let response = AuthenticatorAssertionResponse(clientDataJSON: "clientDataJSON", authenticatorData: UUID().uuidArray, signature: UUID().uuidArray, userHandle: nil)
    
        let result = PublicKeyCredential<AuthenticatorAssertionResponse>(rawId: id, id: id, response: response)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    // MARK: AuthenticatorAttestationResponse
    
    func testEncodeAuthenticatorAttestationResponse() throws {
        // Given
        let response = AuthenticatorAttestationResponse(clientDataJSON: "clientDataJSON", attestationObject: UUID().uuidArray)
    
        // When
        let result = try JSONEncoder().encode(response)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    
    // MARK: AuthenticatorAssertionResponse
    
    func testEncodeAuthenticatorAssertionResponse() throws {
        // Given
       let response = AuthenticatorAssertionResponse(clientDataJSON: "clientDataJSON", authenticatorData: UUID().uuidArray, signature: UUID().uuidArray, userHandle: nil)
    
        // When
        let result = try JSONEncoder().encode(response)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testEncodeAuthenticatorAssertionResponseEx() throws {
        // Given
       let response = AuthenticatorAssertionResponse(clientDataJSON: "clientDataJSON", authenticatorData: UUID().uuidArray, signature: UUID().uuidArray, userHandle: UUID().uuidArray)
    
        // When
        let result = try JSONEncoder().encode(response)
        
        // Then
        XCTAssertNotNil(result)
    }
}
