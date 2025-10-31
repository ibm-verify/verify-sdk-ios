//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import XCTest
@testable import FIDO2

class PublicKeyCredentialRequestOptionsTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testCreateFromISVAFile() throws {
        // Given
        guard let url = Bundle.module.url(forResource: "ISVA.Assertion.Options", withExtension: "json", subdirectory: "Files") else {
            XCTFail("Missing file: ISVA.Assertion.Options.json")
            return
        }
        
        do {
            // When
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            let result = try decoder.decode(PublicKeyCredentialRequestOptions.self, from: data)
            
            // Then
            XCTAssertNotNil(result)
        }
        catch let error {
            print("Unknown error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    func testCreateFromISVFile() throws {
        // Given
        guard let url = Bundle.module.url(forResource: "ISVA.Assertion.Options", withExtension: "json", subdirectory: "Files") else {
            XCTFail("Missing file: ISV.Assertion.Options.json")
            return
        }
        
        do {
            // When
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            let result = try decoder.decode(PublicKeyCredentialRequestOptions.self, from: data)
            
            // Then
            XCTAssertNotNil(result)
        }
        catch let error {
            print("Unknown error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    func testCreateFromChallenge() throws {
        // When
        let result = PublicKeyCredentialRequestOptions(challenge: UUID().uuidString)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreateFromChallengeRpUserMinEx() throws {
        // Given
        let allowCredentials = [PublicKeyCredentialDescriptor(id: UUID().uuidString)]
        
        // When
        let result = PublicKeyCredentialRequestOptions(challenge: UUID().uuidString, rpId: "mydomain.com", allowCredentials: allowCredentials, userVerification: .required, timeout: 30000)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreateAddExtension() throws {
        // When
        var result = PublicKeyCredentialRequestOptions(challenge: UUID().uuidString)
        result.extensions = AuthenticatorExtensions(txAuthSimple: "This is a transfer.")
        
        // Then
        XCTAssertNotNil(result)
    }
}
